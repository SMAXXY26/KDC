# routers/registration.py
import logging
from datetime import datetime
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography import x509

from database import consume_token, next_cert_serial, get_db
from ca import sign_csr
from kdc import derive_device_root, derive_purpose_key
import os

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["registration"])

class RegistrationRequest(BaseModel):
    token:     str
    device_id: str
    csr_pem:   str   # PEM-encoded CSR from the device

    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, v: str) -> str:
        # Enforce a safe format — prevents injection into HKDF info strings
        import re
        if not re.fullmatch(r"[a-z0-9\-]{4,64}", v):
            raise ValueError("device_id must be 4-64 lowercase alphanumeric chars or hyphens")
        return v

    @field_validator("csr_pem")
    @classmethod
    def validate_csr_format(cls, v: str) -> str:
        if not v.strip().startswith("-----BEGIN CERTIFICATE REQUEST-----"):
            raise ValueError("csr_pem must be a PEM certificate request")
        return v.strip()


@router.post("/register")
async def register_device(req: RegistrationRequest, request: Request):
    client_ip = request.client.host
    MASTER_SECRET = bytes.fromhex(os.environ["MASTER_SECRET_HEX"])
    FLEET_SALT    = bytes.fromhex(os.environ["FLEET_SALT_HEX"])

    # ── 1. Consume the one-time token ────────────────────────────────────────
    token_row = consume_token(req.token, client_ip)
    if not token_row:
        # Deliberately vague — don't tell attacker why it failed
        log.warning(f"Registration rejected: invalid/used token from {client_ip} for {req.device_id}")
        raise HTTPException(status_code=401, detail="Invalid or expired provisioning token")

    # ── 2. Verify device_id matches what the token was issued for ─────────────
    if token_row["device_id"] != req.device_id:
        log.warning(f"device_id mismatch: token for {token_row['device_id']}, got {req.device_id}")
        raise HTTPException(status_code=401, detail="Invalid or expired provisioning token")

    # ── 3. Check device is not already registered ─────────────────────────────
    with get_db() as conn:
        existing = conn.execute(
            "SELECT device_id FROM devices WHERE device_id = ?", (req.device_id,)
        ).fetchone()
    if existing:
        log.warning(f"Re-registration attempt for existing device {req.device_id}")
        raise HTTPException(status_code=409, detail="Device already registered")

    # ── 4. Parse and validate the CSR ─────────────────────────────────────────
    try:
        csr = x509.load_pem_x509_csr(req.csr_pem.encode())
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed CSR")

    if not csr.is_signature_valid:
        raise HTTPException(status_code=400, detail="CSR signature invalid")

    # ── 5. KDC verification: does the CSR public key match what we'd derive? ──
    # This is the integration point between your HKD system and registration.
    # The server independently derives what the device's public key SHOULD be,
    # then checks the CSR matches. This proves:
    #   (a) the device has the correct private key
    #   (b) the device_id in the CSR is legitimate
    device_root = derive_device_root(MASTER_SECRET, FLEET_SALT, req.device_id)
    expected_private_bytes = derive_purpose_key(device_root, "sign", version=1)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    expected_private = Ed25519PrivateKey.from_private_bytes(expected_private_bytes)
    expected_public_bytes = expected_private.public_key().public_bytes_raw()

    csr_public_key = csr.public_key()
    if not isinstance(csr_public_key, Ed25519PublicKey):
        raise HTTPException(status_code=400, detail="CSR must use Ed25519 key")

    csr_public_bytes = csr_public_key.public_bytes_raw()

    if csr_public_bytes != expected_public_bytes:
        log.error(f"KDC mismatch for device {req.device_id}: CSR key does not match derived key")
        raise HTTPException(status_code=401, detail="Key verification failed")

    # ── 6. Issue the certificate ──────────────────────────────────────────────
    try:
        with get_db() as conn:
            serial = next_cert_serial(conn)
            cert_pem = sign_csr(req.csr_pem.encode(), serial, req.device_id)

            conn.execute("""
                INSERT INTO devices
                    (device_id, cert_serial, cert_pem, public_key_hex,
                     key_version, registered_at, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                req.device_id,
                serial,
                cert_pem.decode(),
                csr_public_bytes.hex(),
                1,
                datetime.utcnow().isoformat(),
                client_ip,
            ))
    except Exception as e:
        log.exception(f"Failed to issue cert for {req.device_id}")
        raise HTTPException(status_code=500, detail="Certificate issuance failed")

    log.info(f"Device registered: {req.device_id} from {client_ip} (serial {serial})")

    # ── 7. Return everything the device needs to operate ──────────────────────
    from pathlib import Path
    ca_cert_pem = Path("certs/ca.crt").read_text()
    tuf_root_path = Path("tuf/metadata/root.json")
    tuf_root = tuf_root_path.read_text() if tuf_root_path.exists() else None

    return JSONResponse({
        "status":      "registered",
        "device_id":   req.device_id,
        "cert_pem":    cert_pem.decode(),
        "ca_cert_pem": ca_cert_pem,
        "tuf_root":    tuf_root,
        "key_version": 1,
    })
