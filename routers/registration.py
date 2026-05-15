import logging
import os
import re
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime as dt

from database import consume_token, next_cert_serial, get_db
from ca import load_ca
from kdc import derive_device_root, derive_purpose_key

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["registration"])


class RegistrationRequest(BaseModel):
    token:     str
    device_id: str

    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z0-9\-]{4,64}", v):
            raise ValueError("device_id must be 4-64 lowercase alphanumeric chars or hyphens")
        return v


def issue_cert(public_key, serial: int, device_id: str) -> bytes:
    ca_key, ca_cert = load_ca()

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(device_id)]),
            critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM)


@router.post("/register")
async def register_device(req: RegistrationRequest, request: Request):
    client_ip = request.client.host

    MASTER_SECRET = bytes.fromhex(os.environ["MASTER_SECRET_HEX"])
    FLEET_SALT    = bytes.fromhex(os.environ["FLEET_SALT_HEX"])

    token_row = consume_token(req.token, client_ip)
    if not token_row:
        log.warning(f"Registration rejected: invalid/used token from {client_ip} for {req.device_id}")
        raise HTTPException(status_code=401, detail="Invalid or expired provisioning token")

    if token_row["device_id"] != req.device_id:
        log.warning(f"device_id mismatch: token for {token_row['device_id']}, got {req.device_id}")
        raise HTTPException(status_code=401, detail="Invalid or expired provisioning token")

    with get_db() as conn:
        existing = conn.execute(
            "SELECT device_id FROM devices WHERE device_id = ?", (req.device_id,)
        ).fetchone()
    if existing:
        log.warning(f"Re-registration attempt for existing device {req.device_id}")
        raise HTTPException(status_code=409, detail="Device already registered")

    try:
        device_root   = derive_device_root(MASTER_SECRET, FLEET_SALT, req.device_id)
        signing_bytes = derive_purpose_key(device_root, "sign", version=1)
        private_key   = Ed25519PrivateKey.from_private_bytes(signing_bytes)
        public_key    = private_key.public_key()
        public_key_hex = public_key.public_bytes_raw().hex()
    except Exception:
        log.exception(f"Key derivation failed for {req.device_id}")
        raise HTTPException(status_code=500, detail="Key derivation failed")

    try:
        with get_db() as conn:
            serial   = next_cert_serial(conn)
            cert_pem = issue_cert(public_key, serial, req.device_id)

            conn.execute("""
                INSERT INTO devices
                    (device_id, cert_serial, cert_pem, public_key_hex,
                     key_version, registered_at, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                req.device_id,
                serial,
                cert_pem.decode(),
                public_key_hex,
                1,
                datetime.utcnow().isoformat(),
                client_ip,
            ))
    except Exception:
        log.exception(f"Failed to issue cert for {req.device_id}")
        raise HTTPException(status_code=500, detail="Certificate issuance failed")

    log.info(f"Device registered: {req.device_id} from {client_ip} (serial {serial})")

    ca_cert_pem   = Path("certs/ca.crt").read_text()
    tuf_root_path = Path("tuf/metadata/root.json")
    tuf_root      = tuf_root_path.read_text() if tuf_root_path.exists() else None

    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()

    return JSONResponse({
        "status":          "registered",
        "device_id":       req.device_id,
        "cert_pem":        cert_pem.decode(),
        "private_key_pem": private_key_pem,
        "ca_cert_pem":     ca_cert_pem,
        "tuf_root":        tuf_root,
        "key_version":     1,
    })