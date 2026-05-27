import base64
import logging
import time
from fastapi import Request, HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from database import get_db

log = logging.getLogger(__name__)

# Reject requests whose X-Device-Ts is more than 5 minutes old (replay protection)
TIMESTAMP_WINDOW_SECS = 300


def _verify_device_active(device_id: str) -> None:
    """Raise HTTPException if the device is unknown or not active."""
    with get_db() as conn:
        device = conn.execute(
            "SELECT status FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()

    if not device:
        log.warning(f"Unknown device: {device_id}")
        raise HTTPException(status_code=401, detail="Device not registered")

    if device["status"] != "active":
        log.warning(f"Non-active device: {device_id} status={device['status']}")
        raise HTTPException(status_code=403, detail="Device is not active")


# ---------------------------------------------------------------------------
# Auth path 1 — mutual TLS (direct connection on port 8443)
# ---------------------------------------------------------------------------

def _auth_via_mtls(request: Request) -> str | None:
    """
    Read the client certificate injected by the uvicorn monkey-patch.
    Returns the device_id (commonName) on success, None if no cert is present.
    """
    transport = request.scope.get("transport")
    if transport is None:
        return None

    try:
        ssl_obj = transport.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None
        peer_cert = ssl_obj.getpeercert()
        if not peer_cert:
            return None
        subject = dict(x[0] for x in peer_cert["subject"])
        return subject.get("commonName")
    except Exception as e:
        log.debug(f"mTLS extraction failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Auth path 2 — Ed25519 header signatures (Cloudflare Tunnel, port 8080)
#
# The Pi signs the string  "<device_id>:<unix_timestamp>"  with its Ed25519
# private key (received from the server during provisioning).  The server
# verifies against the public_key_hex stored in the device registry.
#
# Required headers:
#   X-Device-ID  : <device_id>
#   X-Device-Ts  : <unix timestamp as integer string>
#   X-Device-Sig : base64(ed25519_sign(b"<device_id>:<timestamp>"))
# ---------------------------------------------------------------------------

def _auth_via_headers(request: Request) -> str | None:
    """
    Returns the device_id on success, None if the required headers are absent.
    Raises HTTPException on malformed / invalid / stale headers so the caller
    can distinguish "not attempted" from "attempted and rejected".
    """
    device_id   = request.headers.get("X-Device-ID")
    ts_str      = request.headers.get("X-Device-Ts")
    sig_b64     = request.headers.get("X-Device-Sig")

    # All three headers must be present; missing = auth not attempted this way
    if not device_id or not ts_str or not sig_b64:
        return None

    # Validate timestamp format
    try:
        ts = int(ts_str)
    except ValueError:
        log.warning(f"X-Device-Ts is not an integer: {ts_str!r}")
        raise HTTPException(status_code=401, detail="Malformed X-Device-Ts header")

    # Reject stale or future timestamps (replay protection)
    skew = abs(int(time.time()) - ts)
    if skew > TIMESTAMP_WINDOW_SECS:
        log.warning(f"Stale/future timestamp for {device_id}: skew={skew}s")
        raise HTTPException(status_code=401, detail="Request timestamp out of window")

    # Look up the device's stored public key
    with get_db() as conn:
        row = conn.execute(
            "SELECT public_key_hex FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()

    if not row:
        log.warning(f"Header auth: unknown device {device_id!r}")
        raise HTTPException(status_code=401, detail="Device not registered")

    # Verify Ed25519 signature
    try:
        pub_bytes  = bytes.fromhex(row["public_key_hex"])
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        signature  = base64.b64decode(sig_b64)
        message    = f"{device_id}:{ts_str}".encode()
        public_key.verify(signature, message)
    except InvalidSignature:
        log.warning(f"Invalid Ed25519 signature for {device_id}")
        raise HTTPException(status_code=401, detail="Invalid device signature")
    except Exception as e:
        log.warning(f"Header auth error for {device_id}: {e}")
        raise HTTPException(status_code=401, detail="Could not verify device signature")

    log.debug(f"Header-sig auth succeeded: {device_id}")
    return device_id


# ---------------------------------------------------------------------------
# Dependency injected into protected endpoints
# ---------------------------------------------------------------------------

def get_authenticated_device(request: Request) -> str:
    """
    Try mTLS first (direct TLS connections on port 8443).
    Fall back to Ed25519 header auth (Cloudflare Tunnel connections on port 8080).
    Raises 401/403 if neither path succeeds.
    """
    # Path 1 — mTLS (direct connection)
    device_id = _auth_via_mtls(request)
    if device_id:
        _verify_device_active(device_id)
        log.info(f"Authenticated device (mTLS): {device_id}")
        return device_id

    # Path 2 — Ed25519 header signatures (via Cloudflare)
    # _auth_via_headers raises HTTPException on malformed/invalid headers,
    # returns None if headers are simply absent.
    device_id = _auth_via_headers(request)
    if device_id:
        _verify_device_active(device_id)
        log.info(f"Authenticated device (header-sig): {device_id}")
        return device_id

    log.warning("Auth failed: no mTLS cert and no valid device headers")
    raise HTTPException(
        status_code=401,
        detail="No valid device authentication (mTLS cert or X-Device-* headers required)",
    )
