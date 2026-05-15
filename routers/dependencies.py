# routers/dependencies.py
import logging
from fastapi import Request, HTTPException
from database import get_db

log = logging.getLogger(__name__)

def get_authenticated_device(request: Request) -> str:
    # ── 1. Extract the client certificate ────────────────────────────────────
    ssl_object = request.scope.get("transport")
    log.debug(f"Transport: {ssl_object}")
    
    if ssl_object is None:
        log.warning("No TLS connection")
        raise HTTPException(status_code=401, detail="No TLS connection")

    try:
        client_cert = request.scope["transport"].get_extra_info("ssl_object")
        log.debug(f"SSL object: {client_cert}")
        if client_cert is None:
            log.warning("No ssl_object found")
            raise HTTPException(status_code=401, detail="No client certificate presented")
        peer_cert = client_cert.getpeercert()
        log.debug(f"Peer cert: {peer_cert}")
    except Exception as e:
        log.warning(f"Could not read client certificate: {e}")
        raise HTTPException(status_code=401, detail="Could not read client certificate")

    if not peer_cert:
        log.warning("Empty peer cert")
        raise HTTPException(status_code=401, detail="No client certificate presented")

    try:
        subject = dict(x[0] for x in peer_cert["subject"])
        device_id = subject["commonName"]
        log.debug(f"Device ID from cert: {device_id}")
    except (KeyError, TypeError) as e:
        log.warning(f"Could not extract device identity: {e}")
        raise HTTPException(status_code=401, detail="Could not extract device identity from cert")

    if not device_id:
        log.warning("Empty device_id")
        raise HTTPException(status_code=401, detail="Empty device identity in cert")

    log.info(f"Authenticated device: {device_id}")

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

    return device_id