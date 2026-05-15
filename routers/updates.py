import logging
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, field_validator
from database import get_db
from routers.dependencies import get_authenticated_device
from tuf.api.metadata import Metadata
from pathlib import Path
import re

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["updates"])

META_DIR = Path("tuf/metadata")


class UpdateCheckRequest(BaseModel):
    current_version: str
    hardware:        str

    @field_validator("current_version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        if not re.fullmatch(r"\d+\.\d+\.\d+", v):
            raise ValueError("version must be in format x.y.z")
        return v

    @field_validator("hardware")
    @classmethod
    def validate_hardware(cls, v: str) -> str:
        allowed = {"rpi4", "rpi3", "rpi5"}
        if v not in allowed:
            raise ValueError(f"hardware must be one of {allowed}")
        return v


@router.post("/check-update")
async def check_update(
    body:      UpdateCheckRequest,
    request:   Request,
    device_id: str = Depends(get_authenticated_device),
):
    client_ip = request.client.host

    log.info(f"Update check | device={device_id} version={body.current_version} "
             f"hardware={body.hardware} ip={client_ip}")

    with get_db() as conn:
        conn.execute("""
            UPDATE devices
            SET last_seen_at     = datetime('now'),
                ip_address       = ?,
                firmware_version = ?
            WHERE device_id = ?
        """, (client_ip, body.current_version, device_id))

    try:
        targets_md = Metadata.from_file(str(META_DIR / "targets.json"))
    except Exception:
        log.error("Could not read targets.json")
        return {"update_available": False}

    latest_version = None
    for name, target in targets_md.signed.targets.items():
        custom = target.unrecognized_fields.get("custom", {})
        if custom.get("hardware") == body.hardware:
            latest_version = custom.get("version")
            break

    if latest_version is None:
        log.warning(f"No artifact found for hardware={body.hardware}")
        return {"update_available": False}

    update_available = latest_version != body.current_version

    log.info(f"Update check result | device={device_id} "
             f"current={body.current_version} latest={latest_version} "
             f"update_available={update_available}")

    return {"update_available": update_available}
