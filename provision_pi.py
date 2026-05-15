import os
import json
import ssl
import logging
import urllib.request
import urllib.error
from pathlib import Path

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

SERVER_URL = os.environ.get("OTA_SERVER", "https://localhost:8443")
OTA_DIR    = Path(os.environ.get("OTA_DIR", "test-device"))
TOKEN      = os.environ.get("PROVISION_TOKEN")
DEVICE_ID  = os.environ.get("DEVICE_ID")

KEY_PATH      = OTA_DIR / "device.key"
CERT_PATH     = OTA_DIR / "device.crt"
CA_CERT_PATH  = OTA_DIR / "ca.crt"
TUF_ROOT_PATH = OTA_DIR / "tuf_root.json"
DONE_MARKER   = OTA_DIR / ".provisioned"


def register(token: str, device_id: str) -> dict:
    payload = json.dumps({
        "token":     token,
        "device_id": device_id,
    }).encode()

    req = urllib.request.Request(
        f"{SERVER_URL}/v1/register",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        log.error(f"Registration failed {e.code}: {body}")
        raise


def main():
    if DONE_MARKER.exists():
        log.info("Already provisioned. Delete test-device/.provisioned to re-run.")
        return

    if not TOKEN or not DEVICE_ID:
        log.error("PROVISION_TOKEN and DEVICE_ID must be set")
        raise SystemExit(1)

    log.info(f"Provisioning device: {DEVICE_ID}")
    log.info("Sending registration request...")

    result = register(TOKEN, DEVICE_ID)

    OTA_DIR.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_text(result["private_key_pem"])
    CERT_PATH.write_text(result["cert_pem"])
    CA_CERT_PATH.write_text(result["ca_cert_pem"])
    TUF_ROOT_PATH.write_text(result["tuf_root"])

    KEY_PATH.chmod(0o400)
    CERT_PATH.chmod(0o444)
    CA_CERT_PATH.chmod(0o444)
    TUF_ROOT_PATH.chmod(0o444)

    DONE_MARKER.write_text(DEVICE_ID)

    log.info("Provisioned successfully.")
    log.info(f"  Key:      {KEY_PATH}")
    log.info(f"  Cert:     {CERT_PATH}")
    log.info(f"  CA cert:  {CA_CERT_PATH}")
    log.info(f"  TUF root: {TUF_ROOT_PATH}")


if __name__ == "__main__":
    main()