import os
import sys
import requests
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from dotenv import dotenv_values

PROVISION_ENV = Path("/etc/ota/provision.env")
DEVICE_ENV    = Path("/etc/ota/device.env")
CERT_OUT      = Path("/etc/ota/device.crt")
CA_CERT_OUT   = Path("/etc/ota/ca.crt")
TUF_ROOT_OUT  = Path("/etc/ota/tuf_root.json")

SERVER_URL = os.environ.get("OTA_SERVER_URL", "http://ota-server:8443")


def load_envs():
    if not PROVISION_ENV.exists():
        sys.exit(f"Missing {PROVISION_ENV} — write PROVISION_TOKEN and DEVICE_ID to it first.")
    if not DEVICE_ENV.exists():
        sys.exit(f"Missing {DEVICE_ENV} — write DEVICE_SIGNING_KEY_HEX to it first.")
    env = {**dotenv_values(PROVISION_ENV), **dotenv_values(DEVICE_ENV)}
    for key in ("PROVISION_TOKEN", "DEVICE_ID", "DEVICE_SIGNING_KEY_HEX"):
        if key not in env:
            sys.exit(f"Missing {key} in env files.")
    return env


def build_csr(private_key: Ed25519PrivateKey, device_id: str) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ]))
        .sign(private_key, None)
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def main():
    env = load_envs()
    token     = env["PROVISION_TOKEN"]
    device_id = env["DEVICE_ID"]
    key_bytes = bytes.fromhex(env["DEVICE_SIGNING_KEY_HEX"])

    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    csr_pem = build_csr(private_key, device_id)

    print(f"Registering {device_id} with {SERVER_URL} ...")
    resp = requests.post(
        f"{SERVER_URL}/v1/register",
        json={
            "token":     token,
            "device_id": device_id,
            "csr_pem":   csr_pem.decode(),
        },
        timeout=30,
    )

    if resp.status_code != 200:
        sys.exit(f"Registration failed ({resp.status_code}): {resp.text}")

    data = resp.json()

    CERT_OUT.parent.mkdir(parents=True, exist_ok=True)
    CERT_OUT.write_text(data["cert_pem"])
    CA_CERT_OUT.write_text(data["ca_cert_pem"])
    if data.get("tuf_root"):
        TUF_ROOT_OUT.write_text(data["tuf_root"])

    print(f"Registered. Certificate written to {CERT_OUT}")
    print(f"CA cert written to {CA_CERT_OUT}")
    if data.get("tuf_root"):
        print(f"TUF root written to {TUF_ROOT_OUT}")


if __name__ == "__main__":
    main()
