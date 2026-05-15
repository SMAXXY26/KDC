import os
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MASTER_SECRET = os.urandom(32)
FLEET_SALT = os.urandom(32)

def derive_device_root(master: bytes, salt: bytes, device_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f"device:{device_id}".encode(),
    )
    return hkdf.derive(master)

def derive_purpose_key(device_root: bytes, purpose: str, version: int = 1) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{purpose}:v{version}".encode(),
    )
    return hkdf.derive(device_root)

def make_signing_keypair(device_root: bytes, version: int = 1):
    signing_key_bytes = derive_purpose_key(device_root, "sign", version)
    private_key = Ed25519PrivateKey.from_private_bytes(signing_key_bytes)
    public_key = private_key.public_key()
    return private_key, public_key

def make_auth_tag(data: bytes, device_root: bytes, version: int = 1) -> bytes:
    mac_key = derive_purpose_key(device_root, "mac", version)
    return hmac.new(mac_key, data, hashlib.sha256).digest()

def verify_auth_tag(data: bytes, tag: bytes, device_root: bytes, version: int = 1) -> bool:
    mac_key = derive_purpose_key(device_root, "mac", version)
    expected = hmac.new(mac_key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, tag)

device_id = "pi-fleet-042"
device_root = derive_device_root(MASTER_SECRET, FLEET_SALT, device_id)

private_key, public_key = make_signing_keypair(device_root)

firmware = b"firmware_v2.0_binary_data..."
signature = private_key.sign(firmware)

public_key.verify(signature, firmware)
print("Firmware signature valid")

tag = make_auth_tag(firmware, device_root)
assert verify_auth_tag(firmware, tag, device_root)
print("Auth tag valid")