import os
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ── Step 1: Master secret (generate once, store offline) ──────────────────────
# In production: generated in an HSM or air-gapped machine, never on the server
MASTER_SECRET = os.urandom(32)  # store this securely — losing it = losing all keys

# ── Step 2: Fleet-wide salt (random, stored in DB, not secret but unique) ─────
# Unlike your version: this has real entropy, not just an index
FLEET_SALT = os.urandom(32)

# ── Step 3: Derive a device-specific root key ─────────────────────────────────
# The device_id is bound into the derivation — two devices cannot share a key
def derive_device_root(master: bytes, salt: bytes, device_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        # info binds this key to a specific device — critical for isolation
        info=f"device:{device_id}".encode(),
    )
    return hkdf.derive(master)

# ── Step 4: Domain separation — one key per purpose ──────────────────────────
# Same device root, different info string = cryptographically independent keys
# Compromising one purpose's key tells an attacker nothing about the others
def derive_purpose_key(device_root: bytes, purpose: str, version: int = 1) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # PRK is already well-distributed; salt optional here
        info=f"{purpose}:v{version}".encode(),
    )
    return hkdf.derive(device_root)

# ── Step 5: Load as Ed25519 keypair ──────────────────────────────────────────
def make_signing_keypair(device_root: bytes, version: int = 1):
    signing_key_bytes = derive_purpose_key(device_root, "sign", version)
    private_key = Ed25519PrivateKey.from_private_bytes(signing_key_bytes)
    public_key = private_key.public_key()
    return private_key, public_key

# ── Step 6: Correct HMAC authentication tag ───────────────────────────────────
# Key = secret (mac_key), message = data being authenticated
def make_auth_tag(data: bytes, device_root: bytes, version: int = 1) -> bytes:
    mac_key = derive_purpose_key(device_root, "mac", version)
    return hmac.new(mac_key, data, hashlib.sha256).digest()

def verify_auth_tag(data: bytes, tag: bytes, device_root: bytes, version: int = 1) -> bool:
    mac_key = derive_purpose_key(device_root, "mac", version)
    expected = hmac.new(mac_key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, tag)  # timing-safe — you had this right

# ── Step 7: Key rotation ──────────────────────────────────────────────────────
# To rotate: derive with version+1, run both in parallel during overlap window
# Old: derive_purpose_key(root, "sign", version=1)
# New: derive_purpose_key(root, "sign", version=2)
# After overlap expires: stop accepting v1 signatures

# ── Usage example ─────────────────────────────────────────────────────────────
device_id = "pi-fleet-042"
device_root = derive_device_root(MASTER_SECRET, FLEET_SALT, device_id)

private_key, public_key = make_signing_keypair(device_root)

firmware = b"firmware_v2.0_binary_data..."
signature = private_key.sign(firmware)

# On the device side — verify using the public key only
public_key.verify(signature, firmware)  # raises InvalidSignature if tampered
print("Firmware signature valid")

# MAC for channel authentication
tag = make_auth_tag(firmware, device_root)
assert verify_auth_tag(firmware, tag, device_root)
print("Auth tag valid")