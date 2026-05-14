# tuf_init.py
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

KEYS_DIR = Path("tuf/keys")

def generate_key(name: str) -> Ed25519PrivateKey:
    key_path = KEYS_DIR / f"{name}.key"

    if key_path.exists():
        print(f"  {name} key already exists, skipping")
        return serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )

    private_key = Ed25519PrivateKey.generate()
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )
    key_path.chmod(0o400)
    print(f"  {name} key generated")
    return private_key

if __name__ == "__main__":
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.chmod(0o700)

    print("Generating role keys...")
    root_private      = generate_key("root")
    targets_private   = generate_key("targets")
    snapshot_private  = generate_key("snapshot")
    timestamp_private = generate_key("timestamp")
    print("Done.")
