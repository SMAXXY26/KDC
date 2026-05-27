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

    print("=== Step 1: Generating role keys ===")
    generate_key("root")
    generate_key("targets")
    generate_key("snapshot")
    generate_key("timestamp")

    print("\n=== Step 2: Building root.json ===")
    from tuf_root import build_root
    build_root()

    print("\n=== Step 3: Building targets.json ===")
    from tuf_targets import build_targets
    build_targets()

    print("\n=== Step 4: Building snapshot.json ===")
    from tuf_snapshot import build_snapshot
    build_snapshot()

    print("\n=== Step 5: Building timestamp.json ===")
    from tuf_timestamp import build_timestamp
    build_timestamp()

    print("\n=== TUF setup complete ===")