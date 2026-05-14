# tuf_root.py
from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from tuf.api.metadata import Metadata, Root, Key
from tuf.api.serialization.json import JSONSerializer
from securesystemslib.signer import CryptoSigner

KEYS_DIR = Path("tuf/keys")
META_DIR = Path("tuf/metadata")

def load_key(name: str):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{name}.key").read_bytes(), password=None
    )

def sslib_to_tuf_key(sslib_key) -> Key:
    return Key.from_dict(
        keyid=sslib_key.keyid,
        key_dict=sslib_key.to_dict()
    )

def build_root():
    print("Loading role keys...")
    root_signer      = CryptoSigner(load_key("root"))
    targets_signer   = CryptoSigner(load_key("targets"))
    snapshot_signer  = CryptoSigner(load_key("snapshot"))
    timestamp_signer = CryptoSigner(load_key("timestamp"))

    print("Building root.json...")
    root = Root(expires=datetime.now(timezone.utc) + timedelta(days=365))

    root.add_key(sslib_to_tuf_key(root_signer.public_key),      "root")
    root.add_key(sslib_to_tuf_key(targets_signer.public_key),   "targets")
    root.add_key(sslib_to_tuf_key(snapshot_signer.public_key),  "snapshot")
    root.add_key(sslib_to_tuf_key(timestamp_signer.public_key), "timestamp")

    root.roles["root"].threshold      = 1
    root.roles["targets"].threshold   = 1
    root.roles["snapshot"].threshold  = 1
    root.roles["timestamp"].threshold = 1

    root_md = Metadata(root)
    root_md.sign(root_signer)

    META_DIR.mkdir(parents=True, exist_ok=True)
    root_md.to_file(str(META_DIR / "root.json"),   JSONSerializer())
    root_md.to_file(str(META_DIR / "1.root.json"), JSONSerializer())

    print(f"root.json written.")
    print(f"Expires: {root.expires.date()}")

if __name__ == "__main__":
    build_root()
