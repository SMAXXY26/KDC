from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from tuf.api.metadata import Metadata, Timestamp
from tuf.api.serialization.json import JSONSerializer
from securesystemslib.signer import CryptoSigner

KEYS_DIR = Path("tuf/keys")
META_DIR = Path("tuf/metadata")

def load_key(name: str):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{name}.key").read_bytes(), password=None
    )

def build_timestamp():
    print("Loading timestamp key...")
    timestamp_signer = CryptoSigner(load_key("timestamp"))

    print("Loading snapshot metadata...")
    snapshot_md = Metadata.from_file(str(META_DIR / "snapshot.json"))

    print("Building timestamp.json...")
    timestamp = Timestamp(expires=datetime.now(timezone.utc) + timedelta(days=1))
    timestamp.snapshot_meta.version = snapshot_md.signed.version

    timestamp_md = Metadata(timestamp)
    timestamp_md.sign(timestamp_signer)

    META_DIR.mkdir(parents=True, exist_ok=True)
    timestamp_md.to_file(str(META_DIR / "timestamp.json"), JSONSerializer())

    print("timestamp.json written.")
    print(f"Expires:          {timestamp.expires.date()}")
    print(f"Snapshot version: {snapshot_md.signed.version}")

if __name__ == "__main__":
    build_timestamp()