# tuf_snapshot.py
from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from tuf.api.metadata import Metadata, Snapshot
from tuf.api.serialization.json import JSONSerializer
from securesystemslib.signer import CryptoSigner

KEYS_DIR = Path("tuf/keys")
META_DIR = Path("tuf/metadata")

def load_key(name: str):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{name}.key").read_bytes(), password=None
    )

def build_snapshot():
    print("Loading snapshot key...")
    snapshot_signer = CryptoSigner(load_key("snapshot"))

    print("Loading targets metadata...")
    targets_md = Metadata.from_file(str(META_DIR / "targets.json"))

    print("Building snapshot.json...")
    snapshot = Snapshot(expires=datetime.now(timezone.utc) + timedelta(days=30))
    snapshot.meta["targets.json"].version = targets_md.signed.version

    snapshot_md = Metadata(snapshot)
    snapshot_md.sign(snapshot_signer)

    META_DIR.mkdir(parents=True, exist_ok=True)
    snapshot_md.to_file(str(META_DIR / "snapshot.json"), JSONSerializer())

    print("snapshot.json written.")
    print(f"Expires:         {snapshot.expires.date()}")
    print(f"Targets version: {targets_md.signed.version}")

if __name__ == "__main__":
    build_snapshot()