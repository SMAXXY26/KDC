from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from tuf.api.metadata import Metadata, Targets, TargetFile
from tuf.api.serialization.json import JSONSerializer
from securesystemslib.signer import CryptoSigner

KEYS_DIR      = Path("tuf/keys")
META_DIR      = Path("tuf/metadata")
ARTIFACTS_DIR = Path("tuf/artifacts")

def load_key(name: str):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{name}.key").read_bytes(), password=None
    )

def build_targets():
    print("Loading targets key...")
    targets_signer = CryptoSigner(load_key("targets"))

    print("Building targets.json...")
    targets = Targets(expires=datetime.now(timezone.utc) + timedelta(days=90))

    artifact = ARTIFACTS_DIR / "app-v1.0.0.py"
    if not artifact.exists():
        print(f"Artifact not found: {artifact}")
        return

    target_file = TargetFile.from_file(
        target_file_path="app-v1.0.0.py",
        local_path=str(artifact),
    )
    target_file.unrecognized_fields["custom"] = {
        "version":     "1.0.0",
        "hardware":    "rpi4",
        "task":        "cv-detection",
        "min_version": "0.0.0",
    }

    targets.targets["app-v1.0.0.py"] = target_file

    targets_md = Metadata(targets)
    targets_md.sign(targets_signer)

    META_DIR.mkdir(parents=True, exist_ok=True)
    targets_md.to_file(str(META_DIR / "targets.json"), JSONSerializer())

    print("targets.json written.")
    print(f"Expires: {targets.expires.date()}")
    print(f"Artifact: app-v1.0.0.py")

if __name__ == "__main__":
    build_targets()