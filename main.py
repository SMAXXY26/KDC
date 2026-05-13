# main.py
import os
import sys
import logging
import uvicorn
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI

load_dotenv()
from database import init_db, create_provision_token
from ca import generate_ca, CA_KEY_PATH
from routers.registration import router as reg_router

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if not CA_KEY_PATH.exists():
        raise RuntimeError("CA not found. Run: python main.py init-ca")
    yield

app = FastAPI(title="OTA Fleet Server", version="0.1.0", lifespan=lifespan)
app.include_router(reg_router)

if __name__ == "__main__":
    import sys

    args = sys.argv[1:]

    if not args:
        print("Starting server...")
        uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)

    elif args[0] == "init-ca":
        generate_ca()
        print("CA initialised.")

    elif args[0] == "new-token":
        if len(args) < 2:
            print("Usage: python main.py new-token <device_id>")
            sys.exit(1)
        device_id = args[1]
        try:
            init_db()  # ensure tables exist
            token = create_provision_token(device_id, ttl_hours=24)
            print(f"\nToken for {device_id}:")
            print(f"  PROVISION_TOKEN={token}")
            print(f"  DEVICE_ID={device_id}")
            print(f"\nWrite these to /etc/ota/provision.env on the Pi.\n")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args[0] == "prep-device":
        if len(args) < 2:
            print("Usage: python main.py prep-device <device_id>")
            sys.exit(1)
        device_id = args[1]
        try:
            from kdc import derive_device_root, derive_purpose_key
            master = bytes.fromhex(os.environ["MASTER_SECRET_HEX"])
            salt   = bytes.fromhex(os.environ["FLEET_SALT_HEX"])
            root   = derive_device_root(master, salt, device_id)
            key_bytes = derive_purpose_key(root, "sign", version=1)
            print(f"\nDevice key for {device_id}:")
            print(f"  DEVICE_SIGNING_KEY_HEX={key_bytes.hex()}")
            print(f"\nWrite this to /etc/ota/device.env on the Pi (alongside provision.env).\n")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    else:
        print(f"Unknown command: {args[0]}")
        print("Commands: init-ca, new-token <device_id>, prep-device <device_id>")
        sys.exit(1)