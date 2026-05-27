import ssl
import sys
import threading
import logging
import os
import uvicorn
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

# Monkey-patch uvicorn to inject the asyncio transport into request.scope
# so that FastAPI dependencies can read the TLS client certificate.
# This is only exercised on the mTLS listener (port 8443); the plain HTTP
# listener on port 8080 has no SSL object and is harmlessly unaffected.
_orig_on_message_begin = HttpToolsProtocol.on_message_begin

def _patched_on_message_begin(self):
    _orig_on_message_begin(self)
    self.scope["transport"] = self.transport

HttpToolsProtocol.on_message_begin = _patched_on_message_begin

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from database import init_db, create_provision_token
from ca import generate_ca, CA_KEY_PATH
from routers.registration import router as reg_router
from routers.updates import router as update_router

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="OTA Fleet Server", version="0.1.0")
app.include_router(reg_router)
app.include_router(update_router)

app.mount("/metadata",  StaticFiles(directory="tuf/metadata"),  name="metadata")
app.mount("/artifacts", StaticFiles(directory="tuf/artifacts"), name="artifacts")

@app.on_event("startup")
def startup():
    init_db()
    if not CA_KEY_PATH.exists():
        raise RuntimeError("CA not found. Run: python main.py init-ca")
    server_url = os.environ.get("SERVER_URL", "")
    if server_url:
        log.info(f"Public endpoint (Cloudflare): {server_url}")


# ---------------------------------------------------------------------------
# Listener: mTLS — port 8443 (direct Pi connections, full mutual TLS)
# ---------------------------------------------------------------------------

def _run_mtls_server():
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8443,
        ssl_certfile="certs/server.crt",
        ssl_keyfile="certs/server.key",
        ssl_ca_certs="certs/ca.crt",
        ssl_cert_reqs=ssl.CERT_OPTIONAL,
        reload=False,
    )


# ---------------------------------------------------------------------------
# Listener: plain HTTP — port 8080, loopback only (Cloudflare Tunnel origin)
#
# Binds only to 127.0.0.1 so it is never directly exposed to the internet.
# cloudflared connects here and handles all external TLS termination.
# Devices authenticating via this path use Ed25519 header signatures instead
# of mTLS (see routers/dependencies.py → _auth_via_headers).
# ---------------------------------------------------------------------------

def _run_tunnel_server():
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8080,
        reload=False,
    )


def run_server():
    """Start both listeners: mTLS on 8443 and plain HTTP on 8080 for Cloudflare."""
    tls_thread = threading.Thread(target=_run_mtls_server, daemon=True, name="mtls-8443")
    tls_thread.start()
    log.info("mTLS server started on 0.0.0.0:8443")

    log.info("Tunnel server starting on 127.0.0.1:8080 (Cloudflare Tunnel origin)")
    _run_tunnel_server()   # blocks the main thread


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        run_server()

    elif args[0] == "init-ca":
        generate_ca()
        print("CA initialised.")

    elif args[0] == "new-token":
        if len(args) < 2:
            print("Usage: python main.py new-token <device_id>")
            sys.exit(1)
        device_id = args[1]
        try:
            init_db()
            token = create_provision_token(device_id, ttl_hours=24)
            print(f"\nToken for {device_id}:")
            print(f"  PROVISION_TOKEN={token}")
            print(f"  DEVICE_ID={device_id}")
            print(f"\nWrite these to /etc/ota/provision.env on the Pi.\n")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    else:
        print(f"Unknown command: {args[0]}")
        print("Commands: init-ca, new-token <device_id>")
        sys.exit(1)
