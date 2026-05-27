# OTA Fleet Server — CLAUDE.md

## Project overview
Secure over-the-air update server for Raspberry Pi fleets.  Python / FastAPI.
Companion daemon lives in the `pi-daemon` repo (Rust) at `/home/vinesh/Documents/rusty/pi-daemon`.

## Public endpoint
`SERVER_URL=https://unboxed-willing-sandblast.ngrok-free.dev` (set in `.env`).
Update this value — and the daemon's `OTA_SERVER` env var — if the ngrok domain changes.
The mTLS listener on port 8443 is unaffected by domain changes.

## Two listeners, one FastAPI app

| Port | Protocol | Purpose |
|------|----------|---------|
| 8443 | mTLS (ECDSA P-256 server cert + CERT_OPTIONAL client certs) | Direct Pi connections; device identity comes from the TLS client certificate |
| 8080 | Plain HTTP, bound to 127.0.0.1 **only** | Cloudflare Tunnel origin; Cloudflare terminates external TLS |

Both ports serve the same `main:app`.  Do not expose 8080 to the internet directly.

## Device authentication — two paths

`routers/dependencies.py → get_authenticated_device()` tries both:

1. **mTLS** — reads client cert from `request.scope["transport"]` (injected by the uvicorn monkey-patch in `main.py`).  Works only on port 8443.
2. **Ed25519 header signatures** — fallback for Cloudflare connections.
   - `X-Device-ID: <device_id>`
   - `X-Device-Ts: <unix timestamp>`  (replay window: ±5 min)
   - `X-Device-Sig: base64(ed25519_sign(b"<device_id>:<timestamp>"))`
   - Server verifies against `public_key_hex` stored in `devices` table.
   - The device's Ed25519 key is derived server-side via HKDF and sent to the Pi during provisioning.

## Cloudflare Tunnel

Config file: `cloudflared.yml`
Credentials (gitignored): `~/.cloudflared/ota-fleet.json`

```bash
# One-time setup
cloudflared tunnel login
cloudflared tunnel create ota-fleet
cloudflared tunnel route dns ota-fleet ota.yourdomain.com

# Daily start (alongside the Python server)
cloudflared tunnel --config cloudflared.yml run
```

After creating the tunnel, update:
- `SERVER_URL` in `.env` → the daemon's `OTA_SERVER` env var should match this.
- `hostname:` in `cloudflared.yml` → same domain.

## Start the server

```bash
# Load env
export $(grep -v '^#' .env | xargs)

# Start both listeners (mTLS on 8443 + tunnel on 8080)
python main.py
```

## Key files

| File | Role |
|------|------|
| `main.py` | FastAPI app, two uvicorn listeners, CLI commands |
| `routers/dependencies.py` | Dual-path device auth (mTLS + header sig) |
| `routers/registration.py` | `/v1/register` — token-based provisioning, cert issuance |
| `routers/updates.py` | `/v1/check-update` — guarded by `get_authenticated_device` |
| `ca.py` | Internal ECDSA P-256 CA |
| `kdc.py` | HKDF key derivation (device root → sign / enc / mac keys) |
| `database.py` | SQLite schema, provisioning tokens, device registry |
| `tuf_*.py` | TUF metadata generation (root / targets / snapshot / timestamp) |
| `cloudflared.yml` | Cloudflare Tunnel ingress config |
| `.env` | `MASTER_SECRET_HEX`, `FLEET_SALT_HEX`, `SERVER_URL` |

## Init sequence (fresh machine)

```bash
python main.py init-ca
python tuf_init.py && python tuf_root.py && python tuf_targets.py
python tuf_snapshot.py && python tuf_timestamp.py
```

## Security notes
- Master secret lives in `.env` (env var).  Production: HSM.
- Device private key is delivered over TLS during provisioning.  Production: generate on-device with TPM.
- `cloudflared.yml` is safe to commit; the credentials JSON (`~/.cloudflared/*.json`) is gitignored.
- 8080 is loopback-only; the only external surface is the Cloudflare edge.
