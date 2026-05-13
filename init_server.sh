#!/bin/bash
set -e

echo "=== OTA Fleet Server Initialization ==="

# ── 1. Check .env exists ──────────────────────────────────────────────────────
if [ ! -f .env ]; then
    echo "No .env found. Generating secrets..."
    python -c "
import os
master = os.urandom(32).hex()
salt   = os.urandom(32).hex()
with open('.env', 'w') as f:
    f.write(f'MASTER_SECRET_HEX={master}\n')
    f.write(f'FLEET_SALT_HEX={salt}\n')
print('  .env created.')
print('  IMPORTANT: Back up .env securely — losing it means losing all device keys.')
"
else
    echo ".env already exists, skipping secret generation."
fi

# ── 2. Install dependencies ───────────────────────────────────────────────────
echo ""
echo "Installing dependencies..."
python -m pip install -r requirements.txt -q && echo "  Done."

# ── 3. Generate CA if not present ────────────────────────────────────────────
if [ ! -f certs/ca.key ]; then
    echo ""
    echo "Generating CA..."
    python main.py init-ca
else
    echo "CA already exists, skipping."
fi

# ── 4. Initialize database ───────────────────────────────────────────────────
echo ""
echo "Initializing database..."
python -c "from dotenv import load_dotenv; load_dotenv(); from database import init_db; init_db(); print('  Database ready.')"

# ── 5. Done ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Initialization complete ==="
echo ""
echo "Next steps:"
echo "  1. Start server:       python main.py"
echo "  2. Provision a device: python provision_pi.py <device_id> <pi_host>"
echo "  3. On the Pi:          OTA_SERVER_URL=http://<your_ip>:8080 python pi_register.py"
