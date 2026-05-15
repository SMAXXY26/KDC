#!/bin/bash
set -e

echo "=== OTA Fleet Server Setup ==="

# ── 1. Check Python ───────────────────────────────────────────────────────────
echo ""
echo "[1/7] Checking Python..."
if ! command -v python3 &>/dev/null; then
    echo "  Python3 not found. Install it first:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-venv python3-pip"
    echo "  Arch:          sudo pacman -S python"
    exit 1
fi
echo "  Python $(python3 --version) found."

# ── 2. Clone repo ─────────────────────────────────────────────────────────────
echo ""
echo "[2/7] Cloning repository..."
if [ -z "$1" ]; then
    echo "  Usage: bash setup_server.sh <github_repo_url>"
    echo "  Example: bash setup_server.sh git@github.com:username/repo.git"
    exit 1
fi

REPO_DIR=$(basename "$1" .git)
if [ -d "$REPO_DIR" ]; then
    echo "  Directory $REPO_DIR already exists, pulling latest..."
    cd "$REPO_DIR"
    git pull
else
    git clone "$1"
    cd "$REPO_DIR"
fi

# ── 3. Create virtual environment ────────────────────────────────────────────
echo ""
echo "[3/7] Creating virtual environment..."
if [ ! -d "env" ]; then
    python3 -m venv env
    echo "  Virtual environment created."
else
    echo "  Virtual environment already exists."
fi
source env/bin/activate

# ── 4. Install dependencies ───────────────────────────────────────────────────
echo ""
echo "[4/7] Installing dependencies..."
python -m pip install -r requirements.txt -q
echo "  Done."

# ── 5. Create .env ────────────────────────────────────────────────────────────
echo ""
echo "[5/7] Setting up secrets..."
if [ ! -f .env ]; then
    python -c "
import os
master = os.urandom(32).hex()
salt   = os.urandom(32).hex()
with open('.env', 'w') as f:
    f.write(f'MASTER_SECRET_HEX={master}\n')
    f.write(f'FLEET_SALT_HEX={salt}\n')
print('  .env created.')
print('  IMPORTANT: Back up .env — losing it means losing all device keys.')
"
else
    echo "  .env already exists, skipping."
fi

# ── 6. Generate CA ────────────────────────────────────────────────────────────
echo ""
echo "[6/7] Generating CA..."
if [ ! -f certs/ca.key ]; then
    python main.py init-ca
else
    echo "  CA already exists, skipping."
fi

# ── 7. Initialize database ───────────────────────────────────────────────────
echo ""
echo "[7/7] Initializing database..."
python -c "from dotenv import load_dotenv; load_dotenv(); from database import init_db; init_db(); print('  Database ready.')"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete ==="
echo ""
echo "To start the server:"
echo "  cd $REPO_DIR && source env/bin/activate && python main.py"
echo ""
echo "To provision a Pi:"
echo "  python provision_pi.py <device_id> <pi_host>"
