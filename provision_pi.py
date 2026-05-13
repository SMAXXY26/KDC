# provision_pi.py — generates token + device key and writes them to the Pi over SSH
# Usage: python provision_pi.py <device_id> <pi_host> [--user pi]
import sys
import subprocess
from dotenv import load_dotenv
import os

load_dotenv()

def run(cmd: str, input: str = None):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, input=input)
    if result.returncode != 0:
        sys.exit(f"Command failed: {cmd}\n{result.stderr}")
    return result.stdout.strip()

def ssh(host: str, user: str, command: str, input: str = None):
    result = subprocess.run(
        ["ssh", f"{user}@{host}", command],
        capture_output=True, text=True, input=input
    )
    if result.returncode != 0:
        sys.exit(f"SSH command failed: {command}\n{result.stderr}")
    return result.stdout.strip()

def main():
    args = sys.argv[1:]
    if len(args) < 2:
        sys.exit("Usage: python provision_pi.py <device_id> <pi_host> [--user pi]")

    device_id = args[0]
    pi_host   = args[1]
    pi_user   = args[args.index("--user") + 1] if "--user" in args else "pi"

    # Derive keys on the server side
    from kdc import derive_device_root, derive_purpose_key
    from database import init_db, create_provision_token

    master = bytes.fromhex(os.environ["MASTER_SECRET_HEX"])
    salt   = bytes.fromhex(os.environ["FLEET_SALT_HEX"])
    root   = derive_device_root(master, salt, device_id)
    key_hex = derive_purpose_key(root, "sign", version=1).hex()

    init_db()
    token = create_provision_token(device_id, ttl_hours=24)

    print(f"Token and key derived for {device_id}. Writing to {pi_user}@{pi_host} ...")

    # Write files on the Pi
    ssh(pi_host, pi_user, "sudo mkdir -p /etc/ota")
    ssh(pi_host, pi_user,
        f"printf 'PROVISION_TOKEN={token}\\nDEVICE_ID={device_id}\\n' | sudo tee /etc/ota/provision.env > /dev/null")
    ssh(pi_host, pi_user,
        f"echo 'DEVICE_SIGNING_KEY_HEX={key_hex}' | sudo tee /etc/ota/device.env > /dev/null")

    # Lock down permissions
    ssh(pi_host, pi_user, "sudo chmod 600 /etc/ota/provision.env /etc/ota/device.env")

    print(f"Done. Files written to /etc/ota/ on the Pi.")
    print(f"Run on Pi: OTA_SERVER_URL=http://10.42.0.1:8443 python pi_register.py")

if __name__ == "__main__":
    main()
