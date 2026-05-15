import sqlite3
import secrets
from datetime import datetime, timedelta
from contextlib import contextmanager

DB_PATH = "ota.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS provision_tokens (
    token           TEXT PRIMARY KEY,
    device_id       TEXT UNIQUE NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    used_at         TEXT,
    used_by_ip      TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    device_id       TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'active',
    cert_serial     INTEGER NOT NULL,
    cert_pem        TEXT NOT NULL,
    public_key_hex  TEXT NOT NULL,
    key_version     INTEGER NOT NULL DEFAULT 1,
    registered_at   TEXT NOT NULL,
    last_seen_at    TEXT,
    ip_address      TEXT,
    firmware_version TEXT
);

CREATE TABLE IF NOT EXISTS cert_serials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT
);
"""

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.executescript(SCHEMA)

def create_provision_token(device_id: str, ttl_hours: int = 24) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    expires = now + timedelta(hours=ttl_hours)
    with get_db() as conn:
        conn.execute("""
            INSERT INTO provision_tokens (token, device_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                token      = excluded.token,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                used_at    = NULL,
                used_by_ip = NULL
        """, (token, device_id, now.isoformat(), expires.isoformat()))
    return token

def consume_token(token: str, ip: str) -> sqlite3.Row | None:
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        row = conn.execute("""
            SELECT * FROM provision_tokens
            WHERE token = ?
              AND used_at IS NULL
              AND expires_at > ?
        """, (token, now)).fetchone()

        if not row:
            return None

        conn.execute("""
            UPDATE provision_tokens
            SET used_at = ?, used_by_ip = ?
            WHERE token = ? AND used_at IS NULL
        """, (now, ip, token))

        if conn.execute("SELECT changes()").fetchone()[0] == 0:
            return None

    return row

def next_cert_serial(conn: sqlite3.Connection) -> int:
    conn.execute("INSERT INTO cert_serials DEFAULT VALUES")
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]