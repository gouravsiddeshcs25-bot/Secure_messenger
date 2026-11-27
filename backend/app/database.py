"""
Database management for Secure Messenger using Python's standard sqlite3 module.
Stores users, registered public keys, and message envelopes.
In v2 mode, the server operates strictly zero-knowledge: it only stores
ciphertext payloads, nonces, and public identity/exchange keys.
"""

import sqlite3
import os
from typing import Optional, List, Dict, Any

_DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "messenger.db")
DB_PATH = os.environ.get("MESSENGER_DB_PATH", _DEFAULT_DB)
os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """Initializes database tables if they do not exist."""
    conn = get_db_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS public_keys (
                username TEXT PRIMARY KEY,
                identity_pubkey TEXT NOT NULL,
                exchange_pubkey TEXT NOT NULL,
                key_signature TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                payload TEXT NOT NULL,
                is_sensitive INTEGER DEFAULT 0,
                expires_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (recipient) REFERENCES users(username) ON DELETE CASCADE
            );
        """)
        # Step A: accounts with passwords. Safe migration for an existing DB:
        # add the column only if it is missing. v1 users keep NULL (they have no password).
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "password_hash" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT NULL")
        # Only the SHA-256 hash of a session token is stored, never the token itself.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            );
        """)
    conn.close()

# ---------- Accounts and sessions (v2) ----------

def create_account(username: str, password_hash: str) -> bool:
    """Creates a v2 account. Returns False if the username is already taken."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_password_hash(username: str) -> Optional[str]:
    conn = get_db_connection()
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row["password_hash"] if row else None

def is_v2_account(username: str) -> bool:
    """True if this user has a password (a v2 account). v1 users have NULL."""
    conn = get_db_connection()
    row = conn.execute("SELECT 1 FROM users WHERE username = ? AND password_hash IS NOT NULL", (username,)).fetchone()
    conn.close()
    return row is not None

def delete_v1_message(message_id: int) -> bool:
    """v1 delete: anyone can delete, but only messages sent to v1 users (never a v2 account's messages)."""
    conn = get_db_connection()
    with conn:
        cursor = conn.execute("""
            DELETE FROM messages WHERE id = ? AND recipient IN
                (SELECT username FROM users WHERE password_hash IS NULL)
        """, (message_id,))
        deleted = cursor.rowcount > 0
    conn.close()
    return deleted

def user_exists(username: str) -> bool:
    conn = get_db_connection()
    row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row is not None

def store_session(token_hash: str, username: str, lifetime_seconds: int) -> str:
    """Saves a session hash with an expiry and returns the expiry time."""
    conn = get_db_connection()
    with conn:
        # Remove expired sessions while we are here.
        conn.execute("DELETE FROM sessions WHERE datetime(expires_at) <= datetime('now')")
        expires_at = conn.execute(
            "SELECT datetime('now', ?) AS exp", (f"+{int(lifetime_seconds)} seconds",)
        ).fetchone()["exp"]
        conn.execute(
            "INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)",
            (token_hash, username, expires_at),
        )
    conn.close()
    return expires_at

def get_session(token_hash: str) -> Optional[Dict[str, Any]]:
    """Returns {token_hash, username} for a session that exists and has not expired."""
    conn = get_db_connection()
    row = conn.execute(
        "SELECT token_hash, username FROM sessions WHERE token_hash = ? AND datetime(expires_at) > datetime('now')",
        (token_hash,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def delete_session(token_hash: str):
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    conn.close()

def ttl_to_expiry(ttl_seconds: Optional[int]) -> Optional[str]:
    """Turns a TTL into an SQLite timestamp. The value goes in as a ? parameter, never into the SQL text."""
    if not ttl_seconds or ttl_seconds <= 0:
        return None
    conn = get_db_connection()
    row = conn.execute("SELECT datetime('now', ?) AS exp", (f"+{int(ttl_seconds)} seconds",)).fetchone()
    conn.close()
    return row["exp"]

def register_user(username: str) -> bool:
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("INSERT INTO users (username) VALUES (?)", (username,))
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_all_users() -> List[str]:
    conn = get_db_connection()
    rows = conn.execute("SELECT username FROM users ORDER BY username ASC").fetchall()
    conn.close()
    return [row["username"] for row in rows]

def store_keys(username: str, identity_pubkey: str, exchange_pubkey: str, key_signature: str):
    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT INTO public_keys (username, identity_pubkey, exchange_pubkey, key_signature, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(username) DO UPDATE SET
                identity_pubkey = excluded.identity_pubkey,
                exchange_pubkey = excluded.exchange_pubkey,
                key_signature = excluded.key_signature,
                updated_at = CURRENT_TIMESTAMP;
        """, (username, identity_pubkey, exchange_pubkey, key_signature))
    conn.close()

def get_keys(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute(
        "SELECT username, identity_pubkey, exchange_pubkey, key_signature, updated_at FROM public_keys WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def store_message(sender: str, recipient: str, payload: str, is_sensitive: bool = False, expires_at: Optional[str] = None) -> int:
    conn = get_db_connection()
    with conn:
        cursor = conn.execute("""
            INSERT INTO messages (sender, recipient, payload, is_sensitive, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (sender, recipient, payload, 1 if is_sensitive else 0, expires_at))
        msg_id = cursor.lastrowid
    conn.close()
    return msg_id

def get_messages_for_recipient(recipient: str) -> List[Dict[str, Any]]:
    """Fetches messages for recipient. Filters out expired messages if expires_at is past."""
    conn = get_db_connection()
    # Delete already expired messages automatically
    with conn:
        conn.execute("""
            DELETE FROM messages 
            WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')
        """)
        rows = conn.execute("""
            SELECT id, sender, recipient, payload, is_sensitive, expires_at, created_at
            FROM messages
            WHERE recipient = ?
            ORDER BY id ASC
        """, (recipient,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def delete_message(message_id: int, recipient: Optional[str] = None) -> bool:
    """v2 passes recipient, so only the person the message was sent to can delete it. v1 passes None."""
    conn = get_db_connection()
    with conn:
        if recipient is None:
            cursor = conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        else:
            cursor = conn.execute("DELETE FROM messages WHERE id = ? AND recipient = ?", (message_id, recipient))
        deleted = cursor.rowcount > 0
    conn.close()
    return deleted

def raw_dump_messages() -> List[Dict[str, Any]]:
    """Used for security audit demonstrations (DB dump attack simulation)."""
    conn = get_db_connection()
    rows = conn.execute("SELECT id, sender, recipient, payload, is_sensitive, created_at FROM messages").fetchall()
    conn.close()
    return [dict(row) for row in rows]
