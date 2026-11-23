"""
Database management for Secure Messenger using Python's standard sqlite3 module.
Stores users, registered public keys, and message envelopes.
In v2 mode, the server operates strictly zero-knowledge: it only stores
ciphertext payloads, nonces, and public identity/exchange keys.
"""

import sqlite3
import os
from typing import Optional, List, Dict, Any

DB_PATH = os.environ.get("MESSENGER_DB_PATH", os.path.join(os.path.dirname(__file__), "messenger.db"))

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
    conn.close()

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

def delete_message(message_id: int) -> bool:
    conn = get_db_connection()
    with conn:
        cursor = conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        deleted = cursor.rowcount > 0
    conn.close()
    return deleted

def raw_dump_messages() -> List[Dict[str, Any]]:
    """Used for security audit demonstrations (DB dump attack simulation)."""
    conn = get_db_connection()
    rows = conn.execute("SELECT id, sender, recipient, payload, is_sensitive, created_at FROM messages").fetchall()
    conn.close()
    return [dict(row) for row in rows]
