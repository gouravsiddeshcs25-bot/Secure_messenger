"""
FastAPI route handlers for Secure Messenger.
Endpoints support user registration, public key lookup/registration,
and message relaying.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from . import database

router = APIRouter(prefix="/api")

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)

class KeyPublishRequest(BaseModel):
    username: str
    identity_pubkey: str
    exchange_pubkey: str
    key_signature: str

class MessageSendRequest(BaseModel):
    sender: str
    recipient: str
    payload: str
    is_sensitive: Optional[bool] = False
    ttl_seconds: Optional[int] = None

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest):
    """Registers a new user handle."""
    success = database.register_user(req.username.strip())
    if not success:
        # If user already exists, we allow returning 200 to ease testing/reconnecting
        return {"status": "ok", "message": "User already registered or logged in", "username": req.username}
    return {"status": "created", "username": req.username}

@router.get("/users", response_model=List[str])
def list_users():
    """Returns list of registered usernames."""
    return database.get_all_users()

@router.post("/keys")
def publish_keys(req: KeyPublishRequest):
    """
    Publishes a user's public keys.
    The server stores these for directory lookup but never sees private keys.
    """
    database.store_keys(
        username=req.username,
        identity_pubkey=req.identity_pubkey,
        exchange_pubkey=req.exchange_pubkey,
        key_signature=req.key_signature
    )
    return {"status": "ok", "message": "Keys registered successfully"}

@router.get("/keys/{username}")
def retrieve_keys(username: str):
    """Retrieves public key bundle for recipient to perform key exchange & signature verification."""
    keys = database.get_keys(username)
    if not keys:
        raise HTTPException(status_code=404, detail="Public keys not found for user")
    return keys

@router.post("/messages", status_code=status.HTTP_201_CREATED)
def send_message(req: MessageSendRequest):
    """
    Accepts message payload.
    In v1: payload contains plaintext or naive string.
    In v2: payload is an encrypted ciphertext bundle with authentication tag.
    The server does NOT decrypt anything.
    """
    # Calculate expires_at if TTL is specified
    expires_at = None
    if req.ttl_seconds and req.ttl_seconds > 0:
        # SQLite datetime expression
        conn = database.get_db_connection()
        row = conn.execute(f"SELECT datetime('now', '+{int(req.ttl_seconds)} seconds') as exp").fetchone()
        conn.close()
        expires_at = row["exp"]

    msg_id = database.store_message(
        sender=req.sender,
        recipient=req.recipient,
        payload=req.payload,
        is_sensitive=bool(req.is_sensitive),
        expires_at=expires_at
    )
    return {"status": "ok", "message_id": msg_id, "expires_at": expires_at}

@router.get("/messages/{username}")
def get_messages(username: str):
    """Polls pending messages for a recipient."""
    messages = database.get_messages_for_recipient(username)
    return {"messages": messages}

@router.delete("/messages/{message_id}")
def delete_message(message_id: int):
    """Purges a message upon viewing (for one-time view sensitive messages)."""
    deleted = database.delete_message(message_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Message not found or already deleted")
    return {"status": "ok", "deleted": True}

@router.get("/dump/messages")
def dump_messages():
    """
    Audit endpoint: returns raw server database records of stored messages.
    Used by attack scripts to demonstrate the security impact of a database breach:
    - In v1, sensitive messages are clearly exposed in plaintext.
    - In v2, only unintelligible ciphertexts and nonces are exposed.
    """
    return {"stored_messages": database.raw_dump_messages()}
