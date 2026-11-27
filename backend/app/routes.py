"""
FastAPI route handlers for Secure Messenger.

Two separate routers:
- `router` at /api: the secure v2 API. Every route except register/login needs a session
  (Depends(require_user)), and the caller's identity always comes from that session.
- `v1_router` at /api/v1: the deliberately insecure v1 API used by the attack lab. No auth, no checks.
  Do NOT add security to it; the lab exists to show the difference.
"""

import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from . import auth, database
from .auth import require_user

router = APIRouter(prefix="/api")
v1_router = APIRouter(prefix="/api/v1")

MAX_TTL_SECONDS = 7 * 24 * 60 * 60   # one week
MAX_PAYLOAD_CHARS = 64 * 1024        # 64 KB envelope is plenty for a chat message

# ======================================================================
# v2 (secure)
# ======================================================================

class AccountRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=128)

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)

class KeyPublishRequest(BaseModel):
    identity_pubkey: str = Field(..., max_length=200)
    exchange_pubkey: str = Field(..., max_length=200)
    key_signature: str = Field(..., max_length=200)

class MessageSendRequest(BaseModel):
    recipient: str = Field(..., min_length=1, max_length=50)
    payload: str = Field(..., min_length=1, max_length=MAX_PAYLOAD_CHARS)
    is_sensitive: Optional[bool] = False
    ttl_seconds: Optional[int] = Field(default=None, ge=0, le=MAX_TTL_SECONDS)


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(req: AccountRequest, request: Request):
    """Creates an account with an Argon2id password hash and logs it in."""
    auth.register_limiter.hit(auth.client_ip(request))
    if not database.create_account(req.username, auth.hash_password(req.password)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username is taken")
    return auth.new_session(req.username)

@router.post("/login")
def login(req: LoginRequest, request: Request):
    """Same 401 text for an unknown user and a wrong password, so attackers can't find valid usernames."""
    username = req.username.strip().lower()
    auth.login_limiter.hit(f"{auth.client_ip(request)}|{username}")
    if not auth.check_login(username, req.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=auth.INVALID_LOGIN)
    return auth.new_session(username)

@router.post("/logout")
def logout(user: str = Depends(require_user), token: str = Depends(auth.bearer_token)):
    auth.end_session(token)
    return {"status": "ok"}

@router.get("/users", response_model=List[str])
def list_users(user: str = Depends(require_user)):
    return database.get_all_users()

@router.post("/keys")
def publish_keys(req: KeyPublishRequest, user: str = Depends(require_user)):
    """Saves public keys for the logged-in user only. Nobody can overwrite someone else's keys."""
    database.store_keys(
        username=user,
        identity_pubkey=req.identity_pubkey,
        exchange_pubkey=req.exchange_pubkey,
        key_signature=req.key_signature,
    )
    return {"status": "ok", "message": "Keys registered successfully"}

@router.get("/keys/{username}")
def retrieve_keys(username: str, user: str = Depends(require_user)):
    keys = database.get_keys(username)
    if not keys:
        raise HTTPException(status_code=404, detail="Public keys not found for user")
    return keys

@router.post("/messages", status_code=status.HTTP_201_CREATED)
def send_message(req: MessageSendRequest, user: str = Depends(require_user)):
    """The sender is the session user. The server never decrypts the payload."""
    if not database.user_exists(req.recipient):
        raise HTTPException(status_code=404, detail="Recipient not found")
    expires_at = database.ttl_to_expiry(req.ttl_seconds)
    msg_id = database.store_message(
        sender=user,
        recipient=req.recipient,
        payload=req.payload,
        is_sensitive=bool(req.is_sensitive),
        expires_at=expires_at,
    )
    return {"status": "ok", "message_id": msg_id, "expires_at": expires_at}

@router.get("/messages/{username}")
def get_messages(username: str, user: str = Depends(require_user)):
    """You can only read your own inbox."""
    if username != user:
        raise HTTPException(status_code=403, detail="You can only read your own messages")
    return {"messages": database.get_messages_for_recipient(user)}

@router.delete("/messages/{message_id}")
def delete_message(message_id: int, user: str = Depends(require_user)):
    """Only the recipient can delete. 'Not yours' and 'does not exist' give the same 404."""
    if not database.delete_message(message_id, recipient=user):
        raise HTTPException(status_code=404, detail="Message not found or already deleted")
    return {"status": "ok", "deleted": True}

@router.get("/dump/messages")
def dump_messages():
    """
    Lab-only "database breach" view for demos. Off unless the server runs with LAB_MODE=1 in secrets/.env.
    When it is off, it looks like the endpoint does not exist (404).
    """
    if os.environ.get("LAB_MODE") != "1":
        raise HTTPException(status_code=404, detail="Not Found")
    return {"stored_messages": database.raw_dump_messages()}

# ======================================================================
# v1 (INSECURE ON PURPOSE - attack-lab target, do not fix)
#
# Among v1 users it stays fully open. The only rule: v1 routes can't touch v2 accounts,
# otherwise /api/v1 would be a back door around all the v2 checks above.
# ======================================================================

def _not_v2(*usernames: str):
    for name in usernames:
        if database.is_v2_account(name):
            raise HTTPException(status_code=404, detail="Not a v1 user")

class V1RegisterRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)

class V1MessageSendRequest(BaseModel):
    sender: str
    recipient: str
    payload: str
    is_sensitive: Optional[bool] = False
    ttl_seconds: Optional[int] = None

@v1_router.post("/register", status_code=status.HTTP_201_CREATED)
def v1_register(req: V1RegisterRequest):
    """No password. Anyone can claim any name."""
    database.register_user(req.username.strip())
    return {"status": "ok", "username": req.username}

@v1_router.post("/messages", status_code=status.HTTP_201_CREATED)
def v1_send_message(req: V1MessageSendRequest):
    """Trusts the sender field from the body, so anyone can send as anyone."""
    _not_v2(req.sender, req.recipient)
    expires_at = database.ttl_to_expiry(req.ttl_seconds)
    msg_id = database.store_message(
        sender=req.sender,
        recipient=req.recipient,
        payload=req.payload,
        is_sensitive=bool(req.is_sensitive),
        expires_at=expires_at,
    )
    return {"status": "ok", "message_id": msg_id, "expires_at": expires_at}

@v1_router.get("/messages/{username}")
def v1_get_messages(username: str):
    """Anyone can read anyone's inbox."""
    _not_v2(username)
    return {"messages": database.get_messages_for_recipient(username)}

@v1_router.delete("/messages/{message_id}")
def v1_delete_message(message_id: int):
    """Anyone can delete any message."""
    if not database.delete_v1_message(message_id):
        raise HTTPException(status_code=404, detail="Message not found or already deleted")
    return {"status": "ok", "deleted": True}
