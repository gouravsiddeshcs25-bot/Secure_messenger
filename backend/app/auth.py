"""
Login and access control for the secure v2 API.

- Passwords are hashed with Argon2id (PyNaCl nacl.pwhash.argon2id). Argon2id is slow and memory-hungry on
  purpose, so a stolen database cannot be brute-forced quickly.
- A session token is 32 random bytes (secrets.token_urlsafe). The browser keeps the token. The database keeps
  only its SHA-256 hash, so a database leak does not hand out working tokens.
- require_user is the one shared FastAPI dependency that every v2 route uses to find out who is calling.
- RateLimiter is a small in-memory limiter that returns HTTP 429.

v1 routes never use anything in this file, because v1 stays insecure on purpose.
"""

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Optional

import nacl.exceptions
import nacl.pwhash
from fastapi import Header, HTTPException, Request, status

from . import database

SESSION_LIFETIME_SECONDS = 24 * 60 * 60  # 24 hours

_OPS = nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE
_MEM = nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE

# A hash of a random password. Used when the username does not exist, so the server still does one full
# Argon2id check. Then "wrong username" and "wrong password" take about the same time and look identical.
_DUMMY_HASH = nacl.pwhash.argon2id.str(secrets.token_bytes(32), opslimit=_OPS, memlimit=_MEM)

INVALID_LOGIN = "Invalid username or password"


# ---------- Passwords ----------

def hash_password(password: str) -> str:
    """Returns an Argon2id hash string (it includes its own random salt and settings)."""
    return nacl.pwhash.argon2id.str(password.encode("utf-8"), opslimit=_OPS, memlimit=_MEM).decode("ascii")


def check_login(username: str, password: str) -> bool:
    """True only if the user exists, has a password and the password matches."""
    stored = database.get_password_hash(username)
    target = stored.encode("ascii") if stored else _DUMMY_HASH
    try:
        ok = nacl.pwhash.argon2id.verify(target, password.encode("utf-8"))
    except nacl.exceptions.InvalidkeyError:
        ok = False
    # v1 users have no password hash and can never log in to v2.
    return ok and stored is not None


# ---------- Sessions ----------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_session(username: str) -> dict:
    """Creates a session and returns the token to the client. Only the hash is saved."""
    token = secrets.token_urlsafe(32)
    expires_at = database.store_session(_hash_token(token), username, SESSION_LIFETIME_SECONDS)
    return {"token": token, "expires_at": expires_at, "username": username}


def end_session(token: str):
    database.delete_session(_hash_token(token))


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Login required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def bearer_token(authorization: Optional[str] = Header(default=None)) -> str:
    """Reads 'Authorization: Bearer <token>'. Missing or malformed header -> 401."""
    if not authorization:
        raise _unauthorized()
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or len(token) > 200:
        raise _unauthorized()
    return token


def require_user(authorization: Optional[str] = Header(default=None)) -> str:
    """
    The shared dependency for every v2 route. Returns the logged-in username, or raises 401.
    Routes must use this value as "who is calling", never a username from the request body.
    """
    token = bearer_token(authorization)
    token_hash = _hash_token(token)
    session = database.get_session(token_hash)  # also checks the 24h expiry
    if session is None or not hmac.compare_digest(session["token_hash"], token_hash):
        raise _unauthorized()
    return session["username"]


# ---------- Rate limiting ----------

class RateLimiter:
    """
    Allows at most `limit` calls per `window` seconds for each key (for example an IP address).
    It lives in memory, so it resets when the server restarts. That is fine for this lab.
    """

    def __init__(self, limit: int, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str):
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many attempts. Wait a minute and try again.",
                )
            hits.append(now)


# Login: 5 tries per minute for one username from one IP (stops password guessing).
login_limiter = RateLimiter(limit=5)
# Register: 30 sign-ups per minute per IP (stops mass account creation, lets the attack suite run).
register_limiter = RateLimiter(limit=30)
# Telegram login: 30 per minute per IP. Sharing: 20 per minute per user (each share calls Telegram).
telegram_limiter = RateLimiter(limit=30)
share_limiter = RateLimiter(limit=20)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
