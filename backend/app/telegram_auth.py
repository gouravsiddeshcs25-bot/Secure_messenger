"""
Telegram Mini App login: checks that `Telegram.WebApp.initData` really came from Telegram.

How it works (from https://core.telegram.org/bots/webapps, "Validating data received via the Mini App"):
- Telegram signs the launch data with a key only Telegram and our bot know.
- secret_key = HMAC-SHA256(key = "WebAppData", message = bot_token)
- data_check_string = every received field except `hash`, sorted by name, written "key=value",
  joined with a newline ("\n").
- The data is genuine only if hex(HMAC-SHA256(key = secret_key, message = data_check_string)) == hash.
- `auth_date` is when the Mini App was opened. We refuse data older than MAX_AGE_SECONDS, so a copied
  initData string stops working after a while.

The `signature` field (Telegram's Ed25519 signature for third parties) is NOT removed from the check string:
the page says the HMAC covers all received fields, and only the separate Ed25519 method drops `signature`.

We only read the `user` field after the hash checks out. Never trust `initDataUnsafe` from the browser.
"""

import hashlib
import hmac
import json
import time
import urllib.parse
from typing import Optional

MAX_AGE_SECONDS = 60 * 60       # initData older than 1 hour is refused
MAX_CLOCK_SKEW_SECONDS = 60     # allow a small clock difference for auth_date "in the future"
MAX_INIT_DATA_CHARS = 4096


class InvalidInitData(Exception):
    """initData is missing, malformed, forged, tampered with or too old. The message is safe to show."""


def _secret_key(bot_token: str) -> bytes:
    return hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()


def sign_init_data(fields: dict, bot_token: str) -> str:
    """
    Builds a correctly signed initData string. Used ONLY by the attack tests, with a test token they make up.
    The real server never signs anything; Telegram does.
    """
    check = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    digest = hmac.new(_secret_key(bot_token), check.encode("utf-8"), hashlib.sha256).hexdigest()
    return urllib.parse.urlencode({**fields, "hash": digest})


def validate_init_data(init_data: str, bot_token: str, now: Optional[float] = None) -> dict:
    """
    Returns the Telegram user ({"id": int, "first_name": str, ...}) if initData is genuine and fresh.
    Raises InvalidInitData otherwise.
    """
    if not bot_token:
        raise InvalidInitData("Telegram login is not set up on this server")
    if not init_data or len(init_data) > MAX_INIT_DATA_CHARS:
        raise InvalidInitData("Missing or oversized Telegram data")

    try:
        pairs = urllib.parse.parse_qsl(init_data, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise InvalidInitData("Telegram data is malformed")
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise InvalidInitData("Telegram data has a repeated field")  # don't guess which copy is real
        fields[key] = value

    received_hash = fields.pop("hash", None)
    if not received_hash:
        raise InvalidInitData("Telegram data is not signed")

    check = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    expected = hmac.new(_secret_key(bot_token), check.encode("utf-8"), hashlib.sha256).hexdigest()
    # compare_digest takes the same time whether the first or the last character differs.
    # Compare bytes: a non-ASCII "hash" must be a clean 401, not a crash.
    if not hmac.compare_digest(expected.encode("ascii"), received_hash.lower().encode("utf-8")):
        raise InvalidInitData("Telegram signature check failed")

    # Only now, after the signature checked out, do we look at the content.
    try:
        auth_date = int(fields.get("auth_date", ""))
    except ValueError:
        raise InvalidInitData("Telegram data has no valid auth_date")
    now = time.time() if now is None else now
    if now - auth_date > MAX_AGE_SECONDS:
        raise InvalidInitData("Telegram data has expired. Close and reopen the Mini App.")
    if auth_date - now > MAX_CLOCK_SKEW_SECONDS:
        raise InvalidInitData("Telegram data is dated in the future")

    try:
        user = json.loads(fields.get("user", ""))
    except ValueError:
        raise InvalidInitData("Telegram data has no user")
    uid = user.get("id") if isinstance(user, dict) else None
    if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
        raise InvalidInitData("Telegram data has no valid user id")
    return user


def username_for(telegram_id: int) -> str:
    """Telegram accounts get the reserved name tg_<telegram id>. Nobody can register a tg_ name by hand."""
    return f"tg_{telegram_id}"


TELEGRAM_PREFIX = "tg_"
