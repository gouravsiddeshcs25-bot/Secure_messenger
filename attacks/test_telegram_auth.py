#!/usr/bin/env python3
"""
Attack Lab 7: Forged Telegram login (initData forgery).

Adversary goal:
Mallory wants to sign in to CipherBridge as someone else's Telegram account, so she can read their
messages or send messages in their name. She can make up any initData string she likes, copy an old one,
or change the user id inside a real one.

v1 has no login at all: anyone can claim any name and send as them.
v2 only accepts initData that carries Telegram's HMAC-SHA256 signature (made with our bot token), is less
than an hour old, and hasn't been changed after signing. tg_ names can't be registered or logged into any
other way.

The tests use a bot token made up inside this file. The real token is never read or needed.
"""

import json
import os
import secrets
import sys
import time
import uuid

import requests

from client_sim import ClientV1, ClientV2, SERVER_BASE

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.app.telegram_auth import InvalidInitData, sign_init_data, validate_init_data  # noqa: E402

# A fake token in the same shape as a real one (digits:letters). Generated fresh on every run.
TEST_TOKEN = f"{secrets.randbelow(10**9)}:{secrets.token_urlsafe(26)}"


def _fields(user_id: int, auth_date: int) -> dict:
    return {
        "auth_date": str(auth_date),
        "query_id": "AAH" + secrets.token_hex(6),
        "user": json.dumps({"id": user_id, "first_name": "Victim"}, separators=(",", ":")),
    }


def _rejected(init_data: str, token: str = TEST_TOKEN) -> bool:
    try:
        validate_init_data(init_data, token)
        return False
    except InvalidInitData:
        return True


def test_v1_forged_login():
    """v1: no proof of identity. Mallory registers the victim's name again and sends as them."""
    uid = uuid.uuid4().hex[:6]
    victim = ClientV1(f"victim_tg_v1_{uid}")
    victim.register()
    friend = ClientV1(f"friend_tg_v1_{uid}")
    friend.register()
    # Mallory "logs in" as the victim simply by using the name.
    claimed = requests.post(f"{SERVER_BASE}/api/v1/register", json={"username": victim.username}).ok
    sent = requests.post(f"{SERVER_BASE}/api/v1/messages", json={
        "sender": victim.username, "recipient": friend.username, "payload": "Send me your OTP (from Mallory)"}).ok
    return {"v1_result": "any name accepted" if claimed and sent else "blocked"}


def test_v2_forged_login():
    checks = {}
    now = int(time.time())
    victim_id = 100000000 + secrets.randbelow(10**8)

    # The validator itself, with a token only this test knows.
    good = sign_init_data(_fields(victim_id, now), TEST_TOKEN)
    try:
        checks["genuine_initdata_accepted"] = validate_init_data(good, TEST_TOKEN)["id"] == victim_id
    except InvalidInitData:
        checks["genuine_initdata_accepted"] = False

    wrong_key = sign_init_data(_fields(victim_id, now), f"999:{secrets.token_urlsafe(26)}")
    checks["forged_hash_rejected"] = _rejected(wrong_key)
    checks["missing_hash_rejected"] = _rejected("&".join(p for p in good.split("&") if not p.startswith("hash=")))
    # Change the user id inside a genuine, signed string (tampered after signing).
    tampered = good.replace(f"%22id%22%3A{victim_id}", f"%22id%22%3A{victim_id + 1}")
    checks["tampered_user_rejected"] = tampered != good and _rejected(tampered)
    checks["expired_rejected"] = _rejected(sign_init_data(_fields(victim_id, now - 2 * 3600), TEST_TOKEN))
    checks["future_date_rejected"] = _rejected(sign_init_data(_fields(victim_id, now + 3600), TEST_TOKEN))
    checks["repeated_field_rejected"] = _rejected(good + "&user=" + json.dumps({"id": 1}))
    checks["no_token_rejected"] = _rejected(good, token="")
    checks["odd_hash_rejected"] = _rejected(good.split("&hash=")[0] + "&hash=%C3%A9" + "0" * 63)
    bool_id = sign_init_data({**_fields(victim_id, now), "user": json.dumps({"id": True})}, TEST_TOKEN)
    checks["non_number_id_rejected"] = _rejected(bool_id)

    # The live server: initData signed with any key but the real bot token never logs in.
    r = requests.post(f"{SERVER_BASE}/api/tg/auth", json={"init_data": good})
    checks["server_refuses_forged_initdata"] = r.status_code in (401, 503) and "token" not in r.json()
    server_configured = r.status_code == 401
    r = requests.post(f"{SERVER_BASE}/api/tg/auth", json={"init_data": good.split("&hash=")[0] + "&hash=%C3%A9"})
    checks["server_odd_hash_no_crash"] = r.status_code in (401, 503)

    # tg_ names are reserved: no sign-up, no password login, not even through v1.
    reserved = f"tg_{victim_id}"
    r = requests.post(f"{SERVER_BASE}/api/register", json={"username": reserved, "password": "mallory-pass-1"})
    checks["tg_name_register_blocked"] = r.status_code == 400
    r = requests.post(f"{SERVER_BASE}/api/v1/register", json={"username": reserved})
    checks["tg_name_v1_register_blocked"] = r.status_code == 400
    r = requests.post(f"{SERVER_BASE}/api/login", json={"username": reserved, "password": "mallory-pass-1"})
    checks["tg_name_password_login_blocked"] = r.status_code == 401

    # The share endpoint needs a session, and only Telegram accounts may use it.
    checks["share_no_token_401"] = requests.post(f"{SERVER_BASE}/api/tg/share", json={"text": "x"}).status_code == 401
    web_user = ClientV2(f"mallory_tg_{uuid.uuid4().hex[:6]}")
    web_user.register()
    r = requests.post(f"{SERVER_BASE}/api/tg/share", json={"text": "\U0001F512SM2:abc"}, headers=web_user.auth_headers())
    checks["share_web_account_403"] = r.status_code == 403

    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print("  [telegram login] v2 checks that FAILED:", ", ".join(failed))
    if not server_configured:
        print("  [telegram login] note: the server has no TELEGRAM_BOT_TOKEN, so /api/tg/auth answers 503. "
              "The signature checks above still ran against the same code with a test token.")
    return {"v2_result": "forged login rejected" if not failed else "forged login accepted"}


def run():
    r1 = test_v1_forged_login()
    r2 = test_v2_forged_login()
    return {
        "attack": "Forged Telegram login",
        "v1_expected": "any name accepted",
        "v1_actual": r1["v1_result"],
        "v2_expected": "forged login rejected",
        "v2_actual": r2["v2_result"],
        "pass": r1["v1_result"] == "any name accepted" and r2["v2_result"] == "forged login rejected",
    }


if __name__ == "__main__":
    print(run())
