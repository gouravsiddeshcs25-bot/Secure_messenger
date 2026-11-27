#!/usr/bin/env python3
"""
Attack Lab 9: Reusing an old or stolen session.

Adversary goal:
Mallory wants to act as Bob without knowing his password. She tries:
  1. a token Bob already logged out of (copied from his browser earlier),
  2. a token that has expired,
  3. a token she made up,
  4. what she finds in a stolen copy of the database's sessions table,
  5. the lab "database dump" endpoint, which must stay locked unless the server was started with LAB_MODE=1.

v1 has no sessions at all: anyone can read Bob's inbox just by naming him.
v2 stores only a SHA-256 hash of each token, checks the expiry on every request, and deletes the session on logout.
"""

import hashlib
import secrets
import sqlite3
import uuid

import requests

from client_sim import DB_PATH, ClientV1, ClientV2, SERVER_BASE


def test_v1_no_session():
    uid = uuid.uuid4().hex[:6]
    alice, bob = ClientV1(f"alice_sess_v1_{uid}"), ClientV1(f"bob_sess_v1_{uid}")
    alice.register()
    bob.register()
    alice.send_message(bob.username, "Bob's bank PIN is 4321")
    # Mallory has no token, no password, nothing. She just asks for Bob's inbox.
    r = requests.get(f"{SERVER_BASE}/api/v1/messages/{bob.username}")
    read = r.ok and any("4321" in m["payload"] for m in r.json().get("messages", []))
    return {"v1_result": "no session needed" if read else "blocked"}


def _inbox_status(username: str, token: str) -> int:
    return requests.get(f"{SERVER_BASE}/api/messages/{username}",
                        headers={"Authorization": f"Bearer {token}"}).status_code


def _expire_sessions_of(username: str):
    """Moves Bob's session expiry into the past, the same as waiting until it runs out."""
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            conn.execute("UPDATE sessions SET expires_at = datetime('now', '-1 minute') WHERE username = ?", (username,))
    finally:
        conn.close()


def _session_rows(username: str):
    conn = sqlite3.connect(DB_PATH)
    try:
        return [r[0] for r in conn.execute("SELECT token_hash FROM sessions WHERE username = ?", (username,))]
    finally:
        conn.close()


def test_v2_session_reuse():
    checks = {}
    uid = uuid.uuid4().hex[:6]
    bob = ClientV2(f"bob_sess_v2_{uid}")
    bob.register()
    checks["fresh_token_works"] = _inbox_status(bob.username, bob.token) == 200

    # 4. Stolen database copy: the sessions table holds only hashes, never the token itself.
    rows = _session_rows(bob.username)
    checks["db_has_no_raw_token"] = bool(rows) and bob.token not in rows and \
        hashlib.sha256(bob.token.encode()).hexdigest() in rows
    # Presenting the stored hash as if it were the token doesn't work either.
    checks["stored_hash_is_useless"] = all(_inbox_status(bob.username, h) == 401 for h in rows)

    # 3. A made-up token.
    checks["made_up_token_401"] = _inbox_status(bob.username, secrets.token_urlsafe(32)) == 401

    # 1. Logout: the copied token stops working at once.
    old = bob.token
    requests.post(f"{SERVER_BASE}/api/logout", headers=bob.auth_headers())
    checks["logged_out_token_401"] = _inbox_status(bob.username, old) == 401

    # 2. Expiry: log in again, then let the session run out.
    r = requests.post(f"{SERVER_BASE}/api/login", json={"username": bob.username, "password": bob.password})
    new = r.json().get("token", "")
    checks["new_login_new_token"] = r.ok and new and new != old and _inbox_status(bob.username, new) == 200
    _expire_sessions_of(bob.username)
    checks["expired_token_401"] = _inbox_status(bob.username, new) == 401

    # 5. The lab dump endpoint stays closed on a normal server.
    dump = requests.get(f"{SERVER_BASE}/api/dump/messages").status_code
    checks["dump_endpoint_locked"] = dump == 404
    if dump != 404:
        print("  [session theft] /api/dump/messages is OPEN: the server runs with LAB_MODE=1. "
              "Remove LAB_MODE from secrets/.env and restart.")

    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print("  [session theft] v2 checks that FAILED:", ", ".join(failed))
    return {"v2_result": "old/stolen token refused" if not failed else "token reused"}


def run():
    r1 = test_v1_no_session()
    r2 = test_v2_session_reuse()
    return {
        "attack": "Reuse old/stolen session",
        "v1_expected": "no session needed",
        "v1_actual": r1["v1_result"],
        "v2_expected": "old/stolen token refused",
        "v2_actual": r2["v2_result"],
        "pass": r1["v1_result"] == "no session needed" and r2["v2_result"] == "old/stolen token refused",
    }


if __name__ == "__main__":
    print(run())
