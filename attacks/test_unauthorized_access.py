#!/usr/bin/env python3
"""
Attack Lab 6: Unauthorized Access (broken access control / IDOR).
Compares vulnerability of Client v1 vs protection of Client v2.

Adversary Goal:
Mallory has no account on Bob's or Alice's side. She tries to:
  1. overwrite Bob's public keys (so she could read his future messages),
  2. read Bob's inbox,
  3. send a message that looks like it came from Alice,
  4. delete Bob's messages,
  5. guess Bob's password many times (brute force),
  6. pull the whole message table from the lab dump endpoint.

v1 has no login, so steps 2-4 just work.
v2 needs a session token for everything, takes the user from the token, and checks ownership.
"""

import uuid
import requests
from client_sim import ClientV1, ClientV2, SERVER_BASE, run_crypto_helper


def test_v1_unauthorized():
    """v1: no token needed, the server trusts whatever the request says."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_acl_v1_{uid}"
    bob_name = f"bob_acl_v1_{uid}"
    alice = ClientV1(alice_name)
    alice.register()
    bob = ClientV1(bob_name)
    bob.register()

    alice.send_message(bob_name, "Private note for Bob")

    # 1. Mallory reads Bob's inbox without logging in
    inbox = requests.get(f"{SERVER_BASE}/api/v1/messages/{bob_name}").json().get("messages", [])
    read_ok = any("Private note for Bob" in m["payload"] for m in inbox)

    # 2. Mallory sends a message with sender = Alice
    requests.post(f"{SERVER_BASE}/api/v1/messages", json={
        "sender": alice_name, "recipient": bob_name, "payload": "Pay Mallory 1000 (fake Alice)"})
    inbox = requests.get(f"{SERVER_BASE}/api/v1/messages/{bob_name}").json().get("messages", [])
    spoof_ok = any(m["sender"] == alice_name and "fake Alice" in m["payload"] for m in inbox)

    # 3. Mallory deletes Bob's first message
    target_id = inbox[0]["id"] if inbox else -1
    delete_ok = requests.delete(f"{SERVER_BASE}/api/v1/messages/{target_id}").status_code == 200

    succeeded = read_ok and spoof_ok and delete_ok
    return {"v1_result": "all succeed" if succeeded else "some blocked"}


def test_v2_unauthorized():
    """v2: every attempt must be refused, and Bob's data must stay unchanged."""
    uid = uuid.uuid4().hex[:6]
    alice = ClientV2(f"alice_acl_v2_{uid}")
    alice.register()
    bob = ClientV2(f"bob_acl_v2_{uid}")
    bob.register()
    mallory = ClientV2(f"mallory_acl_v2_{uid}")
    mallory.register()

    alice.connect_peer(bob.username)
    msg_id = alice.send_message(bob.username, "Private note for Bob")

    checks = {}
    rogue = run_crypto_helper("generate_keys")
    rogue_body = {
        "username": bob.username,  # Mallory tries to name Bob as the owner
        "identity_pubkey": rogue["identity_pub"],
        "exchange_pubkey": rogue["exchange_pub"],
        "key_signature": rogue["key_signature"],
    }

    # 1a. Overwrite Bob's keys with no token -> 401
    r = requests.post(f"{SERVER_BASE}/api/keys", json=rogue_body)
    checks["keys_no_token_401"] = r.status_code == 401
    # 1b. Overwrite Bob's keys with Mallory's own token -> keys are saved under Mallory, Bob's stay the same
    requests.post(f"{SERVER_BASE}/api/keys", json=rogue_body, headers=mallory.auth_headers())
    bob_keys = requests.get(f"{SERVER_BASE}/api/keys/{bob.username}", headers=alice.auth_headers()).json()
    checks["bob_keys_unchanged"] = bob_keys.get("identity_pubkey") == bob.keys["identity_pub"]

    # 2a. Read Bob's inbox with no token / a made-up token -> 401
    r = requests.get(f"{SERVER_BASE}/api/messages/{bob.username}")
    checks["inbox_no_token_401"] = r.status_code == 401
    r = requests.get(f"{SERVER_BASE}/api/messages/{bob.username}",
                     headers={"Authorization": "Bearer forged-token-123"})
    checks["inbox_bad_token_401"] = r.status_code == 401
    # 2b. Read Bob's inbox with Mallory's token -> 403
    r = requests.get(f"{SERVER_BASE}/api/messages/{bob.username}", headers=mallory.auth_headers())
    checks["inbox_other_user_403"] = r.status_code == 403

    # 3. Send "as Alice": the server ignores the sender field and uses Mallory's session
    requests.post(f"{SERVER_BASE}/api/messages", headers=mallory.auth_headers(), json={
        "sender": alice.username, "recipient": bob.username, "payload": "fake Alice"})
    inbox = requests.get(f"{SERVER_BASE}/api/messages/{bob.username}", headers=bob.auth_headers()).json()["messages"]
    fake = [m for m in inbox if m["payload"] == "fake Alice"]
    checks["sender_from_session"] = bool(fake) and all(m["sender"] == mallory.username for m in fake)

    # 4. Delete Bob's message: no token -> 401, Mallory's token -> 404, and the message is still there
    r = requests.delete(f"{SERVER_BASE}/api/messages/{msg_id}")
    checks["delete_no_token_401"] = r.status_code == 401
    r = requests.delete(f"{SERVER_BASE}/api/messages/{msg_id}", headers=mallory.auth_headers())
    checks["delete_other_user_404"] = r.status_code == 404
    inbox = requests.get(f"{SERVER_BASE}/api/messages/{bob.username}", headers=bob.auth_headers()).json()["messages"]
    checks["bob_message_still_there"] = any(m["id"] == msg_id for m in inbox)

    # 4b. Back door: use the open v1 API on Bob's v2 account -> refused, message untouched
    r_read = requests.get(f"{SERVER_BASE}/api/v1/messages/{bob.username}")
    r_del = requests.delete(f"{SERVER_BASE}/api/v1/messages/{msg_id}")
    r_send = requests.post(f"{SERVER_BASE}/api/v1/messages", json={
        "sender": alice.username, "recipient": bob.username, "payload": "fake Alice via v1"})
    inbox = requests.get(f"{SERVER_BASE}/api/messages/{bob.username}", headers=bob.auth_headers()).json()["messages"]
    checks["v1_backdoor_blocked"] = (r_read.status_code == 404 and r_del.status_code == 404 and
                                     r_send.status_code == 404 and any(m["id"] == msg_id for m in inbox))

    # 5. Brute force: 6 wrong passwords for Bob in a row -> the 6th gets 429
    codes = [requests.post(f"{SERVER_BASE}/api/login",
                           json={"username": bob.username, "password": f"guess-{i}-wrong"}).status_code
             for i in range(6)]
    checks["wrong_password_401"] = codes[0] == 401
    checks["brute_force_429"] = codes[-1] == 429
    # Unknown user gets exactly the same answer as a wrong password
    r = requests.post(f"{SERVER_BASE}/api/login", json={"username": f"nobody_{uid}", "password": "whatever123"})
    checks["same_error_unknown_user"] = (r.status_code == 401 and
                                         r.json().get("detail") == "Invalid username or password")

    # 6. Logout really ends the session
    r = requests.post(f"{SERVER_BASE}/api/logout", headers=mallory.auth_headers())
    r2 = requests.get(f"{SERVER_BASE}/api/users", headers=mallory.auth_headers())
    checks["logout_kills_token"] = r.status_code == 200 and r2.status_code == 401

    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print("  [unauthorized access] v2 checks that FAILED:", ", ".join(failed))

    # 7. Lab dump endpoint: must be 404 unless the server was started with LAB_MODE=1
    dump_status = requests.get(f"{SERVER_BASE}/api/dump/messages").status_code
    if dump_status != 404:
        print("  [unauthorized access] note: /api/dump/messages is OPEN (server runs with LAB_MODE=1). "
              "Remove LAB_MODE from secrets/.env after the demo.")

    return {"v2_result": "blocked (401/403/404/429)" if not failed else "access allowed"}


def run():
    r1 = test_v1_unauthorized()
    r2 = test_v2_unauthorized()
    return {
        "attack": "Unauthorized access",
        "v1_expected": "all succeed",
        "v1_actual": r1["v1_result"],
        "v2_expected": "blocked (401/403/404/429)",
        "v2_actual": r2["v2_result"],
        "pass": (r1["v1_result"] == "all succeed" and r2["v2_result"] == "blocked (401/403/404/429)"),
    }


if __name__ == "__main__":
    print(run())
