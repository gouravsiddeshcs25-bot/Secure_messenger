#!/usr/bin/env python3
"""
Attack Lab 5: Open Expired Message Attack.
Compares vulnerability of Client v1 vs protection of Client v2.

Adversary Goal:
Recipient or device thief attempts to read a sensitive message
after its intended time-to-live (TTL) expiration window.
"""

import time
import uuid
import requests
import json
from client_sim import ClientV1, ClientV2, SERVER_BASE

def test_v1_expired():
    """Client v1 has NO expiration mechanism: messages persist indefinitely."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_exp_v1_{uid}"
    bob_name = f"bob_exp_v1_{uid}"

    alice = ClientV1(alice_name)
    alice.register()
    bob = ClientV1(bob_name)
    bob.register()
    
    # Alice sends a message intended to be temporary
    secret = f"TEMPORARY_OTP=889901_{uid}"
    msg_id = alice.send_message(bob_name, secret)
    
    # Wait 2 seconds (past intended short lifespan)
    time.sleep(2)
    
    # Check if Bob or an attacker can still retrieve the message
    resp = requests.get(f"{SERVER_BASE}/api/v1/messages/{bob_name}")
    msgs = resp.json().get("messages", [])
    still_readable = any(secret in m["payload"] for m in msgs)
    
    return {
        "v1_result": "still readable" if still_readable else "purged",
        "v1_passed": still_readable
    }

def test_v2_expired():
    """Client v2 enforces TTL expiry on the server and memory scrubbing on the client."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_exp_v2_{uid}"
    bob_name = f"bob_exp_v2_{uid}"

    alice = ClientV2(alice_name)
    alice.register()
    bob = ClientV2(bob_name)
    bob.register()
    
    alice.connect_peer(bob_name)
    bob.connect_peer(alice_name)
    
    secret = f"ONE_TIME_PASSCODE_EPHEMERAL_992144_{uid}"
    # Send sensitive message with 1 second TTL
    msg_id = alice.send_message(bob_name, secret, is_sensitive=True, ttl=1)
    
    # Wait 2 seconds for TTL to expire
    time.sleep(2)
    
    # Recipient attempts to poll after expiration
    resp = requests.get(f"{SERVER_BASE}/api/messages/{bob_name}", headers=bob.auth_headers())
    msgs = resp.json().get("messages", [])
    
    # Expired message is purged by server and cannot be decrypted
    message_purged = not any(m["id"] == msg_id for m in msgs)
    
    return {
        "v2_result": "key gone, undecryptable" if message_purged else "still readable",
        "v2_protected": message_purged
    }

def run():
    r1 = test_v1_expired()
    r2 = test_v2_expired()
    return {
        "attack": "Open expired message",
        "v1_expected": "still readable",
        "v1_actual": r1["v1_result"],
        "v2_expected": "key gone, undecryptable",
        "v2_actual": r2["v2_result"],
        "pass": (r1["v1_result"] == "still readable" and r2["v2_result"] == "key gone, undecryptable")
    }

if __name__ == "__main__":
    print(run())
