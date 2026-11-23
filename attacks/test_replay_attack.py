#!/usr/bin/env python3
"""
Attack Lab 2: Replay Attack.
Compares vulnerability of Client v1 vs protection of Client v2.

Adversary Goal:
Eavesdropper captures an authentic message packet and retransmits it
to trick the recipient into processing it again.
"""

import uuid
import requests
import json
from client_sim import ClientV1, ClientV2, SERVER_BASE

def test_v1_replay():
    """Client v1 has NO replay counters or nonces: accepts duplicate messages."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_rep_v1_{uid}"
    bob_name = f"bob_rep_v1_{uid}"

    alice = ClientV1(alice_name)
    alice.register()
    bob = ClientV1(bob_name)
    bob.register()
    
    # 1. Alice sends original message
    msg_id = alice.send_message(bob_name, "Transfer $500 to account #9988")
    
    # 2. Bob polls and receives it once
    msgs1 = bob.poll_messages()
    
    # 3. Attacker captures the message payload and replays it to the server
    captured_payload = bob.raw_messages[-1]["payload"]
    requests.post(f"{SERVER_BASE}/api/messages", json={
        "sender": alice_name,
        "recipient": bob_name,
        "payload": captured_payload,
        "is_sensitive": False
    })
    
    # 4. Bob polls again
    msgs2 = bob.poll_messages()
    
    # If the message appears twice in bob's history, v1 accepted the replay
    total_received = sum(1 for m in bob.received_messages if "Transfer $500" in m)
    accepted_twice = (total_received >= 2)
    return {
        "v1_result": "accepted twice" if accepted_twice else "rejected",
        "v1_passed": accepted_twice
    }

def test_v2_replay():
    """Client v2 enforces monotonically increasing sequence counters."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_rep_v2_{uid}"
    bob_name = f"bob_rep_v2_{uid}"

    alice = ClientV2(alice_name)
    alice.register()
    bob = ClientV2(bob_name)
    bob.register()
    
    # Connect
    alice.connect_peer(bob_name)
    bob.connect_peer(alice_name)
    
    # 1. Alice sends original E2EE message (counter = 1)
    alice.send_message(bob_name, "Transfer $500 to account #9988")
    
    # 2. Bob polls and receives message 1
    msgs1 = bob.poll_messages()
    assert len(msgs1) == 1, f"Bob should have received exactly 1 message, got {len(msgs1)}"
    
    # 3. Attacker captures ciphertext envelope from the server and replays it
    resp = requests.get(f"{SERVER_BASE}/api/dump/messages")
    stored = resp.json()["stored_messages"]
    replayed_payload = [m["payload"] for m in stored if m["sender"] == alice_name][-1]
    
    # Replay identical envelope (counter = 1)
    requests.post(f"{SERVER_BASE}/api/messages", json={
        "sender": alice_name,
        "recipient": bob_name,
        "payload": replayed_payload,
        "is_sensitive": False
    })
    
    # 4. Bob polls again
    msgs2 = bob.poll_messages()
    
    # Check if Bob rejected the replayed counter
    has_replay_alert = any("REPLAY_ATTACK_REJECTED" in a for a in bob.security_alerts)
    not_decrypted_twice = (len(bob.received_messages) == 1)
    rejected = has_replay_alert and not_decrypted_twice
    
    return {
        "v2_result": "rejected" if rejected else "accepted twice",
        "v2_protected": rejected
    }

def run():
    r1 = test_v1_replay()
    r2 = test_v2_replay()
    return {
        "attack": "Replay captured message",
        "v1_expected": "accepted twice",
        "v1_actual": r1["v1_result"],
        "v2_expected": "rejected",
        "v2_actual": r2["v2_result"],
        "pass": (r1["v1_result"] == "accepted twice" and r2["v2_result"] == "rejected")
    }

if __name__ == "__main__":
    print(run())
