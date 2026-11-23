#!/usr/bin/env python3
"""
Attack Lab 3: Tamper with Ciphertext / Message Integrity Attack.
Compares vulnerability of Client v1 vs protection of Client v2.

Adversary Goal:
Attacker tampers with the message payload in transit or directly in the database,
attempting to alter the communication without being detected.
"""

import uuid
import requests
import json
from client_sim import ClientV1, ClientV2, SERVER_BASE

def test_v1_tamper():
    """Client v1 has NO MAC or AEAD integrity verification: displays modified text."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_tamper_v1_{uid}"
    bob_name = f"bob_tamper_v1_{uid}"

    alice = ClientV1(alice_name)
    alice.register()
    bob = ClientV1(bob_name)
    bob.register()
    
    # 1. Alice sends original message
    msg_id = alice.send_message(bob_name, "Approved budget: $1,000")
    
    # 2. Attacker tampers with the message in server or transit
    tampered_payload = json.dumps({
        "sender": alice_name,
        "recipient": bob_name,
        "content": "Approved budget: $99,999 (MALICIOUSLY ALTERED)",
        "timestamp": 1700000000
    })
    
    # Send tampered payload directly
    requests.post(f"{SERVER_BASE}/api/messages", json={
        "sender": alice_name,
        "recipient": bob_name,
        "payload": tampered_payload,
        "is_sensitive": False
    })
    
    # 3. Bob polls messages
    msgs = bob.poll_messages()
    altered_shown = any("MALICIOUSLY ALTERED" in m for m in msgs)
    
    return {
        "v1_result": "altered text shown" if altered_shown else "rejected",
        "v1_passed": altered_shown
    }

def test_v2_tamper():
    """Client v2 uses ChaCha20-Poly1305 AEAD: any bit modification breaks the 128-bit MAC."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_tamper_v2_{uid}"
    bob_name = f"bob_tamper_v2_{uid}"

    alice = ClientV2(alice_name)
    alice.register()
    bob = ClientV2(bob_name)
    bob.register()
    
    alice.connect_peer(bob_name)
    bob.connect_peer(alice_name)
    
    # 1. Alice sends authentic E2EE message
    msg_id = alice.send_message(bob_name, "Approved budget: $1,000")
    
    # 2. Attacker retrieves the raw envelope
    resp = requests.get(f"{SERVER_BASE}/api/dump/messages")
    stored = resp.json()["stored_messages"]
    original_envelope = [json.loads(m["payload"]) for m in stored if m["id"] == msg_id][-1]
    
    # 3. Attacker tampers with the ciphertext (flips bits)
    raw_ct = original_envelope["ciphertext"]
    tampered_ct = raw_ct[:-4] + ("AAAA" if raw_ct[-4:] != "AAAA" else "BBBB")
    
    tampered_envelope = dict(original_envelope)
    tampered_envelope["ciphertext"] = tampered_ct
    
    # Inject tampered message with next counter
    tampered_envelope["header"]["counter"] = 2
    
    requests.post(f"{SERVER_BASE}/api/messages", json={
        "sender": alice_name,
        "recipient": bob_name,
        "payload": json.dumps(tampered_envelope),
        "is_sensitive": False
    })
    
    # 4. Bob polls and attempts decryption
    bob.poll_messages()
    
    # Verify that the auth tag / signature check caught the modification
    auth_tag_failed = any("AUTH_TAG_FAILED" in a or "AUTHENTICATION_FAILED" in a or "DECRYPTION_EXCEPTION" in a for a in bob.security_alerts)
    tampered_text_not_decrypted = not any("budget" in m for m in bob.received_messages)
    
    return {
        "v2_result": "auth tag fails" if (auth_tag_failed or tampered_text_not_decrypted) else "altered text shown",
        "v2_protected": (auth_tag_failed or tampered_text_not_decrypted)
    }

def run():
    r1 = test_v1_tamper()
    r2 = test_v2_tamper()
    return {
        "attack": "Tamper with ciphertext",
        "v1_expected": "altered text shown",
        "v1_actual": r1["v1_result"],
        "v2_expected": "auth tag fails",
        "v2_actual": r2["v2_result"],
        "pass": (r1["v1_result"] == "altered text shown" and r2["v2_result"] == "auth tag fails")
    }

if __name__ == "__main__":
    print(run())
