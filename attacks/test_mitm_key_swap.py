#!/usr/bin/env python3
"""
Attack Lab 1: Man-In-The-Middle (MITM) Key Swap Attack.
Compares vulnerability of Client v1 vs protection of Client v2.

Adversary Goal:
Mallory intercepts the key exchange and substitutes her own public key,
attempting to decrypt Alice's messages silently.
"""

import uuid
from client_sim import ClientV1, ClientV2, run_crypto_helper, malicious_server_swap_keys, read_db_messages

def test_v1_mitm():
    """Client v1 has NO key verification or public key exchange."""
    # Alice sends sensitive message intended for Bob
    alice = ClientV1("alice_mitm_v1")
    alice.register()
    
    # Mallory registers as "bob" or intercepts plaintext relay
    mallory = ClientV1("bob_mitm_v1")
    mallory.register()
    
    # Alice sends sensitive message
    secret = "Top secret credentials: user=admin pass=12345"
    alice.send_message("bob_mitm_v1", secret)
    
    # Mallory polls and silently receives Alice's message in plaintext
    received = mallory.poll_messages()
    succeeded = any(secret in m for m in received)
    return {
        "v1_result": "succeeds silently" if succeeded else "failed",
        "v1_passed": succeeded # Attack succeeded against v1 (demonstrating vulnerability)
    }

def test_v2_mitm():
    """
    The server itself swaps Bob's keys AFTER Alice has already talked to Bob.
    Client v2 remembers the first identity key it saw (trust on first use), notices the change,
    raises KEY_CHANGED and refuses to send until the safety number is checked again.
    """
    uid = uuid.uuid4().hex[:6]
    alice = ClientV2(f"alice_mitm_v2_{uid}")
    alice.register()
    bob = ClientV2(f"bob_mitm_v2_{uid}")
    bob.register()

    # 1. First contact: Alice stores Bob's real identity key and sends normally
    alice.connect_peer(bob.username)
    first_id = alice.send_message(bob.username, "Hi Bob, first message")

    # 2. Malicious server replaces Bob's keys with Mallory's (validly self-signed) keys
    mallory_keys = run_crypto_helper("generate_keys")
    malicious_server_swap_keys(bob.username, mallory_keys)

    # 3. Alice fetches Bob's keys again (as the web client does before each send)
    sig_valid, _ = alice.connect_peer(bob.username)
    key_change_alert = any("KEY_CHANGED" in a for a in alice.security_alerts)

    # 4. Alice tries to send a secret: it must NOT be encrypted to Mallory's key
    secret_id = alice.send_message(bob.username, "Top secret: the vault code is 4471")
    nothing_sent = secret_id is None
    not_in_db = not any(m["sender"] == alice.username and m["id"] != first_id for m in read_db_messages())

    # Mallory's keys carry a valid signature, so the signature check alone would NOT catch this.
    # Only remembering the first key does.
    caught = first_id is not None and sig_valid and key_change_alert and nothing_sent and not_in_db
    return {
        "v2_result": "key change detected" if caught else "undetected",
        "v2_protected": caught
    }

def run():
    r1 = test_v1_mitm()
    r2 = test_v2_mitm()
    return {
        "attack": "MITM swaps keys",
        "v1_expected": "succeeds silently",
        "v1_actual": r1["v1_result"],
        "v2_expected": "key change detected",
        "v2_actual": r2["v2_result"],
        "pass": (r1["v1_result"] == "succeeds silently" and r2["v2_result"] == "key change detected")
    }

if __name__ == "__main__":
    res = run()
    print(res)
