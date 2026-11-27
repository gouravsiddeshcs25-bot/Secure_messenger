#!/usr/bin/env python3
"""
Attack Lab 1: Man-In-The-Middle (MITM) Key Swap Attack.
Compares vulnerability of Client v1 vs protection of Client v2.

Adversary Goal:
Mallory intercepts the key exchange and substitutes her own public key,
attempting to decrypt Alice's messages silently.
"""

import uuid
from client_sim import ClientV1, ClientV2, run_crypto_helper

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
    """Client v2 detects key swaps via Ed25519 signatures and out-of-band fingerprints."""
    # Unique names: v2 accounts have passwords, so the same name can't be registered twice.
    uid = uuid.uuid4().hex[:6]
    alice = ClientV2(f"alice_mitm_v2_{uid}")
    alice.register()
    
    bob = ClientV2(f"bob_mitm_v2_{uid}")
    bob.register()
    
    # Mallory generates rogue keys
    mallory_keys = run_crypto_helper("generate_keys")
    
    # Legitimate Alice & Bob Fingerprint
    expected_fp = run_crypto_helper("compute_fingerprint", {
        "pub_a": alice.keys["identity_pub"],
        "pub_b": bob.keys["identity_pub"]
    })["fingerprint"]
    
    # Mallory attempts to substitute Bob's identity key with Mallory's identity key
    mitm_fp = run_crypto_helper("compute_fingerprint", {
        "pub_a": alice.keys["identity_pub"],
        "pub_b": mallory_keys["identity_pub"]
    })["fingerprint"]
    
    # Comparison
    fingerprint_mismatch = (expected_fp != mitm_fp)
    
    # Furthermore, if Mallory tries to swap exchange key while keeping Bob's identity key:
    rogue_sig_check = run_crypto_helper("verify_key_sig", {
        "identity_pub": bob.keys["identity_pub"],
        "exchange_pub": mallory_keys["exchange_pub"],
        "key_signature": mallory_keys["key_signature"] # Signed by Mallory, not Bob!
    })["valid"]
    
    caught = fingerprint_mismatch and (not rogue_sig_check)
    return {
        "v2_result": "caught by fingerprint check" if caught else "undetected",
        "v2_protected": caught
    }

def run():
    r1 = test_v1_mitm()
    r2 = test_v2_mitm()
    return {
        "attack": "MITM swaps keys",
        "v1_expected": "succeeds silently",
        "v1_actual": r1["v1_result"],
        "v2_expected": "caught by fingerprint check",
        "v2_actual": r2["v2_result"],
        "pass": (r1["v1_result"] == "succeeds silently" and r2["v2_result"] == "caught by fingerprint check")
    }

if __name__ == "__main__":
    res = run()
    print(res)
