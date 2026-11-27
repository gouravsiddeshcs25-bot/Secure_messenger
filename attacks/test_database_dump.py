#!/usr/bin/env python3
"""
Attack Lab 4: Server Database Dump Attack.
Compares vulnerability of Client v1 vs protection of Client v2.

Adversary Goal:
A malicious server operator or external attacker dumps the SQL database
and attempts to read all past messages.
"""

import uuid
import requests
import json
from client_sim import ClientV1, ClientV2, SERVER_BASE, read_db_messages

def test_v1_dump():
    """Client v1 stores messages in plaintext: server breach reveals all data."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_dump_v1_{uid}"
    bob_name = f"bob_dump_v1_{uid}"

    alice = ClientV1(alice_name)
    alice.register()
    bob = ClientV1(bob_name)
    bob.register()
    
    secret_text = f"HR_CONFIDENTIAL_SALARY_ALICE=$150,000_{uid}"
    alice.send_message(bob_name, secret_text)
    
    # Adversary steals a full copy of the server database
    stored_messages = read_db_messages()
    
    # Check if secret text is readable in the dump
    plaintext_found = any(secret_text in m["payload"] for m in stored_messages)
    
    return {
        "v1_result": "plaintext readable" if plaintext_found else "not readable",
        "v1_passed": plaintext_found
    }

def test_v2_dump():
    """Client v2 is Zero-Knowledge: server database contains ONLY ciphertexts and public metadata."""
    uid = uuid.uuid4().hex[:6]
    alice_name = f"alice_dump_v2_{uid}"
    bob_name = f"bob_dump_v2_{uid}"

    alice = ClientV2(alice_name)
    alice.register()
    bob = ClientV2(bob_name)
    bob.register()
    
    alice.connect_peer(bob_name)
    bob.connect_peer(alice_name)
    
    secret_text = f"FINANCE_CONFIDENTIAL_REVENUE_Q4=$12,500,000_{uid}"
    msg_id = alice.send_message(bob_name, secret_text)
    
    # Adversary steals a full copy of the server database
    stored_messages = read_db_messages()
    
    # Locate Alice's message in the dump
    alice_row = [m for m in stored_messages if m["id"] == msg_id][-1]
    
    # Assert secret text is NEVER present anywhere in the database row
    secret_leaked = (secret_text in alice_row["payload"])
    
    # Assert payload is a valid ciphertext structure
    envelope = json.loads(alice_row["payload"])
    is_ciphertext_only = ("ciphertext" in envelope and "nonce" in envelope and not secret_leaked)
    
    return {
        "v2_result": "only ciphertext" if is_ciphertext_only else "plaintext readable",
        "v2_protected": is_ciphertext_only
    }

def run():
    r1 = test_v1_dump()
    r2 = test_v2_dump()
    return {
        "attack": "Dump server database",
        "v1_expected": "plaintext readable",
        "v1_actual": r1["v1_result"],
        "v2_expected": "only ciphertext",
        "v2_actual": r2["v2_result"],
        "pass": (r1["v1_result"] == "plaintext readable" and r2["v2_result"] == "only ciphertext")
    }

if __name__ == "__main__":
    print(run())
