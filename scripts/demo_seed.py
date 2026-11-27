#!/usr/bin/env python3
r"""
Puts a short plaintext conversation into the INSECURE v1 side, so the demo can show how much v1 gives away.

    python scripts\demo_seed.py

Run it while the server is running. It only uses the open v1 API (no v2 accounts, no keys):
v2 accounts must be created in the browser, because their private keys are made and kept there.
"""

import os
import sys

import requests

BASE = os.environ.get("SERVER_BASE", "http://127.0.0.1:8000")
ALICE, BOB = "alice_v1demo", "bob_v1demo"
MESSAGES = [
    (ALICE, BOB, "Hi Bob, the office wifi password is Blue-Mango-42"),
    (BOB, ALICE, "Thanks! Can you send the card for the client booking?"),
    (ALICE, BOB, "Card 4111 1111 1111 1111, expiry 08/29, CVV 123"),
    (ALICE, BOB, "And the bank OTP is 482913"),
]


def main():
    try:
        requests.get(f"{BASE}/", timeout=3)
    except requests.RequestException:
        print(f"The server is not running at {BASE}. Start it first (python scripts\\run_demo.py --no-telegram).")
        return 1
    for name in (ALICE, BOB):
        requests.post(f"{BASE}/api/v1/register", json={"username": name}, timeout=5)
    for sender, recipient, text in MESSAGES:
        r = requests.post(f"{BASE}/api/v1/messages", json={"sender": sender, "recipient": recipient, "payload": text}, timeout=5)
        r.raise_for_status()
    print(f"Added {len(MESSAGES)} plaintext v1 messages between {ALICE} and {BOB}.")
    print("Show that anyone can read them, with no login:")
    print(f"  {BASE}/api/v1/messages/{BOB}")
    print(f"Or open {BASE}/v1/ and sign in as {BOB}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
