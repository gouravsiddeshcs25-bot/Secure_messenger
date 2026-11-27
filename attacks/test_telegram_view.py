#!/usr/bin/env python3
"""
Attack Lab 8: What Telegram's servers can read.

Adversary goal:
Telegram's normal chats (and every bot chat) are not end-to-end encrypted, so Telegram's servers, or anyone
who gets into them, can read what is stored there. The attacker reads, changes or re-sends a message that
went through a Telegram chat.

v1: the message is plain text, so whoever holds the Telegram chat reads it (and can change it unnoticed).
v2: CipherBridge seals the message as a 🔒SM2 text before it is pasted into Telegram. We check that
    - the text Telegram stores contains no plaintext,
    - the intended recipient can open it,
    - a changed copy fails the tamper check,
    - the same copy can't be opened twice (replay),
    - someone else (Mallory) can't open it with her keys.

Uses the real crypto.js through crypto_helper.js, and the same 🔒SM2 format as frontend/web/js/sm2.js.
"""

import base64
import json
import uuid

from client_sim import ClientV1, run_crypto_helper

SM2_PREFIX = "\U0001F512SM2:"
SECRET = "The safe code is 4471, don't share it"


def sm2_encode(env: dict) -> str:
    raw = json.dumps(env).encode("utf-8")
    return SM2_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sm2_decode(text: str) -> dict:
    body = text.split("SM2:", 1)[1].strip()
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def open_sm2(text: str, me: dict, me_name: str, sender: dict, opened: set) -> str:
    """The same checks as openSm2() in chat.js. Returns the plaintext or an error code."""
    try:
        env = sm2_decode(text)
    except Exception:
        return "DAMAGED"
    h = env.get("header", {})
    if h.get("version") != 2 or h.get("channel") != "telegram":
        return "WRONG_FORMAT"
    if h.get("recipient") != me_name:
        return "NOT_FOR_ME"
    res = run_crypto_helper("decrypt", {
        "recipient_exchange_priv": me["exchange_priv"],
        "sender_exchange_pub": sender["exchange_pub"],
        "sender_identity_pub": sender["identity_pub"],
        "header": h, "nonce": env["nonce"], "ciphertext": env["ciphertext"], "signature": env["signature"],
    })
    if res.get("status") != "success":
        return "TAMPER_DETECTED"   # checked first, so a changed copy is never called a mere replay
    if (h["sender"], h["counter"]) in opened:
        return "REPLAY_REJECTED"
    opened.add((h["sender"], h["counter"]))
    return res["plaintext"]


def test_v1_telegram():
    """v1 sends plain text. Pasting it into Telegram = Telegram stores it readable."""
    uid = uuid.uuid4().hex[:6]
    alice = ClientV1(f"alice_tgv_v1_{uid}")
    alice.register()
    bob = ClientV1(f"bob_tgv_v1_{uid}")
    bob.register()
    alice.send_message(bob.username, SECRET)
    telegram_chat_log = [SECRET]  # what the user would paste into the Telegram chat
    return {"v1_result": "Telegram reads it" if any(SECRET in m for m in telegram_chat_log) else "hidden"}


def test_v2_telegram():
    alice = run_crypto_helper("generate_keys")
    bob = run_crypto_helper("generate_keys")
    mallory = run_crypto_helper("generate_keys")
    uid = uuid.uuid4().hex[:6]
    alice_name, bob_name = f"alice_{uid}", f"bob_{uid}"

    env = run_crypto_helper("encrypt", {
        "sender_identity_priv": alice["identity_priv"], "sender_exchange_priv": alice["exchange_priv"],
        "recipient_exchange_pub": bob["exchange_pub"], "sender": alice_name, "recipient": bob_name,
        "counter": 1, "plaintext": SECRET, "is_sensitive": False, "ttl_seconds": None, "channel": "telegram",
    })
    sealed = sm2_encode(env)  # this string is all Telegram ever stores

    checks = {}
    checks["no_plaintext_in_telegram"] = SECRET not in sealed and "4471" not in sealed
    checks["fits_one_telegram_message"] = len(sealed) <= 4096

    # Mallory (or Telegram) holds the text but not Bob's private key.
    checks["mallory_cannot_open"] = open_sm2(sealed, mallory, bob_name, alice, set()) == "TAMPER_DETECTED"

    # Someone edits the stored text: change one character of the ciphertext.
    tampered_env = sm2_decode(sealed)
    ct = tampered_env["ciphertext"]
    tampered_env["ciphertext"] = ("A" if ct[0] != "A" else "B") + ct[1:]
    checks["tampered_copy_rejected"] = open_sm2(sm2_encode(tampered_env), bob, bob_name, alice, set()) == "TAMPER_DETECTED"

    # Changing the header (e.g. pretending it's a different message number) also breaks the signature.
    moved = sm2_decode(sealed)
    moved["header"]["counter"] = 2
    checks["changed_header_rejected"] = open_sm2(sm2_encode(moved), bob, bob_name, alice, set()) == "TAMPER_DETECTED"

    # Bob opens it once; the very same copy pasted again is a replay.
    opened = set()
    checks["recipient_opens_it"] = open_sm2(sealed, bob, bob_name, alice, opened) == SECRET
    checks["second_open_is_replay"] = open_sm2(sealed, bob, bob_name, alice, opened) == "REPLAY_REJECTED"

    # Cut off when copying: refused, never half-shown.
    checks["cut_off_copy_rejected"] = open_sm2(sealed[: len(sealed) // 2], bob, bob_name, alice, set()) in ("DAMAGED", "TAMPER_DETECTED")

    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print("  [telegram view] v2 checks that FAILED:", ", ".join(failed))
    return {"v2_result": "only ciphertext, tamper caught" if not failed else "readable or accepted"}


def run():
    r1 = test_v1_telegram()
    r2 = test_v2_telegram()
    return {
        "attack": "Telegram reads the chat",
        "v1_expected": "Telegram reads it",
        "v1_actual": r1["v1_result"],
        "v2_expected": "only ciphertext, tamper caught",
        "v2_actual": r2["v2_result"],
        "pass": r1["v1_result"] == "Telegram reads it" and r2["v2_result"] == "only ciphertext, tamper caught",
    }


if __name__ == "__main__":
    print(run())
