#!/usr/bin/env python3
"""
Attack Lab 10: Script injection (stored XSS) through a username or a message.

Adversary goal:
Mallory puts HTML with JavaScript in her name or her message, for example
    <img src=x onerror=alert(document.cookie)>
If the receiver's page inserts that as HTML, the script runs inside the victim's page. There it can read the
session token and the decrypted messages, and in v2 even the unlocked private keys.

How this test checks it (statically, no browser needed):
  1. Live server: is Mallory's HTML name accepted and handed back unchanged to the victim?
  2. The page code: does the code that draws messages use an HTML sink (innerHTML, outerHTML,
     insertAdjacentHTML, document.write) on data from the server?

v1 accepts any sender name and draws it with innerHTML, so the script runs.
v2 only allows names made of a-z, 0-9, _ and -, and its pages never use an HTML sink: every piece of text is
put on the page with textContent, so HTML shows up as plain characters.
"""

import os
import re
import uuid

import requests

from client_sim import ClientV1, ClientV2, SERVER_BASE

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOAD = "<img src=x onerror=alert(1)>"
SINKS = re.compile(r"\.(innerHTML|outerHTML)\s*[+]?=|insertAdjacentHTML\s*\(|document\.write(ln)?\s*\(")

# Every page script v2 and the Mini App run (third-party libsodium in shared/vendor is not ours to scan).
V2_CODE_DIRS = ["frontend/web", "frontend/telegram-miniapp", "frontend/shared", "frontend/landing"]
V1_RENDER_FILE = "frontend/legacy-insecure/app.js"


def _sinks_in(path: str):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # Inline <script> blocks in HTML count too.
    return [m.group(0) for m in SINKS.finditer(text)]


def _v2_sinks():
    found = []
    for d in V2_CODE_DIRS:
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, d)):
            dirs[:] = [x for x in dirs if x != "vendor"]
            for name in files:
                if name.endswith((".js", ".mjs", ".html")):
                    path = os.path.join(root, name)
                    for hit in _sinks_in(path):
                        found.append(f"{os.path.relpath(path, REPO_ROOT)}: {hit}")
    return found


def test_v1_xss():
    uid = uuid.uuid4().hex[:6]
    victim = ClientV1(f"victim_xss_v1_{uid}")
    victim.register()
    # Mallory registers the payload as her v1 "name" (v1 accepts any name) and messages the victim.
    evil_name = f"<img src=x alt={uid} onerror=alert(1)>"
    requests.post(f"{SERVER_BASE}/api/v1/register", json={"username": evil_name})
    requests.post(f"{SERVER_BASE}/api/v1/messages", json={
        "sender": evil_name, "recipient": victim.username, "payload": "hi"})
    inbox = requests.get(f"{SERVER_BASE}/api/v1/messages/{victim.username}").json().get("messages", [])
    delivered = any(m["sender"] == evil_name for m in inbox)
    # ...and the v1 page draws the sender with innerHTML.
    with open(os.path.join(REPO_ROOT, V1_RENDER_FILE), encoding="utf-8") as f:
        drawn_as_html = re.search(r"\.innerHTML\s*=\s*`[^`]*\$\{sender\}", f.read()) is not None
    return {"v1_result": "script runs" if delivered and drawn_as_html else "not exploitable"}


def test_v2_xss():
    checks = {}
    uid = uuid.uuid4().hex[:6]
    # 1. HTML in a username is refused at sign-up (v2 and v1 both refuse HTML names for v2 accounts).
    r = requests.post(f"{SERVER_BASE}/api/register", json={"username": PAYLOAD, "password": "mallory-pass-1"})
    checks["html_username_refused"] = r.status_code in (400, 422)

    # 2. HTML in a message: the server only ever sees ciphertext, and the page shows the decrypted text with textContent.
    alice, bob = ClientV2(f"alice_xss_v2_{uid}"), ClientV2(f"bob_xss_v2_{uid}")
    alice.register()
    bob.register()
    alice.connect_peer(bob.username)
    alice.send_message(bob.username, PAYLOAD)
    received = bob.poll_messages()
    checks["payload_arrives_as_text"] = PAYLOAD in received

    # 3. No HTML sink anywhere in the v2 / Mini App page code.
    sinks = _v2_sinks()
    checks["no_html_sinks_in_v2"] = not sinks
    if sinks:
        print("  [xss] HTML sinks found in v2 code:", "; ".join(sinks))

    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print("  [xss] v2 checks that FAILED:", ", ".join(failed))
    return {"v2_result": "shown as text" if not failed else "script runs"}


def run():
    r1 = test_v1_xss()
    r2 = test_v2_xss()
    return {
        "attack": "Script injection (XSS)",
        "v1_expected": "script runs",
        "v1_actual": r1["v1_result"],
        "v2_expected": "shown as text",
        "v2_actual": r2["v2_result"],
        "pass": r1["v1_result"] == "script runs" and r2["v2_result"] == "shown as text",
    }


if __name__ == "__main__":
    print(run())
