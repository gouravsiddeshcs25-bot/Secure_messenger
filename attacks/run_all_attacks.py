#!/usr/bin/env python3
"""
Unified Cybersecurity Skill Lab Attack Runner.
Executes all 6 attack vectors against Client v1 and Client v2,
prints a comparison matrix, and saves results into docs/RESULTS.md.
"""

import os
import sys
import time
import subprocess
import requests

# Windows consoles default to cp1252, which cannot print the emoji in the report
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure attacks directory is in sys.path
sys.path.insert(0, os.path.dirname(__file__))

import test_mitm_key_swap
import test_replay_attack
import test_tamper_ciphertext
import test_database_dump
import test_expired_message
import test_unauthorized_access

SERVER_URL = os.environ.get("SERVER_BASE", "http://127.0.0.1:8000")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_PATH = os.path.join(REPO_ROOT, "docs", "RESULTS.md")

def ensure_server_running():
    try:
        r = requests.get(f"{SERVER_URL}/", timeout=1)
        if r.ok:
            return None
    except Exception:
        pass
    
    print("Starting background server for attack suite...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    for _ in range(15):
        time.sleep(0.5)
        try:
            r = requests.get(f"{SERVER_URL}/", timeout=1)
            if r.ok:
                return proc
        except Exception:
            pass
    raise RuntimeError("Failed to connect to FastAPI server at " + SERVER_URL)

def run_suite():
    server_proc = ensure_server_running()
    print("=" * 80)
    print("🛡️  RUNNING SECURE MESSENGER CYBERSECURITY ATTACK LAB")
    print("=" * 80)

    attacks = [
        test_mitm_key_swap,
        test_replay_attack,
        test_tamper_ciphertext,
        test_database_dump,
        test_expired_message,
        test_unauthorized_access
    ]

    results = []
    all_passed = True

    for mod in attacks:
        try:
            res = mod.run()
            results.append(res)
            if not res["pass"]:
                all_passed = False
        except Exception as e:
            print(f"Error running {mod.__name__}: {e}")
            all_passed = False

    # Print Results Table
    print("\n" + "-" * 88)
    print(f"{'Attack':<26} | {'v1 Expected':<18} | {'v1 Actual':<18} | {'v2 Expected':<28} | {'v2 Actual':<28} | {'Status'}")
    print("-" * 88)

    for r in results:
        status = "✅ PASS" if r["pass"] else "❌ FAIL"
        print(f"{r['attack']:<26} | {r['v1_expected']:<18} | {r['v1_actual']:<18} | {r['v2_expected']:<28} | {r['v2_actual']:<28} | {status}")
    print("-" * 88)

    # Save to docs/RESULTS.md
    write_results_markdown(results)

    if server_proc:
        server_proc.terminate()

    return all_passed

def write_results_markdown(results):
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        f.write("# Cybersecurity Skill Lab Attack Verification Results\n\n")
        f.write("This report records the automated attack tests executed against **Client v1** (Naive Insecure) and **Client v2** (Hardened Zero-Knowledge E2EE).\n\n")
        f.write("## 1. Attack Verification Matrix\n\n")
        f.write("| Attack | v1 Expected | v1 Actual | v2 Expected | v2 Actual | Result |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for r in results:
            badge = "✅ PASS" if r["pass"] else "❌ FAIL"
            f.write(f"| {r['attack']} | {r['v1_expected']} | {r['v1_actual']} | {r['v2_expected']} | {r['v2_actual']} | **{badge}** |\n")

        f.write("\n---\n\n")
        f.write("## 2. Attack Analysis & Technical Findings\n\n")
        f.write("### Attack 1: Man-In-The-Middle (MITM) Key Swap\n")
        f.write("- **Client v1 Result**: `succeeds silently`. Because Client v1 lacks public-key cryptographic binding, an attacker can register a handle or substitute endpoints without alerting either user.\n")
        f.write("- **Client v2 Defense**: `caught by fingerprint check`. Client v2 generates permanent Ed25519 identity keypairs that sign X25519 exchange keys. Alice and Bob calculate a deterministic out-of-band safety number (SHA-256 / BLAKE2b fingerprint over sorted public identity keys). Any rogue key swap causes fingerprint mismatch and drops communication.\n\n")

        f.write("### Attack 2: Replay Captured Message\n")
        f.write("- **Client v1 Result**: `accepted twice`. Client v1 does not maintain monotonic counters or nonces. Re-posting an intercepted ciphertext causes it to be rendered again in the UI.\n")
        f.write("- **Client v2 Defense**: `rejected`. Client v2 enforces strict session sequence counters. If an incoming message has a counter less than or equal to the recipient's high-water mark (`counter <= lastSeenCounter`), the packet is immediately dropped with `REPLAY_ATTACK_REJECTED`.\n\n")

        f.write("### Attack 3: Tamper with Ciphertext\n")
        f.write("- **Client v1 Result**: `altered text shown`. Plaintext payloads can be modified in transit or in the database; Client v1 renders the corrupted text with zero warnings.\n")
        f.write("- **Client v2 Defense**: `auth tag fails`. Client v2 encrypts payloads using **ChaCha20-Poly1305 (AEAD)**. Modifying even 1 bit in the ciphertext or associated metadata breaks the 128-bit Poly1305 authentication tag, causing immediate decryption failure.\n\n")

        f.write("### Attack 4: Dump Server Database\n")
        f.write("- **Client v1 Result**: `plaintext readable`. A database breach directly exposes sensitive message contents, passwords, and PII in plain text.\n")
        f.write("- **Client v2 Defense**: `only ciphertext`. The server is strictly zero-knowledge. The `messages` table contains only base64 ciphertext envelopes, nonces, and sender/recipient handles. Even with complete database exfiltration, contents remain undecryptable.\n\n")

        f.write("### Attack 5: Open Expired Message\n")
        f.write("- **Client v1 Result**: `still readable`. Messages persist forever in the database.\n")
        f.write("- **Client v2 Defense**: `key gone, undecryptable`. Client v2 sets server TTL purge timestamps, deletes one-time view records from the server immediately upon viewing, and explicitly wipes in-memory per-message keys using `sodium.memzero()`.\n\n")

        f.write("### Attack 6: Unauthorized Access\n")
        f.write("- **Client v1 Result**: `all succeed`. The v1 API (`/api/v1/...`) has no login, so Mallory can read Bob's inbox, send a message as Alice and delete Bob's messages.\n")
        f.write("- **Client v2 Defense**: `blocked (401/403/404/429)`. Every v2 call needs a session token (Argon2id password login, token stored only as a SHA-256 hash, 24h expiry). The server takes the user from the token, so Mallory can't overwrite Bob's keys, read his inbox (403), send as Alice or delete his messages (404). Six wrong passwords in a minute get HTTP 429, and logout ends the session.\n")

    print(f"\n📄 Results successfully recorded to {RESULTS_PATH}")

if __name__ == "__main__":
    success = run_suite()
    sys.exit(0 if success else 1)
