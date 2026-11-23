"""
Simulated Client Framework for Attack Lab.
Provides Python clients for Client v1 (Insecure) and Client v2 (Zero-Knowledge E2EE)
to automate attacks and assert pass/fail outcomes.
"""

import subprocess
import json
import os
import requests
from typing import Dict, Any, List, Optional, Tuple

SERVER_BASE = os.environ.get("SERVER_BASE", "http://127.0.0.1:8000")
HELPER_JS = os.path.join(os.path.dirname(__file__), "crypto_helper.js")

def run_crypto_helper(action: str, input_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    args = ["node", HELPER_JS, action]
    if input_data is not None:
        args.append(json.dumps(input_data))
    proc = subprocess.run(args, capture_output=True, text=True, check=True)
    return json.loads(proc.stdout.strip())

class ClientV1:
    """Simulates Client v1 (Insecure): plaintext, no signatures, no replay check."""
    def __init__(self, username: str, base_url: str = SERVER_BASE):
        self.username = username
        self.base_url = base_url
        self.received_messages: List[str] = []
        self.raw_messages: List[Dict[str, Any]] = []

    def register(self):
        resp = requests.post(f"{self.base_url}/api/register", json={"username": self.username})
        resp.raise_for_status()

    def send_message(self, recipient: str, text: str) -> int:
        payload = json.dumps({
            "sender": self.username,
            "recipient": recipient,
            "content": text,
            "timestamp": 1700000000
        })
        resp = requests.post(f"{self.base_url}/api/messages", json={
            "sender": self.username,
            "recipient": recipient,
            "payload": payload,
            "is_sensitive": False
        })
        resp.raise_for_status()
        return resp.json()["message_id"]

    def poll_messages(self) -> List[str]:
        resp = requests.get(f"{self.base_url}/api/messages/{self.username}")
        if not resp.ok:
            return []
        msgs = resp.json().get("messages", [])
        new_texts = []
        for m in msgs:
            self.raw_messages.append(m)
            try:
                parsed = json.loads(m["payload"])
                content = parsed.get("content", m["payload"])
            except Exception:
                content = m["payload"]
            self.received_messages.append(content)
            new_texts.append(content)
        return new_texts

class ClientV2:
    """Simulates Client v2 (Hardened): Ed25519, X25519, ChaCha20-Poly1305, KDF, Replay defense."""
    def __init__(self, username: str, base_url: str = SERVER_BASE):
        self.username = username
        self.base_url = base_url
        self.keys = run_crypto_helper("generate_keys")
        self.peer_cache: Dict[str, Dict[str, Any]] = {}
        self.last_seen_counters: Dict[str, int] = {}
        self.out_counters: Dict[str, int] = {}
        self.received_messages: List[str] = []
        self.security_alerts: List[str] = []

    def register(self):
        requests.post(f"{self.base_url}/api/register", json={"username": self.username})
        resp = requests.post(f"{self.base_url}/api/keys", json={
            "username": self.username,
            "identity_pubkey": self.keys["identity_pub"],
            "exchange_pubkey": self.keys["exchange_pub"],
            "key_signature": self.keys["key_signature"]
        })
        resp.raise_for_status()

    def connect_peer(self, peer_username: str) -> Tuple[bool, str]:
        resp = requests.get(f"{self.base_url}/api/keys/{peer_username}")
        if not resp.ok:
            raise RuntimeError(f"Peer {peer_username} keys not found")
        peer_data = resp.json()

        # 1. Verify peer exchange key signature
        verify_res = run_crypto_helper("verify_key_sig", {
            "identity_pub": peer_data["identity_pubkey"],
            "exchange_pub": peer_data["exchange_pubkey"],
            "key_signature": peer_data["key_signature"]
        })
        sig_valid = verify_res.get("valid", False)

        # 2. Compute fingerprint
        fp_res = run_crypto_helper("compute_fingerprint", {
            "pub_a": self.keys["identity_pub"],
            "pub_b": peer_data["identity_pubkey"]
        })
        fingerprint = fp_res["fingerprint"]

        self.peer_cache[peer_username] = {
            "identity_pubkey": peer_data["identity_pubkey"],
            "exchange_pubkey": peer_data["exchange_pubkey"],
            "key_signature": peer_data["key_signature"],
            "fingerprint": fingerprint,
            "sig_valid": sig_valid
        }
        return sig_valid, fingerprint

    def send_message(self, recipient: str, text: str, is_sensitive: bool = False, ttl: int = 60) -> int:
        if recipient not in self.peer_cache:
            self.connect_peer(recipient)
        peer = self.peer_cache[recipient]

        self.out_counters[recipient] = self.out_counters.get(recipient, 0) + 1
        counter = self.out_counters[recipient]

        enc_res = run_crypto_helper("encrypt", {
            "sender_identity_priv": self.keys["identity_priv"],
            "sender_exchange_priv": self.keys["exchange_priv"],
            "recipient_exchange_pub": peer["exchange_pubkey"],
            "sender": self.username,
            "recipient": recipient,
            "counter": counter,
            "plaintext": text,
            "is_sensitive": is_sensitive,
            "ttl_seconds": ttl
        })

        wire_payload = json.dumps(enc_res)
        resp = requests.post(f"{self.base_url}/api/messages", json={
            "sender": self.username,
            "recipient": recipient,
            "payload": wire_payload,
            "is_sensitive": is_sensitive,
            "ttl_seconds": ttl
        })
        resp.raise_for_status()
        return resp.json()["message_id"]

    def poll_messages(self) -> List[str]:
        resp = requests.get(f"{self.base_url}/api/messages/{self.username}")
        if not resp.ok:
            return []
        msgs = resp.json().get("messages", [])
        decrypted_list = []

        for m in msgs:
            try:
                env = json.loads(m["payload"])
                header = env["header"]
                sender = header["sender"]
                counter = header["counter"]

                if sender not in self.peer_cache:
                    self.connect_peer(sender)
                peer = self.peer_cache[sender]

                # Replay protection check
                last_counter = self.last_seen_counters.get(sender, 0)
                if counter <= last_counter:
                    alert = f"REPLAY_ATTACK_REJECTED: Counter {counter} <= last {last_counter}"
                    self.security_alerts.append(alert)
                    continue
                self.last_seen_counters[sender] = counter

                # Decrypt
                dec_res = run_crypto_helper("decrypt", {
                    "recipient_exchange_priv": self.keys["exchange_priv"],
                    "sender_exchange_pub": peer["exchange_pubkey"],
                    "sender_identity_pub": peer["identity_pubkey"],
                    "header": header,
                    "nonce": env["nonce"],
                    "ciphertext": env["ciphertext"],
                    "signature": env["signature"]
                })

                if dec_res.get("status") == "success":
                    plaintext = dec_res["plaintext"]
                    self.received_messages.append(plaintext)
                    decrypted_list.append(plaintext)
                    # If one-time view sensitive, trigger server delete
                    if header.get("one_time_view"):
                        requests.delete(f"{self.base_url}/api/messages/{m['id']}")
                else:
                    self.security_alerts.append(f"AUTH_TAG_FAILED: {dec_res.get('error')}")
            except Exception as e:
                self.security_alerts.append(f"DECRYPTION_EXCEPTION: {str(e)}")

        return decrypted_list
