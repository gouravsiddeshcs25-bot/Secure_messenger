# Cybersecurity Skill Lab Attack Verification Results

This report records the automated attack tests executed against **Client v1** (Naive Insecure) and **Client v2** (Hardened Zero-Knowledge E2EE).

## 1. Attack Verification Matrix

| Attack | v1 Expected | v1 Actual | v2 Expected | v2 Actual | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| MITM swaps keys | succeeds silently | succeeds silently | caught by fingerprint check | caught by fingerprint check | **✅ PASS** |
| Replay captured message | accepted twice | accepted twice | rejected | rejected | **✅ PASS** |
| Tamper with ciphertext | altered text shown | altered text shown | auth tag fails | auth tag fails | **✅ PASS** |
| Dump server database | plaintext readable | plaintext readable | only ciphertext | only ciphertext | **✅ PASS** |
| Open expired message | still readable | still readable | key gone, undecryptable | key gone, undecryptable | **✅ PASS** |
| Unauthorized access | all succeed | all succeed | blocked (401/403/404/429) | blocked (401/403/404/429) | **✅ PASS** |

---

## 2. Attack Analysis & Technical Findings

### Attack 1: Man-In-The-Middle (MITM) Key Swap
- **Client v1 Result**: `succeeds silently`. Because Client v1 lacks public-key cryptographic binding, an attacker can register a handle or substitute endpoints without alerting either user.
- **Client v2 Defense**: `caught by fingerprint check`. Client v2 generates permanent Ed25519 identity keypairs that sign X25519 exchange keys. Alice and Bob calculate a deterministic out-of-band safety number (SHA-256 / BLAKE2b fingerprint over sorted public identity keys). Any rogue key swap causes fingerprint mismatch and drops communication.

### Attack 2: Replay Captured Message
- **Client v1 Result**: `accepted twice`. Client v1 does not maintain monotonic counters or nonces. Re-posting an intercepted ciphertext causes it to be rendered again in the UI.
- **Client v2 Defense**: `rejected`. Client v2 enforces strict session sequence counters. If an incoming message has a counter less than or equal to the recipient's high-water mark (`counter <= lastSeenCounter`), the packet is immediately dropped with `REPLAY_ATTACK_REJECTED`.

### Attack 3: Tamper with Ciphertext
- **Client v1 Result**: `altered text shown`. Plaintext payloads can be modified in transit or in the database; Client v1 renders the corrupted text with zero warnings.
- **Client v2 Defense**: `auth tag fails`. Client v2 encrypts payloads using **ChaCha20-Poly1305 (AEAD)**. Modifying even 1 bit in the ciphertext or associated metadata breaks the 128-bit Poly1305 authentication tag, causing immediate decryption failure.

### Attack 4: Dump Server Database
- **Client v1 Result**: `plaintext readable`. A database breach directly exposes sensitive message contents, passwords, and PII in plain text.
- **Client v2 Defense**: `only ciphertext`. The server is strictly zero-knowledge. The `messages` table contains only base64 ciphertext envelopes, nonces, and sender/recipient handles. Even with complete database exfiltration, contents remain undecryptable.

### Attack 5: Open Expired Message
- **Client v1 Result**: `still readable`. Messages persist forever in the database.
- **Client v2 Defense**: `key gone, undecryptable`. Client v2 sets server TTL purge timestamps, deletes one-time view records from the server immediately upon viewing, and explicitly wipes in-memory per-message keys using `sodium.memzero()`.

### Attack 6: Unauthorized Access
- **Client v1 Result**: `all succeed`. The v1 API (`/api/v1/...`) has no login, so Mallory can read Bob's inbox, send a message as Alice and delete Bob's messages.
- **Client v2 Defense**: `blocked (401/403/404/429)`. Every v2 call needs a session token (Argon2id password login, token stored only as a SHA-256 hash, 24h expiry). The server takes the user from the token, so Mallory can't overwrite Bob's keys, read his inbox (403), send as Alice or delete his messages (404). Six wrong passwords in a minute get HTTP 429, and logout ends the session.
