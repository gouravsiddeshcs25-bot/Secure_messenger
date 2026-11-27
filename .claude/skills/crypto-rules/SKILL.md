---
name: crypto-rules
description: Rules for any change to encryption, keys, fingerprints, replay counters, expiry or crypto wording in Secure Messenger. Use before editing frontend/shared/crypto.js, key storage, docs/PROTOCOL.md, or writing any security claim.
---
# Crypto rules

**Ground truth:** `docs/PROTOCOL.md` + `frontend/shared/crypto.js`. The same crypto.js is loaded by
the browser (`/shared/crypto.js`) and by the attack suite (`attacks/crypto_helper.js`). Change it once and both are affected.

## Allowed primitives (libsodium / PyNaCl only)
| Purpose | Primitive |
|---|---|
| Identity / signing | Ed25519 (`crypto_sign_*`) |
| Key exchange | X25519 (`crypto_kx_*` / `crypto_scalarmult`) |
| Message AEAD | ChaCha20-Poly1305 IETF / XChaCha20-Poly1305 |
| KDF / hashing | `crypto_kdf_*`, BLAKE2b (`crypto_generichash`) |
| Password hashing (server) | Argon2id (`crypto_pwhash` / argon2-cffi) |
| Randomness | `randombytes_buf` / Python `secrets` |

Never: invent a primitive, use `Math.random`, ECB/CBC without a MAC, MD5/SHA1 for security, reuse a nonce
under a key, or move private keys to the server.

## Invariants the attack suite relies on
- An Ed25519 signature over the X25519 key is verified before use (MITM test).
- `counter <= lastSeenCounter` is rejected with `REPLAY_ATTACK_REJECTED` (replay test).
- AEAD failure is a hard error and never shows partial text (tamper test).
- The server stores only ciphertext envelopes (dump test).
- Expired or one-time messages are deleted on the server, and keys are wiped with `sodium.memzero` (expiry test).

## Planned work (step 4)
- Persisted identity keys in IndexedDB, with a passphrase-wrapped secret key (pwhash + secretbox).
- A key change for a known contact means a **blocking warning** before any new message is shown.
- The green tick only appears after the user confirms the fingerprint manually. It is never automatic.

## Honest wording
Say "end-to-end encrypted with libsodium (X25519 + ChaCha20-Poly1305)" and "the server cannot read message
content". Always add the limits: metadata (who, when, size) is visible, and a compromised endpoint defeats E2EE.
Never say unbreakable, military-grade or 100% secure.
