# Threat Model & Security Architecture: Secure Messenger

## 1. Problem Statement
Traditional messaging solutions protect data in transit (e.g., TLS) and often end-to-end between active endpoints. However, they provide minimal protection against post-delivery exposure, compromised or untrusted servers, and hostile recipients. Once delivered, messages typically persist indefinitely in plaintext databases on client devices, easily vulnerable to device theft, forensic recovery, server database exfiltration, or rogue recipients re-sharing confidential records.

This project implements a secure messenger for sensitive communication where:
- The server is strictly zero-knowledge (stores only encrypted blobs and public cryptographic identities).
- Even with a full database dump or network MITM, adversaries cannot read message contents or forge messages.
- Sensitive messages are ephemeral: enforced with one-time view restrictions, expiration timestamps, local cryptographic key destruction upon viewing, and passphrase-based client re-authentication.

---

## 2. Adversaries & Threat Profiles

| Adversary | Capabilities & Access | Defenses |
| :--- | :--- | :--- |
| **1. Network Eavesdropper / Man-in-the-Middle (MITM)** | Can intercept, drop, inject, tamper with, or replay network packets between client and server. | TLS in transit; client-side end-to-end encryption using **ChaCha20-Poly1305 (AEAD)**; identity signing with **Ed25519**; out-of-band **X25519/Ed25519 fingerprint verification**; sequence counters and timestamps to eliminate replay attacks. |
| **2. Malicious or Breached Server** | Complete control or dump of the central database; ability to inspect stored records, logs, and metadata; ability to alter stored ciphertext or attempt to inject rogue public keys. | **Zero-Knowledge design**: Server only receives ciphertext, nonces, and public keys. Private keys never leave the browser. Public keys are signed and verified against out-of-band fingerprints. AEAD authentication tags immediately detect server tampering. |
| **3. Recipient Turning Hostile** | Authenticated recipient who attempts to retain, re-export, or leak messages beyond intended scope or validity period. | Ephemeral sensitive-message mode: client-side memory scrubbing, strict one-time view enforcement, expiration timers, and immediate cryptographic deletion of per-message keys after decryption. |
| **4. Stolen or Unlocked Device** | Unauthorized physical or forensic access to a sender or recipient's unlocked workstation or browser session. | Master secrets and sensitive messages are not stored in plaintext `localStorage`; sensitive messages require local passphrase re-authentication via **Argon2id (`crypto_pwhash`)** to decrypt; in-memory session keys are zeroed upon session expiry. |

---

## 3. Security Properties Delivered

1. **Confidentiality**: Only the intended recipient holding the corresponding private key can decrypt the message payload.
2. **Integrity & Tamper Detection**: Authenticated Encryption with Associated Data (AEAD) ensures that any bit flip or alteration by the network or server causes decryption to fail.
3. **Authentication**: All messages and key announcements are cryptographically bound to the sender's long-term Ed25519 identity key.
4. **Replay Protection**: Messages include monotonically increasing session counters and timestamps; duplicate or out-of-order counter replays are rejected.
5. **Forward Secrecy**: Per-message keys are derived from the master shared secret combined with ratcheted message counters using HKDF-style key derivation (`crypto_kdf`). Compromise of an individual message key does not reveal past or future messages.
6. **Controlled Ephemerality & Revocation**: Sensitive messages carry an explicit time-to-live (TTL) and one-time view flags. Keys are wiped from client memory immediately upon display, and servers purge expired records.

---

## 4. Cryptographic Primitives & Design Choices

All cryptographic operations are performed strictly client-side using **libsodium** (`libsodium-wrappers`):
- **Identity & Signatures**: `Ed25519` (`crypto_sign`) for permanent user identity keys and message integrity signatures.
- **Key Exchange**: `X25519` (`crypto_kx` / `crypto_scalarmult`) for ephemeral and shared secret agreement.
- **Symmetric Encryption**: `ChaCha20-Poly1305` (`crypto_aead_chacha20poly1305_ietf`) providing high-performance 256-bit encryption with a 128-bit authentication tag.
- **Key Derivation (KDF)**: `crypto_kdf_derive_from_key` (BLAKE2b-based HKDF equivalent) to derive unique, non-reversible per-message encryption keys from the ratcheted shared secret.
- **Passphrase Re-Authentication**: `Argon2id` (`crypto_pwhash`) for memory-hard key derivation to unlock sensitive messages locally on the device.

---

## 5. Known Limitations & Honest Security Boundary

1. **Client Trust & Code Integrity in Web Browsers**:
   - In a web application model, the server serves the JavaScript code. A compromised server could theoretically alter the served JavaScript to exfiltrate keys. (Installed desktop/mobile apps with code signing mitigate this).
2. **Recipient Modification (Bypassing Ephemeral Controls)**:
   - Expiration and one-time view policies are enforced by the recipient's client runtime. A technologically sophisticated recipient who modifies their client code, intercepts network packets with their own private key, or attaches a memory debugger can retain messages.
3. **Screen Capture & Physical Displays**:
   - No cryptographic system can prevent a user from taking a physical photograph of the screen or using OS-level screen recording tools while a message is actively rendered.
