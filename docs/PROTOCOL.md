# Cryptographic Protocol Specification: Secure Messenger v2

## 1. Cryptographic Primitives
The cryptographic design uses standardized, proven algorithms provided by **libsodium**:
- **Identity & Signatures**: `Ed25519` (`crypto_sign`)
- **Key Agreement (Diffie-Hellman)**: `X25519` (`crypto_scalarmult`)
- **Per-Message Key Derivation (KDF)**: `BLAKE2b`-based KDF (`crypto_kdf_derive_from_key`)
- **Authenticated Encryption with Associated Data (AEAD)**: `ChaCha20-Poly1305 (IETF)` (`crypto_aead_chacha20poly1305_ietf`)
- **Safety Number / Fingerprint**: Lexicographically sorted concatenated identity public keys hashed via `crypto_generichash` (BLAKE2b) and rendered as a 24-digit / 6-group number.
- **Passphrase Hashing**: `Argon2id` (`crypto_pwhash`) for client re-authentication.

---

## 2. Key Registration & Out-of-Band Fingerprint Handshake

1. **User Key Generation**:
   - Each client generates:
     - Long-term identity signing keypair: $(ID_{pub}, ID_{priv}) \leftarrow \text{Ed25519\_Keypair}()$
     - Exchange keypair: $(X_{pub}, X_{priv}) \leftarrow \text{X25519\_Keypair}()$
   - Client signs their exchange key with their identity key:
     $$\sigma_{key} = \text{Ed25519\_Sign}(ID_{priv}, X_{pub})$$
   - Client publishes $(ID_{pub}, X_{pub}, \sigma_{key})$ to the server via `POST /api/keys`.

2. **Peer Key Verification**:
   - When Alice wants to message Bob, she queries `GET /api/keys/bob`.
   - Alice verifies:
     $$\text{Ed25519\_Verify}(ID_{pub}^{bob}, X_{pub}^{bob}, \sigma_{key}^{bob}) \stackrel{?}{=} \text{True}$$
   - If invalid, Alice rejects the key bundle immediately (MITM attack detected).

3. **Out-of-Band Safety Number (Fingerprint)**:
   - Alice and Bob derive a shared fingerprint:
     $$FP = \text{GenericHash}(\min(ID_{pub}^{alice}, ID_{pub}^{bob}) \mathbin{\Vert} \max(ID_{pub}^{alice}, ID_{pub}^{bob}))$$
   - Users compare this fingerprint out-of-band to ensure no rogue identity was injected.

4. **Shared Secret Derivation**:
   - Both parties compute the identical 32-byte shared master secret:
     $$K_{shared} = \text{X25519}(X_{priv}^{alice}, X_{pub}^{bob}) = \text{X25519}(X_{priv}^{bob}, X_{pub}^{alice})$$

---

## 3. Forward Secrecy & Per-Message Key Ratchet

For every outgoing message $i \in \{1, 2, 3, \dots\}$:
1. Sender increments their sequence counter: $C \leftarrow C + 1$.
2. Sender derives an isolated 256-bit message key using libsodium KDF:
   $$MKey_C = \text{crypto\_kdf\_derive\_from\_key}(32, C, \text{"MsgKey\_\_"}, K_{shared})$$
3. Sender generates a 24-byte random IETF nonce: $N \leftarrow \text{randombytes}(24)$.
4. Sender constructs an unencrypted Header $H$:
   ```json
   {
     "version": 2,
     "sender": "alice",
     "recipient": "bob",
     "counter": C,
     "timestamp": 1711200000,
     "is_sensitive": true,
     "ttl_seconds": 60,
     "one_time_view": true,
     "require_passphrase": false
   }
   ```
5. Sender encrypts plaintext $P$ with ChaCha20-Poly1305 AEAD, binding $H$ as Associated Data (AD):
   $$CT, Tag = \text{AEAD\_Encrypt}(MKey_C, N, P, AD=H)$$
6. Sender signs the serialized $(H \mathbin{\Vert} CT)$ with their identity private key:
   $$\sigma_{msg} = \text{Ed25519\_Sign}(ID_{priv}^{alice}, H \mathbin{\Vert} CT)$$
7. Sender scrubs $MKey_C$ from memory: $\text{memzero}(MKey_C)$.
8. Ciphertext envelope is transmitted to the server:
   $$\text{Envelope} = \{ H, N, CT, \sigma_{msg} \}$$

---

## 4. Recipient Decryption & Verification

Upon receiving $\text{Envelope} = \{ H, N, CT, \sigma_{msg} \}$:
1. **Signature Verification**:
   $$\text{Ed25519\_Verify}(ID_{pub}^{sender}, H \mathbin{\Vert} CT, \sigma_{msg}) \stackrel{?}{=} \text{True}$$
   If false, reject as forged.
2. **Replay Defense**:
   Check if $H.counter > \text{LastSeenCounter}[sender]$.
   If false, abort immediately with `REPLAY_ATTACK_DETECTED`.
   Update $\text{LastSeenCounter}[sender] \leftarrow H.counter$.
3. **Key Derivation**:
   $$MKey_C = \text{crypto\_kdf\_derive\_from\_key}(32, H.counter, \text{"MsgKey\_\_"}, K_{shared})$$
4. **AEAD Integrity & Decryption**:
   $$P = \text{AEAD\_Decrypt}(MKey_C, N, CT, AD=H)$$
   If the Poly1305 tag check fails, abort immediately with `INTEGRITY_CHECK_FAILED`.
5. **Memory Scrubbing**:
   $\text{memzero}(MKey_C)$.

---

## 5. Sensitive Ephemeral Message Protocol

When `is_sensitive == true`:
1. **Server Expiration**: The server sets `expires_at = datetime('now', +ttl)` and drops the record once expired.
2. **Client Expiration**: The client verifies $(Now - H.timestamp) \le H.ttl\_seconds$. If expired, the message is unviewable and purged.
3. **One-Time View**:
   - The message payload is unlocked in memory only upon user confirmation.
   - The client immediately issues `DELETE /api/messages/{id}` to erase server storage.
   - A local countdown timer (e.g. 15s) starts.
   - Upon timer expiry or user clicking "Burn Now", the decrypted text is wiped from the DOM and all key buffers zeroized.
4. **Passphrase Protection**:
   - If `require_passphrase == true`, recipient must provide their local passphrase.
   - Argon2id verifies recipient presence before unlocking the decrypted buffer in memory.
