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

## 3. Per-Message Keys

Each message gets its own key, derived from the shared secret and the message counter. This is **not** forward secrecy: anyone who steals $K_{shared}$ (or a private key) can derive every message key of that conversation. A Double Ratchet would fix this (future work).

For every outgoing message $i \in \{1, 2, 3, \dots\}$:
1. Sender increments their sequence counter: $C \leftarrow C + 1$.
2. Sender derives an isolated 256-bit message key using libsodium KDF:
   $$MKey_C = \text{crypto\_kdf\_derive\_from\_key}(32, C, \text{"MsgKey\_\_"}, K_{shared})$$
3. Sender generates a 12-byte random nonce (`crypto_aead_chacha20poly1305_ietf_NPUBBYTES` = 12): $N \leftarrow \text{randombytes}(12)$. Each message key is used once, so a nonce never repeats under the same key.
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

## Keys stored on the device (v2 web client)

- At sign-up the browser generates the Ed25519 identity key pair and the X25519 exchange key pair.
- The password is turned into a 32-byte storage key with Argon2id (`crypto_pwhash`, INTERACTIVE limits, random 16-byte salt).
- Private keys, contacts, counters and chat history are encrypted with XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf`, random 24-byte nonce, associated data `sm2-local-v1`) and only that ciphertext is written to `localStorage["sm2.vault.<username>"]`.
- New keys are made only at sign-up, or when the user signs in on a browser that has no keys and confirms it.

## Trust on first use and key changes

- The first identity key the client sees for a contact is remembered (inside the encrypted vault).
- Before every send, and every ~10 s for the open chat, the client fetches the contact's keys again.
- If the identity key is different, the chat shows "security key changed", **sending is blocked** and incoming messages from that contact are held, until the user compares the new safety number and accepts it. Accepting resets the contact to "not verified".
- "Verified" is shown only after the user confirms that the safety numbers match.
- `attacks/test_mitm_key_swap.py` checks this with a real server-side key swap.

## CipherBridge: messages through Telegram (🔒SM2)

Telegram's normal chats and bot chats are not end-to-end encrypted. CipherBridge adds our encryption on top:
the user writes the message in our app, the app seals it, and only the sealed text goes into Telegram.

**Sealing** (`sealForTelegram()` in `frontend/web/js/chat.js`, format in `frontend/web/js/sm2.js`):
1. Same steps as a normal v2 message: re-check the contact's keys (trust on first use), take the next message number
   for that contact, derive the per-message key, encrypt with ChaCha20-Poly1305 and sign with Ed25519.
2. The header gets one extra field, `channel: "telegram"`. It is inside the signed and authenticated header.
3. The text is `🔒SM2:` + base64url (no padding) of the envelope JSON `{header, nonce, ciphertext, signature}`.
   It must fit in one Telegram message (4096 characters), so the message itself is limited to 1500 characters.
4. Sensitive messages can't be sealed for Telegram: a pasted text can't disappear on a timer.

**Opening** (`openSm2()` in `chat.js`), in this order:
1. Decode the text. Refuse it if it isn't version 2 with `channel: "telegram"`.
2. Refuse it if `recipient` isn't me ("sealed for someone else") or `sender` is me.
3. Fetch the sender's keys and apply trust on first use. A changed key means: review it first, nothing is opened.
4. Check the Ed25519 signature and the Poly1305 tag. Any change to the text fails here ("tamper check").
5. Replay check: Telegram messages can be opened in any order, so the client keeps the list of message numbers
   it has already opened from each contact (`tgSeen` in the encrypted vault). A number seen before is refused.

The two routes can't be mixed up: the inbox refuses any envelope with a `channel` field, and the paste box refuses
any envelope without `channel: "telegram"`. Both routes share one counter per contact, so a message number, and so
a message key, is never used twice.

## Telegram login (Mini App)

1. Telegram opens the Mini App at `/tg/` and gives it `Telegram.WebApp.initData`, signed by Telegram.
2. The Mini App sends that string to `POST /api/tg/auth`. The server (`backend/app/telegram_auth.py`) checks it
   as described at https://core.telegram.org/bots/webapps ("Validating data received via the Mini App"):
   - `secret_key = HMAC-SHA256(key = "WebAppData", message = bot_token)`
   - `data_check_string` = every field except `hash`, sorted by name, as `key=value`, joined with `\n`
   - accept only if `hex(HMAC-SHA256(key = secret_key, message = data_check_string)) == hash`
     (compared with `hmac.compare_digest`), and `auth_date` is less than 1 hour old.
3. The user id is read only from the checked data. The account is `tg_<telegram id>`. `tg_` names can't be
   registered or used with a password, so a valid Telegram signature is the only way in.
4. The private keys are made on the phone and kept in the same encrypted vault as the web app, locked with a
   PIN (Argon2id) instead of a password. The PIN never leaves the device.
5. The bot only ever handles 🔒SM2 ciphertext (its Decrypt button opens `/tg/?m=<sealed text>`). It never decrypts.
