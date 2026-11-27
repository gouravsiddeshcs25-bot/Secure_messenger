# Project Report: Secure Messenger and CipherBridge

## 1. Problem
Messengers usually protect messages on the wire. The weak spots are the places a message rests: the server's
database, the chat platform, a session token someone copied, and the person or device at the other end. We wanted to
show, with working code and repeatable attacks, what goes wrong in a naive messenger and what each defense stops.

The project has two clients on one server:
- **v1 (insecure target):** plaintext messages, no login, the server trusts every field it is sent. It is kept broken on purpose.
- **v2 (hardened):** end-to-end encryption in the browser, password accounts with sessions, keys kept on the device,
  a key-change warning, sensitive messages that expire. **CipherBridge** runs the same v2 client inside Telegram as a
  Mini App, and can seal a message into a `🔒SM2:` text that is safe to post in any chat (Telegram, WhatsApp).

## 2. Threat model (summary)
Full version with every adversary and the test that checks it: [THREAT_MODEL.md](THREAT_MODEL.md).

| Adversary | Defense in v2 |
| :--- | :--- |
| Someone in the middle (network or server) swapping keys | Signed keys, trust on first use, blocking key-change warning, safety numbers |
| Replay and tampering | Signed counters; ChaCha20-Poly1305 tag with the header as associated data; Ed25519 signature |
| Breached database | Only ciphertext, Argon2id password hashes, SHA-256 token hashes |
| Users without the right account; password guessing; stolen tokens | Session on every call, user from the token, ownership checks, 429 rate limit, logout and expiry |
| Script injection | Strict usernames, text only through `textContent` |
| Telegram reading chats; forged Telegram login | 🔒SM2 sealing on the phone; `initData` HMAC check with a 1-hour limit |
| Stolen device | Keys and history sealed with Argon2id + XChaCha20-Poly1305 under the password or PIN |

## 3. Design

### 3.1 Cryptography (libsodium only, no hand-made crypto)
Details and packet formats: [PROTOCOL.md](PROTOCOL.md).
- Each user has an **Ed25519** identity key (signing) and an **X25519** exchange key, made in the browser at sign-up.
  The public halves are signed and published; the private halves never leave the device.
- Two users get a shared secret with X25519. Each message key is derived from it and the message counter with
  `crypto_kdf_derive_from_key`, so every message has its own key (this is *not* forward secrecy; see limits).
- Messages are encrypted with **ChaCha20-Poly1305** (random 12-byte nonce). The header (sender, recipient, counter,
  time, sensitive flags) is the associated data, and the sender signs header and ciphertext with Ed25519.
- The **safety number** is a BLAKE2b hash of both identity keys, shown as 6 groups of 4 digits.

### 3.2 Accounts and sessions (server)
- Passwords are hashed with **Argon2id** (PyNaCl). Unknown users and wrong passwords get the same answer, and a dummy
  hash keeps the timing the same.
- Login returns a random 32-byte token. The database stores only its **SHA-256 hash** and an expiry (24 h).
- Every v2 route takes the user from the token, never from the request body, and checks that the user owns what they touch.
- Login is limited to 5 tries per minute per IP and username (HTTP 429).

### 3.3 Keys on the device
The v2 client keeps a "vault" in browser storage: private keys, the identity key first seen for each contact,
counters and normal message history. It is sealed with **XChaCha20-Poly1305** under a key from **Argon2id** of the
password (in the Mini App: of a PIN of at least 6 characters). Sensitive messages are never saved.

### 3.4 Trust on first use
The first identity key seen for a contact is remembered. If the server later hands out a different key, the chat
turns red, sending is blocked and incoming messages are held until the user reviews the change and compares safety
numbers again.

### 3.5 Sensitive messages
A sensitive message carries a time limit (30 s to 5 min), can be view-once, and can ask for the password again before
opening. The client shows a countdown, wipes the message key with `sodium.memzero` and deletes the envelope from the
server. The server also deletes expired envelopes. A client-side **DLP** check (card numbers with the Luhn check,
Aadhaar-like numbers, API keys) switches sensitive mode on by itself.

### 3.6 CipherBridge (Telegram)
- **Login:** the Mini App sends Telegram's signed `initData` to `/api/tg/auth`. The server recomputes Telegram's
  HMAC-SHA256 with a key derived from the bot token, compares in constant time, and refuses data older than one hour.
  Each Telegram user gets the reserved name `tg_<id>`, which can't be registered or used with a password.
- **Sealing:** the message is encrypted on the phone exactly like a v2 message, with `channel: "telegram"` in the signed
  header, and written as `🔒SM2:` + base64url. Telegram, the bot and our server see only that text.
- **Opening:** paste the text, or forward it to the bot and tap **Decrypt**. The client checks the recipient, the key,
  the signature and tag, and then that this copy was not opened before.
- The bot never encrypts or decrypts: it has no keys. Typing a message to the bot would send it to Telegram as plain
  text, which is why sealing happens inside the Mini App.

## 4. Attacks and results
Ten attack modules in `attacks/` run each attack against v1 and v2 (`python attacks/run_all_attacks.py`).
Latest run (also in [RESULTS.md](RESULTS.md)): **10/10 PASS**.

| Attack | v1 result | v2 result |
| :--- | :--- | :--- |
| MITM swaps keys | succeeds silently | key change detected |
| Replay captured message | accepted twice | rejected |
| Tamper with ciphertext | altered text shown | auth tag fails |
| Dump server database | plaintext readable | only ciphertext |
| Open expired message | still readable | key gone, undecryptable |
| Unauthorized access | all succeed | blocked (401/403/404/429) |
| Forged Telegram login | any name accepted | forged login rejected |
| Telegram reads the chat | Telegram reads it | only ciphertext, tamper caught |
| Reuse old/stolen session | no session needed | old/stolen token refused |
| Script injection (XSS) | script runs | shown as text |

How we know the tests are real:
- Each test must see v1 fail *and* v2 hold; a test that only checks v2 could pass for the wrong reason.
- We weakened the code on purpose and checked that the matching test turns red: removing the `initData` age check or the
  hash check, and adding an `innerHTML` line to the v2 code.
- The Telegram tests sign with a bot token made up inside the test, never the real one.
- Browser checks (Playwright) covered both clients: sign-up, chatting both ways, verification, reload keeping history,
  sensitive reveal and burn, key change blocking sending, the Mini App PIN flow, sealing and opening, phone widths.
- CipherBridge was also tried on a real phone: sealed in the Mini App, sent through WhatsApp, opened in the web app.

## 5. Limitations
Full list: [THREAT_MODEL.md, section 5](THREAT_MODEL.md#5-known-limits-honest-boundary).
1. **No forward secrecy:** message keys come from one long-term shared secret. Saved ciphertext plus a later-stolen
   private key reveals those messages.
2. **Trust in served code:** the web app and Mini App are JavaScript from our server; a compromised server could change it.
3. **Recipients can keep a copy:** expiry and view-once are enforced by the recipient's app; screenshots always work.
4. **Metadata:** the server and Telegram see who talks to whom, when, and message sizes.
5. **Demo setup:** plain http on the laptop, a Cloudflare quick tunnel for the phone, rate limits in memory.
6. **XSS check** is a code scan plus server checks, not an attack run in a real browser.
7. **One device per account:** keys live in one browser; another browser means new keys and a key-change warning.

## 6. Future work
1. **Double Ratchet** (as in Signal) for forward secrecy and recovery after a key leak.
2. **Smoother Telegram flow:** a one-tap **Open** button under every sealed message, and sealing straight back into the
   chat it was started from.
3. **Seal in any app:** an Android keyboard or a browser extension (WhatsApp Web, Telegram Web) that encrypts before the
   app sees the text.
4. **Public deployment:** an always-on host with HTTPS end to end, a database with backups, the bot in webhook mode,
   v1 and lab endpoints switched off, and a Content-Security-Policy header.
5. **Multi-device:** move keys to a second device safely (for example with a QR code).
6. **Post-quantum key agreement** (ML-KEM + X25519) and **sealed sender** to hide who sent a message from the server.
