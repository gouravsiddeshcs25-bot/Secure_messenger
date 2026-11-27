# Threat Model and Security Architecture: Secure Messenger

Every claim below names the attack test that checks it (`attacks/test_*.py`, run all of them with
`python attacks/run_all_attacks.py`; latest results in [RESULTS.md](RESULTS.md)).

## 1. Problem statement
Most messengers protect messages on the wire, but the server, a stolen database, a hostile recipient or the chat
platform itself (for example a normal Telegram chat) can still read or keep them. This project shows the difference
with two clients on one server:

- **v1, the insecure target:** plaintext, no login, trusts every field in the request. It stays broken on purpose so
  each attack can be shown working.
- **v2, the hardened client:** end-to-end encryption in the browser, password login with sessions, keys that stay on
  the device, a key-change warning, and sensitive messages that expire. The same client runs inside Telegram as the
  CipherBridge Mini App.

What the server stores for v2: usernames, Argon2id password hashes, SHA-256 hashes of session tokens, public keys, and
message envelopes (ciphertext plus a readable header: sender, recipient, counter, time, sensitive flags). Never
plaintext, never a private key.

## 2. Assets
- Message content (normal and sensitive).
- Each user's private keys (Ed25519 identity, X25519 exchange).
- Accounts: passwords and session tokens.
- The link between a Telegram account and its CipherBridge account.

## 3. Adversaries and defenses

| # | Adversary | What they can do | v2 defense | Checked by |
| :- | :--- | :--- | :--- | :--- |
| 1 | **Network or server man-in-the-middle** | Swap a user's public keys for their own. | Ed25519-signed key bundles; trust on first use (the client remembers the first identity key per contact); a changed key raises a red warning and blocks sending until the user reviews it; safety numbers to compare out of band. | `test_mitm_key_swap.py` |
| 2 | **Replay** | Re-send a captured message. | Signed, increasing counter per contact; anything at or below the last seen counter is dropped. For 🔒SM2 texts, the client remembers opened counters. | `test_replay_attack.py`, `test_telegram_view.py` |
| 3 | **Tampering** (network, server, Telegram) | Change bytes in a message or its header. | ChaCha20-Poly1305 tag over the ciphertext with the header as associated data, plus an Ed25519 signature over the header and ciphertext (the nonce is covered by the tag, since a changed nonce makes decryption fail). | `test_tamper_ciphertext.py`, `test_telegram_view.py` |
| 4 | **Database breach** | Copy the whole SQLite file. | Only ciphertext, Argon2id password hashes and SHA-256 token hashes are stored. The lab dump endpoint is off unless `LAB_MODE=1`. | `test_database_dump.py`, `test_session_theft.py` |
| 5 | **Someone without an account (IDOR)** | Read, send as, or delete for another user; guess passwords. | Every v2 call needs a session; the user comes from the token, never the request body; ownership checks (403/404); 5 login tries per minute per IP and username, then 429; same error for unknown users and wrong passwords. | `test_unauthorized_access.py` |
| 6 | **Stolen or old session token** | Reuse a token after logout or expiry, or use what's in a stolen DB. | Logout deletes the session; sessions expire after 24 hours and are checked on every request; the DB holds only SHA-256 hashes of tokens. | `test_session_theft.py` |
| 7 | **Script injection (XSS)** | Put HTML/JS in a name or message so it runs in the victim's page, where it could read keys. | v2 usernames only allow `a-z 0-9 _ -`; v2 and Mini App pages put text on the page only with `textContent` (no `innerHTML` anywhere). | `test_xss.py` (code scan + live server) |
| 8 | **Expired or one-time message** | Read a sensitive message after its time is up. | The server deletes expired envelopes; the client wipes the per-message key (`sodium.memzero`) after display and never saves sensitive text to history. | `test_expired_message.py` |
| 9 | **Telegram (or anyone inside Telegram)** | Read and change every normal chat and bot chat. | CipherBridge seals the message on the phone before it reaches Telegram (`🔒SM2` text): Telegram only stores ciphertext; tag and signature catch changes; a copy opened before is refused. | `test_telegram_view.py` |
| 10 | **Forged Telegram login** | Send made-up, copied or edited `initData` to sign in as another Telegram user. | The server checks Telegram's HMAC-SHA256 over all fields (key derived from the bot token), compares in constant time, refuses data older than 1 hour; `tg_` names can't be registered or used with a password. | `test_telegram_auth.py` |
| 11 | **Stolen or unlocked device** | Open the browser storage. | Private keys, contacts and history are sealed with XChaCha20-Poly1305 under a key from Argon2id of the password (Mini App: of the PIN). Sensitive messages can also require the password again before opening. | Manual check (see `docs/PROTOCOL.md`) |

## 4. Cryptography used (all from libsodium, never hand-made)
- **Identity and signatures:** Ed25519 (`crypto_sign`).
- **Key agreement:** X25519 (`crypto_kx_keypair`, `crypto_scalarmult`). These are long-term keys, not fresh keys per session.
- **Per-message keys:** `crypto_kdf_derive_from_key` (BLAKE2b) from the shared secret and the message counter.
- **Message encryption:** ChaCha20-Poly1305 IETF, random 12-byte nonce, header as associated data.
- **On-device storage:** Argon2id (`crypto_pwhash`) + XChaCha20-Poly1305.
- **Server side:** Argon2id password hashes (PyNaCl), session tokens from `secrets.token_urlsafe(32)` stored as SHA-256,
  Telegram `initData` checked with HMAC-SHA256 and `hmac.compare_digest`.

## 5. Known limits (honest boundary)
1. **Not forward secrecy.** Message keys come from one long-term shared secret per contact. Someone who saved the
   ciphertext *and* later steals a private key can read those messages. A Double Ratchet would fix this (future work).
   The expiry defense relies on the server really deleting the envelope.
2. **Trusting the served code.** The web app and the Mini App are JavaScript sent by our server. A compromised
   server could send code that leaks keys. The Mini App also loads Telegram's `telegram-web-app.js`.
3. **Recipients can always keep a copy.** Expiry and view-once are enforced by the recipient's app; a modified client,
   a debugger or a photo of the screen gets around them.
4. **Metadata is visible.** The server (and Telegram, for 🔒SM2 texts) sees who talks to whom, when, and roughly how long
   the messages are.
5. **Transport.** On a laptop the server runs on plain `http://localhost`. Through the cloudflared tunnel the phone talks
   HTTPS to Cloudflare, which forwards to the laptop. Cloudflare could see the (already encrypted) traffic and the
   session tokens. A public deployment needs HTTPS end to end.
6. **Rate limits live in memory.** They reset when the server restarts, and behind the tunnel all users share one IP
   (the per-username login limit still protects each account).
7. **Copied initData** works for up to 1 hour; it is only handed to the Mini App, so copying it needs the user's device.
8. **XSS check is a code scan**, not a run in a real browser. It proves there is no HTML sink in our code today; a
   Content-Security-Policy header would be a second line of defense (future work).
9. **Keys live in one browser.** Signing in on another browser creates new keys, and contacts see "key changed".
