# Project Context: Secure Messenger and CipherBridge

> **How to use this file:** paste everything below into a new Claude chat (or attach this file) and add your request,
> for example: *"Using this context, make a well-designed PDF guide for my friends who will present this project. Explain
> everything simply, include diagrams, and add likely teacher questions about the limitations with good answers."*
> Every fact here is checked against the real code and test results. Ask Claude not to add features or numbers that
> are not in this file.

---

## 1. One-paragraph summary
A cybersecurity lab project. Two messengers share one server: **v1** is deliberately insecure (plaintext, no login, trusts
everything) and **v2** is a hardened end-to-end encrypted messenger. **CipherBridge** is the same v2 client running inside
Telegram as a Mini App with a bot, which can seal a message into a `🔒SM2:` text that is safe to paste into any chat
(Telegram, WhatsApp). Ten automated attack programs attack both versions; a test passes only if v1 breaks **and** v2
holds. Latest result: **10/10 PASS**.

## 2. Tech stack
| Part | Technology | Role |
| --- | --- | --- |
| Server | Python 3.13, FastAPI, uvicorn, Pydantic | API under `/api/...`; validates every request |
| Database | SQLite (one file, `backend/data/messenger.db`) | tables `users`, `sessions`, `public_keys`, `messages`; SQL always uses `?` placeholders |
| Password hashing | PyNaCl (Argon2id) | server-side password hashes |
| Clients | Plain JavaScript (ES modules), HTML, CSS | no framework; own design system `frontend/shared/ui.css` with light/dark mode and phone layout |
| Cryptography | libsodium.js (bundled locally) | all encryption, signatures, key agreement, hashing in the browser; "never invent your own crypto" |
| Attack tests | Python + Node.js | Node runs the same `crypto.js` the browser uses |
| Telegram | python-telegram-bot 22.8, Telegram Mini App | bot `backend/bot/bot.py`; Mini App at `/tg/` |
| Tunnel | cloudflared (`--protocol http2`) | temporary public https address so a phone can reach the laptop |
| Testing | Playwright (browser robot) | end-to-end checks of sign-up, chat, phone widths |
| Version control | Git, branch `upgrades` | every step committed |

Web addresses: `/` home page · `/v1/` insecure client · `/v2/` secure client · `/tg/` CipherBridge Mini App.

## 3. Cryptography (all libsodium)
- **Identity / signatures:** Ed25519. **Key agreement:** X25519 (long-term keys, not per session).
- **Per-message keys:** `crypto_kdf_derive_from_key` (BLAKE2b) from the X25519 shared secret and the message counter.
  This is **not forward secrecy**: all keys derive from one long-term shared secret.
- **Message encryption:** ChaCha20-Poly1305 IETF, random 12-byte nonce, the JSON header is AEAD "associated data".
- **Signature:** Ed25519 over header + ciphertext.
- **Header fields:** version, sender, recipient, counter, timestamp, is_sensitive, ttl_seconds, one_time_view,
  require_passphrase, optional channel ("telegram").
- **Safety number:** BLAKE2b (`crypto_generichash`) over both identity keys, shown as 6 groups of 4 digits.
- **On-device vault:** private keys, first-seen identity key per contact, counters and normal history, sealed with
  XChaCha20-Poly1305 under a key from Argon2id of the password (Mini App: of a PIN, at least 6 characters).
- **Key wiping:** `sodium.memzero` on message keys after use.

## 4. Receiving a normal v2 message (order of checks)
1. Is the sender's identity key the one remembered (trust on first use)? If changed: hold the message, red warning, block sending.
2. Counter higher than the last seen? Otherwise: replay, drop.
3. Derive the message key from shared secret + counter.
4. Verify Ed25519 signature, then the Poly1305 tag while decrypting. Any failure: tampered/forged, drop.
5. Show text, wipe the message key.

## 5. Accounts and sessions (server)
- Argon2id password hashes; a dummy hash keeps timing equal; "wrong password" and "unknown user" give the same answer.
- Login returns a random 32-byte token; DB stores only its **SHA-256 hash**; expires after **24 hours**; logout deletes it.
- The user identity always comes from the token, never from the request body; ownership checks on every route.
- Rate limit: **5 login attempts per minute** per IP+username → HTTP 429 (in memory).
- Usernames for v2: only `a-z 0-9 _ -`. Names starting `tg_` are reserved for Telegram accounts.
- `/api/dump/messages` (lab "database breach" view) returns 404 unless the server runs with `LAB_MODE=1`.

## 6. v2 features (what you can show)
- Create account / sign in with a live checklist (generating keys in this browser → encrypting them with your password → publishing public keys).
- Chat list, user search (exact usernames), light/dark theme, phone layout.
- Trust chip: amber "Not verified" → green "Verified" only after comparing safety numbers; red "Key changed" blocks sending.
- Lock line under each message ("Sent encrypted") opens "How this message was protected": counter, cipher, the exact JSON the server received.
- Sensitive mode: disappears after 30 s / 1 min / 5 min, view once, optional password to open; countdown ring; burns; never saved.
- DLP: card numbers (Luhn check), Aadhaar-like 12-digit numbers, API keys/tokens/private-key headers → switches Sensitive on.
- One active tab per account (a second tab signs the first out, to keep the vault consistent).

## 7. CipherBridge (Telegram)
- **Bot:** opens the Mini App (menu button "CipherBridge"), replies with a "Decrypt" button for forwarded 🔒SM2 text, warns
  if readable text is sent to it. The bot has **no keys** and never encrypts/decrypts.
- **Mini App `/tg/`:** the v2 client signed in through Telegram; keys made on the phone, locked with a PIN.
- **Login:** Telegram `initData` checked on the server: HMAC-SHA256 with secret = HMAC-SHA256(key "WebAppData", bot token),
  over all fields except `hash`, sorted, joined by newlines; constant-time compare; max 1 hour old; repeated fields rejected.
  Account name `tg_<telegram id>`.
- **🔒SM2 format:** `🔒SM2:` + base64url (no padding) of JSON `{header, nonce, ciphertext, signature}` with `channel: "telegram"`
  in the signed header. Message limit 1500 characters (sealed text ≤ 4000, under Telegram's 4096).
- **Opening checks (in order):** decode → not your own → addressed to you → sender's key (trust on first use) → signature +
  tag → replay (each counter opened once). Tamper is checked before replay so the error is accurate.
- Sensitive messages cannot be sealed for Telegram (a pasted text can't disappear).
- `/api/tg/share` lets the Mini App use Telegram's native share sheet (only 🔒SM2 text, only Telegram accounts).
- **Real-phone test done:** sealed in the Mini App → sent via WhatsApp → opened in the web app as the recipient; replay and
  tamper refused; safety numbers matched between phone and laptop.
- **Why the bot can't encrypt for you:** text typed to a bot reaches Telegram and the bot unencrypted, and the bot has no private keys.

## 8. The 10 attacks (all PASS)
| # | Attack (file in `attacks/`) | v1 result | v2 result | Why v2 holds |
| --- | --- | --- | --- | --- |
| 1 | MITM key swap (`test_mitm_key_swap.py`) | succeeds silently | key change detected | TOFU + red warning blocks sending; server swaps keys directly in the DB |
| 2 | Replay (`test_replay_attack.py`) | accepted twice | rejected | signed counter must increase |
| 3 | Tamper (`test_tamper_ciphertext.py`) | altered text shown | auth tag fails | Poly1305 tag + signature |
| 4 | Database dump (`test_database_dump.py`) | plaintext readable | only ciphertext | server never has text or keys |
| 5 | Expired message (`test_expired_message.py`) | still readable | key gone, undecryptable | server deletes; key wiped; never saved |
| 6 | Unauthorized access (`test_unauthorized_access.py`) | all succeed | blocked (401/403/404/429) | token required, user from token, ownership, rate limit, logout |
| 7 | Forged Telegram login (`test_telegram_auth.py`) | any name accepted | forged login rejected | HMAC check, 1 hour, reserved tg_ names; uses a made-up token |
| 8 | Telegram reads the chat (`test_telegram_view.py`) | Telegram reads it | only ciphertext, tamper caught | 🔒SM2 sealing; replay/tamper refused |
| 9 | Reuse old/stolen session (`test_session_theft.py`) | no session needed | old/stolen token refused | logout, expiry, hash-only storage, dump page locked |
| 10 | Script injection / XSS (`test_xss.py`) | script runs | shown as text | strict usernames; no innerHTML anywhere in v2 (code scan, not a real-browser run) |

Honesty checks: v2 was deliberately weakened (Telegram age check removed, hash check removed, an `innerHTML` line added) and
the matching tests failed; a fresh clone of the project also scored 10/10.

## 9. Build history (steps)
1. Base project + first 5 attacks. 2. Folder structure. 3. Argon2id login, sessions, ownership, rate limits, dump locked.
4. Keys persisted on device, key-change warning, safety numbers, honest wording, full redesign. 5. Telegram bot + Mini App +
initData check (tested on a real phone). 6. Two new attacks (sessions, XSS) → 10. 7. Docs (threat model, protocol, report,
README). 8. Demo prep (launcher `scripts/run_demo.py`, `scripts/demo_seed.py`, `docs/DEMO.md`, `docs/VIVA.md`).
Planned: 9. Public deployment. 10. Email + forgot password with a recovery key.

## 10. Who can see what
| Thing | Server | DB thief | Telegram/WhatsApp | Cloudflare tunnel | Receiver |
| --- | --- | --- | --- | --- | --- |
| Message text | no | no | no | no | yes |
| Private keys | no | no | no | no | no |
| Password | at login, stores hash | hash only | no | only if logging in through the tunnel | no |
| Login token | receives, stores hash | hash only | no | yes (https ends at Cloudflare) | no |
| Who/when/size (metadata) | yes | yes | yes (for 🔒SM2) | yes | yes |

## 11. Limitations (answer pattern: Admit → Why → Fix)
1. **No forward secrecy** — one long-term shared secret → Double Ratchet (future).
2. **Served JavaScript is trusted** — a hacked server could ship bad code → signed apps, SRI, CSP.
3. **Receiver can screenshot / modify app** — enforced on their device → protects against server/theft/accidents only.
4. **Metadata visible** (server, Telegram) → sealed sender (future).
5. **TOFU can't catch a fake first key** → safety numbers compared in person.
6. **Demo transport:** http on localhost; tunnel https only to Cloudflare → https end-to-end in deployment.
7. **Forgot password** = account lost; even email reset can't recover keys → planned email reset + recovery key.
8. **New tunnel address → Mini App asks for a new PIN** (storage is per web address) → fixed address.
9. **6-character PIN** weaker than a password (Argon2id slows guesses) → longer PIN / secure hardware.
10. **One device per account** → QR key transfer (future).
11. **Rate limit in memory**, shared IP behind tunnel → database/Redis.
12. **XSS check is a code scan** → real-browser test + CSP.
13. **Copied initData valid up to 1 hour** (needs the user's device).
14. **Telegram flow is clumsy** → one-tap "Open" button under sealed messages; seal back into the same chat; later an Android keyboard or browser extension.
15. **DLP is pattern matching** (misses/false alarms possible).
16. **Sensitive message not opened before a reload is lost** (by design: never saved).
17. **Server can refuse to deliver** (availability not protected).
18. **Not audited; student project; v1 must be off in any public deployment.**
Words never to use: "unbreakable", "100% secure", "military-grade", "forward secrecy".

## 11b. Future plan (roadmap; nothing here is built yet)
**Now (right after the presentation)**
- Public deployment (step 9): always-on host (Render/Railway/Fly), https end to end, fixed address, real database with backups, bot in webhook mode, v1 and lab pages off. Removes: laptop + tunnel, new PIN after restart, http on localhost.
- Email + forgot password (step 10): verified email, single-use 30-minute reset links stored as hashes, same answer for unknown accounts, all sessions signed out after reset. Removes: forgotten password = lost account.
- Recovery key shown once at sign-up (like WhatsApp's 64-digit key) so a reset keeps keys and history.
- Hardening: Content-Security-Policy, Subresource Integrity, rate limits in a database/Redis, real-browser XSS tests.

**Next (make Telegram feel normal)**
- One-tap "Open" button under every sealed Telegram message (server keeps the sealed text under a short code, still only ciphertext).
- Seal into the same chat: `@bot` → Seal → message lands back in that chat (typed in the Mini App, never in Telegram's box).
- Multi-device key transfer (e.g. QR code). Stronger PIN storage (longer PIN, secure hardware).

**Later (research steps)**
- Double Ratchet (forward secrecy) · sealed sender (hide sender metadata) · Android keyboard / browser extension to seal in any app ·
  post-quantum hybrid ML-KEM + X25519 · invisible per-receiver watermarks to trace leaks (traces, doesn't prevent).

Order rationale: a reliable public version first, then convenience, then research-level cryptography.

## 12. Demo (about 6 minutes)
Setup: `python scripts\run_demo.py` (server + tunnel + bot) and `python scripts\demo_seed.py` (fake card/OTP in v1).
1. Idea (home page). 2. v1 falls: open `/api/v1/messages/bob_v1demo` → card number and OTP with no login.
3. v2 holds: send a message, open the lock line (server only had ciphertext), safety number, 30 s sensitive message burns,
DLP. 4. CipherBridge: seal on phone → WhatsApp shows gibberish → open on laptop → paste again = "Replay blocked" → change a
letter = refused. 5. Show 10/10. 6. Limits and next steps.
Troubleshooting: black screen in Telegram = old button, use the blue CipherBridge menu button; new PIN = new tunnel address.

## 13. Likely teacher questions (short answers)
- *E2EE meaning?* Encrypted on sender's device, decrypted only on receiver's; private keys never leave; DB dump finds no plaintext.
- *Encryption vs hashing vs signing?* Reversible with key / one-way fingerprint / proves who and unchanged.
- *Why ChaCha20-Poly1305?* Fast in software, hard to misuse, encrypt + integrity in one (AEAD), provided by libsodium.
- *Why Argon2id?* Slow and memory-hard on purpose; Argon2 won the Password Hashing Competition (2015).
- *Why hash tokens?* A stolen DB then holds nothing usable to log in.
- *Counter vs timestamp?* Clocks drift; a signed counter is exact.
- *Nonce?* Random 12 bytes per message; never reuse with the same key.
- *Telegram login?* HMAC-SHA256 with a key from the bot token, constant-time compare, ≤1 hour old; never trust initDataUnsafe.
- *SQL injection?* Always `?` placeholders.
- *Why keep v1?* To prove each defence matters (v1 breaks, v2 holds).
- *Why not Signal's library?* To learn and demonstrate each defence while using only proven primitives.
- *AI use?* Claude Code as assistant; every change verified by tests; logged in `plan/AI-LOG.md`.

## 14. Analogies that work for beginners
Postcard vs locked box (E2EE) · padlocks you hand out vs the key you keep (public/private) · paint mixing (X25519) ·
key factory (KDF) · seal sticker (Poly1305) · king's wax seal (Ed25519) · fingerprint (hash) · slow lock (Argon2id) ·
restaurant: HTML walls, CSS paint, JavaScript waiter, Python kitchen, SQLite storeroom, libsodium bank safe.
Memory aids: "Lock at home, carry locked, open at home" · "Cats Sleep While Puppies Snore" (Code, Seal, Wax, Paint, Slow) ·
"Check, Count, Crack" (receiver order) · "Admit, Why, Fix" (limitations) · "Content hidden, contacts visible" (metadata).
