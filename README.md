# 🛡️ Secure Messenger: Cybersecurity Skill Lab

A cybersecurity skill lab and proof-of-concept secure messenger demonstrating end-to-end encryption (E2EE), zero-knowledge server storage, ephemeral sensitive messaging, and client-side Data Loss Prevention (DLP). 

The system compares a **deliberately insecure baseline (Client v1)** against a **hardened cryptographic client (Client v2)** and provides automated Python attack scripts proving how each holds up under active adversarial attacks.

---

## 📑 Table of Contents
1. [Problem Statement](#-problem-statement)
2. [Threat Model & Security Design](#-threat-model--security-design)
3. [Cryptographic Architecture](#-cryptographic-architecture)
4. [Tech Stack](#-fixed-tech-stack)
5. [Directory Layout](#-project-structure)
6. [Quickstart & Setup](#-quickstart--setup)
7. [Running the Web Clients](#-running-the-web-clients)
8. [CipherBridge: Telegram Setup](#-cipherbridge-telegram-setup-windows)
9. [Data Loss Prevention (DLP) Subsystem](#-data-loss-prevention-dlp-subsystem)
10. [Automated Attack Lab & Results](#-automated-attack-lab--results)
11. [Honest Security Limitations](#-honest-security-limitations)
12. [Future Work](#-future-work)

---

## 🎯 Problem Statement
Most modern messaging applications protect data in transit (via TLS) and end-to-end between active endpoints. However, they leave sensitive data vulnerable post-delivery:
- Messages persist indefinitely in plaintext on servers or client databases.
- Breached server operators can dump message histories.
- Recipients can retain, screenshot, or leak confidential credentials.
- Lost or stolen unlocked devices expose long-term private keys and histories.

**Secure Messenger v2** enforces a zero-knowledge architecture where the server cannot decrypt messages, every message gets its own key derived from a shared secret and a counter, and sensitive messages self-destruct upon reading or expiration.

---

## 🥋 Threat Model & Security Design
The full table (11 adversaries, each linked to the test that checks it) is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

| Adversary | What they try | Defense in v2 |
| :--- | :--- | :--- |
| **Network or server in the middle** | Swap public keys, replay or change messages | Ed25519-signed keys, trust on first use with a blocking key-change warning, safety numbers; signed counters; ChaCha20-Poly1305 tag + Ed25519 signature |
| **Breached server / stolen database** | Read the database file | Only ciphertext, Argon2id password hashes and SHA-256 token hashes are stored |
| **Someone without the right account** | Read, send as, or delete for another user; guess passwords; reuse old tokens | Session on every call, user taken from the token, ownership checks, login rate limit (429), logout and 24h expiry |
| **Script injection (XSS)** | HTML/JS in a name or message | Strict username rule; all text drawn with `textContent` |
| **Telegram** | Read or change chats; forge a Telegram login | 🔒SM2 sealed text (only ciphertext reaches Telegram); `initData` HMAC check with 1-hour limit |
| **Stolen device** | Open browser storage | Keys and history sealed with Argon2id + XChaCha20-Poly1305 under the password (Mini App: PIN) |

---

## 🔐 Cryptographic Architecture
Detailed cryptographic formulas and packet diagrams are in [docs/PROTOCOL.md](docs/PROTOCOL.md).

All cryptographic primitives are provided client-side by **libsodium** (`libsodium-wrappers-sumo` bundled locally in `frontend/shared/vendor/libsodium.js` without any external CDN dependencies):
- **Identity & Signatures**: `Ed25519` (`crypto_sign`)
- **Key Exchange**: `X25519` Diffie-Hellman (`crypto_scalarmult`)
- **Per-Message Keys** (not forward secrecy: all keys come from one shared secret): `BLAKE2b`-based KDF (`crypto_kdf_derive_from_key`)
- **Authenticated Encryption with Associated Data**: `ChaCha20-Poly1305 (IETF)` (`crypto_aead_chacha20poly1305_ietf`)
- **Out-of-Band Fingerprint**: 24-digit formatted Safety Number derived via `crypto_generichash` over lexicographically sorted public keys
- **Local Passphrase Protection**: `Argon2id` (`crypto_pwhash`) memory-hard key derivation

---

## 🛠️ Fixed Tech Stack
- **Backend**: Python 3.14 + FastAPI + SQLite (standard `sqlite3` module)
- **Clients**: Plain HTML5 + Vanilla ES6 JavaScript + CSS3 (no external frontend frameworks)
- **Cryptography**: `libsodium.js` (bundled locally, strictly zero-knowledge server)
- **Attack Automation**: Python 3 (`requests`, `pynacl`, `cryptography`)
- **Transport**: REST API with real-time HTTP polling

---

## 📂 Project Structure
```text
secure_messenger/
├── backend/
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py             # FastAPI app; serves / (landing), /v1, /v2, /tg, /shared
│   │   ├── routes.py           # v2 API (/api/...), Telegram (/api/tg/...), insecure v1 API (/api/v1/...)
│   │   ├── auth.py             # Argon2id passwords, sessions, require_user, rate limits
│   │   ├── telegram_auth.py    # Telegram Mini App initData check (HMAC-SHA256)
│   │   └── database.py         # SQLite tables and queries (? parameters only)
│   ├── bot/bot.py              # CipherBridge Telegram bot
│   └── data/                   # git-ignored; holds messenger.db
├── frontend/
│   ├── shared/                 # /shared/: crypto.js (libsodium wrapper), dlp.js, ui.css, vendor/libsodium.js
│   ├── landing/                # / : home page
│   ├── legacy-insecure/        # /v1/: deliberately insecure client (the attack target)
│   ├── web/                    # /v2/: hardened client; js/ = app, chat, vault, api, dom, sm2
│   └── telegram-miniapp/       # /tg/: the v2 client signed in through Telegram (index.html is generated)
├── attacks/                    # 10 attack modules + run_all_attacks.py (see the table below)
├── docs/                       # THREAT_MODEL, PROTOCOL, RESULTS, REPORT, DEMO, VIVA
├── contracts/                  # API.md: the frontend/backend contract
├── scripts/                    # run_demo.py, demo_seed.py, build_miniapp.py, check.ps1 / check.sh
├── secrets/                    # git-ignored except .env.example and README.md
├── plan/ · prompts/ · .claude/ # project plan, step prompts, Claude Code setup
└── README.md · START-HERE.md · CLAUDE.md
```

---

## 🚀 Quickstart & Setup

### 1. Prerequisites
- Python 3.10+ (tested with 3.13)
- Node.js 18+ (the attack suite uses it to run the same crypto code as the browser)

### 2. Install and start (Windows PowerShell)
```powershell
cd Secure_Messenger
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
python scripts\run_demo.py --no-telegram      # server only; or: python -m uvicorn backend.app.main:app --port 8000
```

### 2. Install and start (bash: macOS, Linux, Git Bash)
```bash
cd Secure_Messenger
python -m venv .venv
source .venv/bin/activate            # Git Bash on Windows: source .venv/Scripts/activate
python -m pip install -r backend/requirements.txt
python scripts/run_demo.py --no-telegram
```

### 3. Run the attack suite (second terminal)
```bash
python attacks/run_all_attacks.py    # expect 10/10 PASS
```

---

## 🖥️ Running the Web Clients

Open your browser to:
- **Lab Switchboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Client v1 (Insecure Target)**: [http://127.0.0.1:8000/v1/](http://127.0.0.1:8000/v1/)
- **Client v2 (Hardened E2EE)**: [http://127.0.0.1:8000/v2/](http://127.0.0.1:8000/v2/)
- **CipherBridge Mini App** (open it from Telegram): [http://127.0.0.1:8000/tg/](http://127.0.0.1:8000/tg/)

### Walkthrough: End-to-End Encrypted Exchange in Client v2
1. Open [http://127.0.0.1:8000/v2/](http://127.0.0.1:8000/v2/) in two different browsers (or a normal and a private window).
   One account per browser: keys live in the browser that created them.
2. **Create account** as `alice` in one and `bob` in the other. Keys are made in the browser and locked with the password.
3. As alice, search `bob` and open the chat. Click **Not verified**: both sides show the same safety number. Compare and
   press **Numbers match** on both.
4. Send a message. Click the lock line under it (**Sent encrypted**) to see the counter, cipher and the exact JSON the server got.
5. Turn on **Sensitive**, pick 30 s, **View once**, and optionally **Ask for password to open**. Bob sees a locked card,
   reveals it, and it burns when the timer ends.
6. Typing something like `4111 1111 1111 1111` switches Sensitive on by itself (DLP).

---

## 📨 CipherBridge: Telegram Setup (Windows)

CipherBridge is the v2 messenger inside Telegram. Write a message, tap **Seal for Telegram**, and paste the
`🔒SM2:...` text into any Telegram chat. Telegram only stores the scrambled text; the receiver opens it with
**Open a 🔒SM2 message** (in the Mini App or at `/v2/`). The bot never sees readable text.

1. **Create the bot.** In Telegram, open @BotFather, send `/newbot`, pick a name and a username ending in `bot`.
   Copy the token it gives you. Also send `/setinline`, tap your bot (or type its name with `@`), and type `Seal a message`.
2. **Install cloudflared** (gives the laptop a public https address; Telegram only opens https pages):
   `winget install --id Cloudflare.cloudflared`, then open a new terminal.
3. **Put the token in `secrets\.env`** (`copy secrets\.env.example secrets\.env`, then `notepad secrets\.env`):
   `TELEGRAM_BOT_TOKEN=<token from BotFather>`. Never commit or share this file.
4. **Start everything with one command:** `python scripts\run_demo.py`. It starts the server, the tunnel
   (`--protocol http2`, because some networks block QUIC) and the bot, and passes the new tunnel address to the bot,
   so you never copy it by hand. Ctrl+C stops all three.
5. In Telegram, open your bot and press **Start**, then **Open CipherBridge**. Choose a PIN; your keys are made on the phone.
6. To receive: forward a `🔒SM2:` message to the bot and tap **Decrypt**, or paste it into **Open a 🔒SM2 message**
   (Mini App or `/v2/`).

Manual way (three terminals): server, `cloudflared tunnel --protocol http2 --url http://localhost:8000`, then set
`MINIAPP_URL=https://<tunnel>/tg/` in `secrets\.env` and run `python backend\bot\bot.py`. The quick-tunnel address
changes on every cloudflared restart. Telegram (and our server) still see who talks to whom and when; only the content is hidden.

---

## 🔍 Data Loss Prevention (DLP) Subsystem

Client v2 includes a pre-transmission Data Loss Prevention (DLP) engine in [frontend/shared/dlp.js](frontend/shared/dlp.js):
- **Aadhaar-like 12-digit IDs**: Matches `XXXX XXXX XXXX` or contiguous digits starting with `[2-9]`.
- **Credit Card Numbers**: Scans 13–19 digit card numbers and validates them with the **Luhn algorithm (Mod 10)**. Fake numbers or order IDs failing Luhn are ignored.
- **API Keys & Credentials**: Detects AWS Access Keys (`AKIA...`), GitHub Tokens (`ghp_...`), OpenAI keys (`sk-...`), Slack tokens (`xox...`), private key headers, and password assignments.

**Behavior**: When sensitive content is typed:
1. An amber DLP banner identifies the exact pattern.
2. **Sensitive Mode is locked ON** so the message is guaranteed ephemeral delivery with server TTL and one-time viewing.

---

## 🧪 Automated Attack Lab & Results

The attack lab executes the identical attack vectors against both **Client v1** and **Client v2**.

### Run the Entire Attack Suite
```bash
python attacks/run_all_attacks.py
```

### Verification Matrix Output
```text
----------------------------------------------------------------------------------------
Attack                     | v1 Expected        | v1 Actual          | v2 Expected                  | v2 Actual                    | Status
----------------------------------------------------------------------------------------
MITM swaps keys            | succeeds silently  | succeeds silently  | key change detected          | key change detected          | ✅ PASS
Replay captured message    | accepted twice     | accepted twice     | rejected                     | rejected                     | ✅ PASS
Tamper with ciphertext     | altered text shown | altered text shown | auth tag fails               | auth tag fails               | ✅ PASS
Dump server database       | plaintext readable | plaintext readable | only ciphertext              | only ciphertext              | ✅ PASS
Open expired message       | still readable     | still readable     | key gone, undecryptable      | key gone, undecryptable      | ✅ PASS
Unauthorized access        | all succeed        | all succeed        | blocked (401/403/404/429)    | blocked (401/403/404/429)    | ✅ PASS
Forged Telegram login      | any name accepted  | any name accepted  | forged login rejected        | forged login rejected        | ✅ PASS
Telegram reads the chat    | Telegram reads it  | Telegram reads it  | only ciphertext, tamper caught | only ciphertext, tamper caught | ✅ PASS
Reuse old/stolen session   | no session needed  | no session needed  | old/stolen token refused     | old/stolen token refused     | ✅ PASS
Script injection (XSS)     | script runs        | script runs        | shown as text                | shown as text                | ✅ PASS
----------------------------------------------------------------------------------------
```
Detailed technical explanations are preserved in [docs/RESULTS.md](docs/RESULTS.md).

### What each attack proves
| # | Attack (file) | v1 shows | v2 proves |
| :- | :--- | :--- | :--- |
| 1 | MITM key swap (`test_mitm_key_swap.py`) | a swapped key goes unnoticed | a changed key is caught and sending is blocked until reviewed |
| 2 | Replay (`test_replay_attack.py`) | the same message is accepted twice | counters stop re-sent messages |
| 3 | Tamper (`test_tamper_ciphertext.py`) | changed text is shown | one flipped bit fails the Poly1305 tag |
| 4 | Database dump (`test_database_dump.py`) | messages readable in the DB file | the DB holds only ciphertext |
| 5 | Expired message (`test_expired_message.py`) | old messages stay readable | expired envelopes are gone and the key is wiped |
| 6 | Unauthorized access (`test_unauthorized_access.py`) | anyone reads, spoofs, deletes | 401/403/404, and 429 after 5 wrong passwords |
| 7 | Forged Telegram login (`test_telegram_auth.py`) | any name is accepted | only Telegram-signed, fresh `initData` logs in |
| 8 | Telegram reads the chat (`test_telegram_view.py`) | Telegram can read plain text | Telegram stores only ciphertext; changes and re-opens are caught |
| 9 | Old/stolen session (`test_session_theft.py`) | no session needed at all | logged-out, expired, made-up and DB-stolen tokens all fail |
| 10 | Script injection (`test_xss.py`) | an HTML name runs script (innerHTML) | HTML names refused; all text drawn as text (code scan) |

---

## ⚠️ Honest Security Limitations
Full list in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#5-known-limits-honest-boundary). The main ones:
1. **No forward secrecy.** Per-message keys come from one long-term shared secret; a stolen private key plus saved ciphertext reveals old messages.
2. **The served code is trusted.** A compromised server could send JavaScript that leaks keys (true for any web app).
3. **Recipients can keep a copy.** Expiry and view-once run in the recipient's app; a modified app or a photo of the screen gets around them.
4. **Metadata is visible** to our server and, for 🔒SM2 texts, to Telegram: who talks to whom, when, and message size.
5. **Demo transport.** Locally it is plain http; through the tunnel Cloudflare is in the path. A public deployment needs HTTPS end to end.

---

## 🔮 Future Work

1. **Per-Recipient Invisible Watermarking**:
   - Injecting recipient-specific invisible Unicode characters (such as Zero-Width Spaces `\u200B`, Zero-Width Non-Joiners `\u200C`, and Word Joiners `\u2060`) into sensitive plaintext before rendering.
   - If a recipient leaks the text via copy-paste or screenshots OCR, the extracted zero-width binary signature identifies the exact leaking recipient handle.
2. **Double-Ratchet Key Agreement**:
   - Upgrading from per-message keys (one shared secret + counter) to the full Signal Double-Ratchet protocol (combining asymmetric DH ratchet with symmetric KDF chains) for post-compromise security.
3. **Post-Quantum Cryptography (PQ-KEM)**:
   - Integrating hybrid post-quantum key encapsulation (e.g. ML-KEM / Kyber768 + X25519) to guard against "Store Now, Decrypt Later" adversaries with future quantum hardware.
4. **Encrypted Metadata**:
   - Implementing sealed sender envelopes so the relaying server cannot see sender identity metadata.
