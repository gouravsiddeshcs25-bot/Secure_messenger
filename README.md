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
8. [Data Loss Prevention (DLP) Subsystem](#-data-loss-prevention-dlp-subsystem)
9. [Automated Attack Lab & Results](#-automated-attack-lab--results)
10. [Honest Security Limitations](#-honest-security-limitations)
11. [Future Work & Enhancements](#-future-work)

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
Detailed specifications are documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

| Adversary | Adversary Capability | Defense in v2 |
| :--- | :--- | :--- |
| **1. Network Eavesdropper / MITM** | Intercepts or modifies packets in transit | End-to-end encryption with **ChaCha20-Poly1305 (AEAD)**; out-of-band **Safety Number / Fingerprint** comparison; Ed25519 identity signatures. |
| **2. Breached or Malicious Server** | Performs full database dumps or tampers with stored records | **Zero-Knowledge Design**: The server receives only Base64 ciphertext, nonces, and public keys. Tampering invalidates the Poly1305 auth tag. |
| **3. Hostile Recipient Leaking Data** | Attempts to retain or re-share confidential messages | **Sensitive Mode**: Enforces one-time view, auto-burn timers, server-side TTL purge, and local memory zeroization (`memzero`). |
| **4. Stolen / Unlocked Device** | Physical or forensic memory access on device | Private keys reside only in ephemeral memory (never `localStorage`); local passphrase re-authentication via **Argon2id** (`crypto_pwhash`). |

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
├── docs/
│   ├── THREAT_MODEL.md         # Adversaries, boundaries, and security choices
│   ├── PROTOCOL.md             # Cryptographic handshake, per-message key derivation, and wire specs
│   └── RESULTS.md              # Attack lab verification results matrix
├── backend/
│   ├── CLAUDE.md               # Backend-only rules
│   ├── requirements.txt        # Python dependencies
│   ├── app/
│   │   ├── main.py             # FastAPI application & static routing (/v1, /v2, /shared)
│   │   ├── database.py         # SQLite schemas and lifecycle operations
│   │   └── routes.py           # REST API endpoints
│   └── data/                   # git-ignored; holds messenger.db
├── frontend/
│   ├── CLAUDE.md               # Frontend-only rules
│   ├── shared/                 # Served at /shared/
│   │   ├── vendor/
│   │   │   └── libsodium.js    # Local libsodium bundle (no CDN dependency)
│   │   ├── crypto.js           # Client-side libsodium wrapper & primitives
│   │   └── dlp.js              # Client-side Data Loss Prevention engine
│   ├── legacy-insecure/        # Client v1: Deliberately Insecure (The Attack Target), served at /v1/
│   │   ├── index.html          # Plaintext chat UI
│   │   ├── app.js              # Vulnerable client logic (no E2EE, no replay check)
│   │   └── style.css
│   └── web/                    # Client v2: Hardened Zero-Knowledge Client, served at /v2/
│       ├── app.js              # Secure state machine & ephemeral messaging UI
│       ├── index.html
│       └── style.css
├── attacks/                    # Automated Attack Scripts
│   ├── client_sim.py           # Headless Python client framework
│   ├── crypto_helper.js        # Node bridge to local libsodium crypto module
│   ├── test_mitm_key_swap.py   # MITM public key substitution attack
│   ├── test_replay_attack.py   # Message retransmission attack
│   ├── test_tamper_ciphertext.py # Bit-flip & ciphertext corruption attack
│   ├── test_database_dump.py   # SQL database exfiltration attack
│   ├── test_expired_message.py # Expiration & memory scrub attack
│   ├── test_unauthorized_access.py # Broken access control (IDOR, brute force)
│   ├── test_telegram_auth.py   # Forged / expired / edited Telegram initData
│   ├── test_telegram_view.py   # What Telegram's servers can read
│   └── run_all_attacks.py      # Unified runner outputting PASS/FAIL table
├── contracts/                  # API.md + examples: the frontend/backend handshake
├── plan/                       # PLAN, TASKS, PROGRESS, DECISIONS, LESSONS, AI-LOG
├── prompts/                    # One ready prompt per step in plan/TASKS.md
├── scripts/                    # check.ps1 / check.sh
├── secrets/                    # git-ignored except .env.example and README.md
├── .claude/                    # Claude Code settings, agents, commands, skills, hooks
├── CLAUDE.md · AGENTS.md · START-HERE.md
└── README.md
```

---

## 🚀 Quickstart & Setup

### 1. Prerequisites
- Python 3.9+ (Python 3.10 to 3.14 supported)
- Node.js 18+ (used by the headless attack runner)

### 2. Install Dependencies
```bash
python -m pip install -r backend/requirements.txt
```

### 3. Start the Server
```bash
# run from the repo root
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🖥️ Running the Web Clients

Open your browser to:
- **Lab Switchboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Client v1 (Insecure Target)**: [http://127.0.0.1:8000/v1/](http://127.0.0.1:8000/v1/)
- **Client v2 (Hardened E2EE)**: [http://127.0.0.1:8000/v2/](http://127.0.0.1:8000/v2/)
- **CipherBridge Mini App** (open it from Telegram): [http://127.0.0.1:8000/tg/](http://127.0.0.1:8000/tg/)

### Walkthrough: End-to-End Encrypted Exchange in Client v2
1. Open two browser tabs to [http://127.0.0.1:8000/v2/](http://127.0.0.1:8000/v2/).
2. Log in as `alice` in Tab 1 and as `bob` in Tab 2.
3. In Alice's tab, enter `bob` and click **Connect**.
4. Observe the **Out-of-Band Safety Number (Fingerprint)**: both tabs will display the exact same 24-digit fingerprint.
5. In Alice's tab, toggle **Sensitive Mode** (select 60s TTL). Type `"Secret server password: Passw0rd!#123"`.
6. Click **Send (E2EE)**.
7. In Bob's tab, notice the locked card: `[🔒 Confidential Sensitive Message from alice]`.
8. Click **Decrypt & View**: The message decrypts in memory, the server immediately purges the record (`DELETE /api/messages/{id}`), and an auto-burn countdown begins.

---

## 📨 CipherBridge: Telegram Setup (Windows)

CipherBridge is the v2 messenger inside Telegram. Write a message, tap **Seal for Telegram**, and paste the
`🔒SM2:...` text into any Telegram chat. Telegram only stores the scrambled text; the receiver opens it with
**Open a 🔒SM2 message** (in the Mini App or at `/v2/`). The bot never sees readable text.

1. **Create the bot.** In Telegram, open @BotFather, send `/newbot`, pick a name and a username ending in `bot`.
   Copy the token it gives you. Also send `/setinline`, pick the bot, and type a placeholder like `Seal a message`.
2. **Start an HTTPS tunnel** (Telegram only opens https pages). Install cloudflared, then in a new terminal:
   `cloudflared tunnel --url http://localhost:8000`. Copy the `https://...trycloudflare.com` address it prints.
3. **Fill `secrets\.env`** (copy `secrets\.env.example` first):
   `TELEGRAM_BOT_TOKEN=<token from BotFather>` and `MINIAPP_URL=https://<your tunnel>/tg/`. Never commit or share this file.
4. **Restart the server**, then **run the bot** in another terminal: `python backend\bot\bot.py`.
   The bot sets its own menu button to open the Mini App.
5. In Telegram, open your bot and press **Start**, then **Open CipherBridge**. Choose a PIN; your keys are made on the phone.
6. To receive: forward a `🔒SM2:` message to the bot and tap **Decrypt**, or paste it into **Open a 🔒SM2 message**.

The tunnel address changes every time cloudflared restarts: update `MINIAPP_URL` and restart the bot.
Telegram (and our server) still see who talks to whom and when; only the content is hidden.

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
----------------------------------------------------------------------------------------
```
Detailed technical explanations are preserved in [docs/RESULTS.md](docs/RESULTS.md).

---

## ⚠️ Honest Security Limitations

In cybersecurity, stating boundaries honestly is critical:
1. **Client Code Delivery**: In a browser-based web application, the server serves the JavaScript code. A compromised server could attempt to serve tampered JavaScript. (Native desktop apps with binary code signing mitigate this).
2. **Adversarial Recipient with Modified Client**: Expiration and one-time viewing are enforced by the recipient's client runtime. A recipient who modifies their client code or attaches a debugger can extract decrypted buffers.
3. **Display Screen Capture**: No software encryption can stop a user from photographing their physical monitor or taking an OS-level screenshot while a message is displayed.

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
