# Secure Messenger + CipherBridge: instructions for Claude Code

You are helping a student team finish a **Cyber Security Skill Lab project** that is submitted and demoed **today**. The team is new to cyber security, so explain every change in simple words. The reviewers will ask the team to explain any part of the code, so the team must understand everything you write.

**The product in 3 sentences:** Secure Messenger is an end-to-end encrypted chat app where the server only ever stores public keys and ciphertext. It ships with a deliberately insecure v1 client and a hardened v2 client, plus an attack lab that runs the same attacks against both and prints a PASS/FAIL table. CipherBridge adds a Telegram Bot and Mini App so people can send end-to-end encrypted messages through normal Telegram chats, where Telegram only sees ciphertext.

**Why Telegram:** the first review asked for something usable with WhatsApp or Telegram. Telegram's normal chats are not end-to-end encrypted (only opt-in 1:1 "Secret Chats" are), so CipherBridge adds that layer on top using Telegram's official Bot API and Mini Apps.

## Start of every session
1. The SessionStart hook has already loaded `plan/PROGRESS.md`, `plan/LESSONS.md` and the git state. Read them first.
2. Check the next unticked step in `plan/TASKS.md`. Work on that step unless the user asks for something else.
3. Read only the files the task needs. Don't read the whole repo.
4. If the folder layout below doesn't match what's on disk, trust the disk, tell the user, and update this file.

## Environment
- **Windows + PowerShell.** Use `python`, not `python3`. Use backslashes in commands the user types (`attacks\run_all_attacks.py`).
- Virtual environment: `.venv` (activate with `.venv\Scripts\activate`).
- Python 3.10+, Node 18+ (the attack helper and the Claude Code hooks need Node).
- The user runs the server in a separate terminal. If a change needs a restart, say so clearly.

## Commands (from the repo root)
| What | Command |
|---|---|
| Install | `pip install -r backend\requirements.txt` |
| Run server | `python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000` |
| Web clients | http://127.0.0.1:8000/v1/ (insecure) and http://127.0.0.1:8000/v2/ (secure) |
| Mini App (local check) | http://127.0.0.1:8000/tg/ |
| Run the bot | `python backend\bot\bot.py` |
| HTTPS tunnel for Telegram | `cloudflared tunnel --url http://localhost:8000` (the user runs it) |
| **Attack suite** | `python attacks\run_all_attacks.py` |

**Done means:** the attack suite passes, the user has checked the feature by hand, `plan/` is updated, and the work is committed (`/checkpoint`).

## Folder layout (who owns what)
| Folder | Contents | Owner |
|---|---|---|
| `backend/app/` | FastAPI server: `main.py`, `routes.py`, `database.py`, `auth.py`, `telegram_auth.py` | Backend |
| `backend/bot/` | Telegram bot | Backend / Telegram |
| `backend/data/` | `messenger.db` at runtime (git-ignored) | – |
| `frontend/shared/` | `crypto.js`, `dlp.js`, `vendor/libsodium.js`, shared by web and Mini App | Frontend |
| `frontend/web/` | Secure v2 client, served at `/v2/` | Frontend |
| `frontend/legacy-insecure/` | Insecure v1 client, served at `/v1/` (the attack target) | Frontend |
| `frontend/telegram-miniapp/` | CipherBridge Mini App, served at `/tg/` | Frontend / Telegram |
| `contracts/API.md` | Every endpoint: method, auth, request, response, errors | Both |
| `attacks/` | Attack lab: `client_sim.py`, `crypto_helper.js`, `test_*.py`, `run_all_attacks.py` | Security |
| `docs/` | THREAT_MODEL, PROTOCOL, ARCHITECTURE, SECURITY, RESULTS, REPORT, API-NOTES | Docs |
| `plan/` | PLAN, TASKS, PROGRESS, DECISIONS, LESSONS, AI-LOG (the team's live memory) | Everyone |
| `prompts/` | Ready prompts for each step | Everyone |
| `secrets/` | `.env` (git-ignored), `.env.example`, `README.md` | Never read `.env` |
| `.claude/` | agents, commands, skills, hooks, settings.json | – |

## Rules that must never be broken
1. **v1 stays insecure.** `frontend/legacy-insecure/` and the `/api/v1/...` endpoints are the attack target. Never add encryption, auth or checks to them. They exist so the attack lab can show the difference.
2. **Proven crypto only.** libsodium in the browser (`frontend/shared/crypto.js`), PyNaCl on the server. Never invent a cipher, never use Base64 or XOR as "encryption", never reuse a nonce, never use `Math.random()` for anything security-related.
3. **One crypto module.** The web client and the Mini App both use `frontend/shared/crypto.js`. Don't copy crypto code into a second file.
4. **Private keys and plaintext never reach the server.** The server stores only usernames, password hashes, session-token hashes, public keys and ciphertext. No message content in logs, error messages or push text.
5. **Secrets live only in `secrets/.env`.** Never hard-code a token, never print one, never ask the user to paste one into chat, never read `secrets/.env`. Add new keys with empty values to `secrets/.env.example`.
6. **Every v2 endpoint is authenticated** with the shared dependency in `backend/app/auth.py`. The user can only touch their own keys, inbox and received messages. The sender always comes from the session, never from the request body.
7. **SQL uses `?` parameters only.** No f-strings or string concatenation in SQL, including the TTL calculation.
8. **Untrusted text goes into the page with `textContent`,** never `innerHTML`. That includes message text, usernames and anything from Telegram.
9. **Never trust Telegram `initData` on the client.** The server validates it (HMAC-SHA256 as in Telegram's docs, constant-time compare, max age 1 hour) before creating a session.
10. **Honest wording.** Never write "unbreakable", "military-grade", "100% secure" or "forward secrecy" (we derive per-message keys from a shared secret and a counter; a full Double Ratchet is future work). Say the real limit instead.
11. **Every security fix gets an attack test** that fails before the fix and passes after it.
12. **No fake results.** Numbers and PASS lines in docs come from actually running the attack suite.

## How to work
- **One step at a time.** Take the next unticked step in `plan/TASKS.md`. Ideas outside it go under "Ideas / later" in `plan/PROGRESS.md`.
- **Plan first** when a change touches more than 2 files: list the files, the steps and the tests, then wait for the user's OK.
- **Small diffs.** Edit, don't rewrite whole files, and don't refactor outside the task.
- **Check docs before using an API you haven't verified** (Telegram Bot API, Mini Apps, python-telegram-bot, PyNaCl, libsodium.js). Use the `verify-before-use` skill and note what you confirmed in `docs/API-NOTES.md`.
- **After every change:** run `python attacks\run_all_attacks.py`, show the table, and tell the user exactly what to test by hand.
- **Bugs:** find the cause first. After two failed fixes, stop and suggest a different approach. Every fixed bug gets one line in `plan/LESSONS.md`.
- **Explain as you go:** after each step, give a 3–5 line plain-language summary: what changed, why it's more secure, and how to show it in the demo.
- **Finish a step with `/checkpoint`:** run the suite, tick `plan/TASKS.md`, update `plan/PROGRESS.md` and `plan/AI-LOG.md`, then commit (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). Don't push unless asked.
- **Context:** the user will `/clear` between steps. Before a break, `/handoff`.
- **Git:** work on the `upgrades` branch. No force-push, no `reset --hard`, no history rewriting.

## The plan for today (details for each step)
Cut from the bottom if late. Never cut steps A, C, or the attack suite passing.

### A. Login and access control (most important)
- `/api/register` and `/api/login` with username and password. Hash passwords with Argon2id (`nacl.pwhash.argon2id`). Same error for wrong username and wrong password.
- A random session token (`secrets.token_urlsafe(32)`). Store only its SHA-256 hash with a 24-hour expiry. Add `/api/logout`.
- A shared `require_user` dependency in `backend/app/auth.py`, used on every v2 route. Ownership checks on keys, inbox and delete. Sender taken from the session.
- Rate limit login and register to 5 per minute per IP (in-memory, HTTP 429).
- `/api/dump/messages` works only when `LAB_MODE=1` is set in `secrets/.env`.
- v1 moves to its own unprotected `/api/v1/...` endpoints.
- Web client: password field, token kept in memory (not localStorage), sent as `Authorization: Bearer`.
- Fix the f-string in the TTL SQL.
- New attack `attacks/test_unauthorized_access.py`: with no token, or with someone else's token, the attacker can't overwrite Bob's keys, read his inbox, send as Alice or delete his messages. v1 still can.

### B. Keys and warnings
- Private keys persist between sessions: encrypted with a key derived from the password (Argon2id `crypto_pwhash`, XChaCha20-Poly1305), stored in localStorage as ciphertext only. New keys only on first sign-up.
- Trust on first use: remember each contact's identity key. If it changes, show a red "⚠️ <name>'s security key changed. Verify the safety number again" warning and block sending until the user confirms.
- Replace the green "Verified" tick with "Signature valid, not yet verified" until the user marks the safety number as verified.
- Make the MITM test real: the server swaps Bob's key after first contact, and the client logic must detect the change.
- Docs: replace "forward secrecy" with "per-message keys", fix the `file:///Users/gourav` links, and fix the nonce comment (12 bytes, not 24).

### C. CipherBridge: Telegram Bot and Mini App
The user provides `TELEGRAM_BOT_TOKEN` and `MINIAPP_URL` (the cloudflared HTTPS link + `/tg/`) in `secrets/.env`.
- **Bot** (`backend/bot/bot.py`, python-telegram-bot v21+, loads `secrets/.env`): `/start` explains in two lines and shows a button that opens the Mini App. A message starting with `🔒SM2:` gets a "Decrypt" button that opens the Mini App with it. Inline mode, so the Mini App can share ciphertext into any chat.
- **Mini App** (`frontend/telegram-miniapp/`, served at `/tg/`): loads `https://telegram.org/js/telegram-web-app.js`, reuses `frontend/shared/crypto.js`, and uses Telegram theme colours. Also works when opened in a normal browser for debugging.
- **Login:** the Mini App sends `Telegram.WebApp.initData` to `/api/tg/auth`. The server validates it (secret key = HMAC-SHA256 of the bot token keyed with "WebAppData", hash = HMAC-SHA256 of the sorted data-check-string, constant-time compare, auth_date under 1 hour), then links or creates user `tg_<telegram_id>` and returns a session token.
- **Keys:** generated on first use and stored in `Telegram.WebApp.SecureStorage` when available, otherwise encrypted with a user PIN (Argon2id) in localStorage. Public keys go through the normal authenticated keys endpoint.
- **Encrypt tab:** pick any CipherBridge user (web or Telegram), show the safety number, encrypt with the same signed envelope as v2, and output one string `🔒SM2:<base64url JSON envelope>`. Buttons: Copy, and Share to chat (`switchInlineQuery`).
- **Decrypt tab:** paste or open a `🔒SM2:` string, verify signature and counter (replay protection stored locally), and decrypt. Clear errors for tampered, replayed or wrong-recipient messages.
- **Attacks:** `attacks/test_telegram_view.py` (a v1-style message is readable by Telegram's server, while the `🔒SM2` string has no plaintext and fails if tampered with) and a forged/modified initData test against `/api/tg/auth`.
- README "Telegram setup" section: BotFather, cloudflared, `.env`, `/setmenubutton`.

### D. Final security pass
- Run the full suite and fix anything failing.
- Run the `security-reviewer` and `crypto-auditor` agents (`/review`) and fix the serious findings: missing auth, secrets in code, innerHTML, tokens in logs, CORS `*`, missing input limits.
- `docs/RESULTS.md` regenerated from a real run.

### E. Docs for submission
- README: overview, features, architecture (Mermaid diagram), Windows setup, Telegram setup, attack results table, limitations, future work.
- `docs/THREAT_MODEL.md`: add a STRIDE table and the Telegram threats (Telegram still sees metadata, users must trust the Mini App code).
- `docs/PROTOCOL.md`: add the login flow, the `🔒SM2` envelope format and the initData check.
- `docs/REPORT.md` for college reviewers: problem statement, objectives, solution, architecture, flows, security testing, results, limitations, future work (Double Ratchet, post-quantum hybrid X25519 + ML-KEM-768, WhatsApp Web extension, group chats).

### F. Demo prep
- A list of screenshots to take: attack table, DB dump showing only ciphertext, Telegram Web showing `🔒SM2:...` next to the Mini App showing the message, key-change warning, 401 on unauthorized access.
- A 5-minute demo script and 15 likely viva questions with simple answers.

## Honest limits (use these words in docs and answers)
- Telegram, and our server, still see metadata: who talks to whom, when, and message size.
- A web app or Mini App is served by our server, so users must trust the JavaScript we serve.
- Per-message keys come from one shared secret, so stealing that secret exposes the conversation. A Double Ratchet would fix this (future work).
- Expiry and view-once are enforced by the recipient's app, so a modified client or a photo of the screen can still keep a message.
- The code has not had an independent security audit.

## Agents and skills
| Use | When |
|---|---|
| `security-reviewer` agent | Before committing anything that touches auth, routes or the database |
| `crypto-auditor` agent | Any change to `frontend/shared/crypto.js` or the envelope format |
| `red-teamer` agent | After each step, to try to break it and write a failing attack test |
| `test-writer` agent | New attack tests |
| `telegram-expert` agent | Bot, Mini App and initData work |
| `docs-writer` agent | Step E |
| `crypto-rules`, `backend-conventions`, `frontend-conventions`, `telegram-miniapp`, `verify-before-use` skills | Load the matching one before working in that area |

## Talking to the user
- Short, plain language. No jargon without a one-line explanation.
- Say what you ran and what you saw ("I ran the attack suite: 6/6 PASS").
- When something needs the user (a token, a tunnel, testing on a phone), say exactly what to do, step by step, for Windows.
- If two files or docs disagree, or you're unsure, stop and ask.
