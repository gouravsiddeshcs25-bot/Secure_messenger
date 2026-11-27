# Secure Messenger: project guide for Claude

A cybersecurity skill lab. One zero-knowledge FastAPI + SQLite server serves two clients:
**v1** (`/v1/`, deliberately insecure: plaintext, no replay check) and **v2** (`/v2/`, hardened E2EE with libsodium:
Ed25519 + X25519 + ChaCha20-Poly1305, DLP, expiry). An automated attack suite runs 5 attacks against both and
records the results in `docs/RESULTS.md`. Next up: real accounts, persisted keys, honest wording and a Telegram Mini App
(see `plan/TASKS.md`).

## Never break
1. **v1 stays insecure.** It is the control group. Never add security to `frontend/legacy-insecure/`, and never weaken v2 to match it.
2. **libsodium / PyNaCl only** for crypto. No home-made primitives. See `.claude/skills/crypto-rules`.
3. **Secrets only in `secrets/.env`** (git-ignored; Claude can't read it). Code reads `os.environ`. Never commit tokens.
4. **Run the attacks after every change:** `python attacks\run_all_attacks.py`. All rows must PASS before a commit.
5. URLs `/v1/`, `/v2/` and `/shared/` don't change. API changes go to `contracts/API.md` first, then the backend, then the frontend.
6. Honest wording: state each guarantee with its limits. Overclaiming words are blocked by `.claude/hooks/guard.mjs`.

## Where each truth lives
| Truth | File |
|---|---|
| What we're doing and why | `plan/PLAN.md` |
| Steps and status | `plan/TASKS.md` (ticked by `/checkpoint`) |
| Current state / next step | `plan/PROGRESS.md` |
| Why a choice was made | `plan/DECISIONS.md` |
| Bugs and the rules they taught us | `plan/LESSONS.md` |
| What the AI did | `plan/AI-LOG.md` |
| API between halves | `contracts/API.md` + `contracts/examples/` |
| Crypto protocol | `docs/PROTOCOL.md` + `frontend/shared/crypto.js` |
| Threats | `docs/THREAT_MODEL.md` |
| Attack results | `docs/RESULTS.md` (generated; don't hand-edit) |
| Backend rules | `backend/CLAUDE.md` |
| Frontend rules | `frontend/CLAUDE.md` |
| Required config keys | `secrets/.env.example` |
| Ready prompt per step | `prompts/NN-*.md` |

## Layout
`backend/app/` (main.py, routes.py, database.py) · `backend/data/` (messenger.db, ignored) ·
`frontend/shared/` (crypto.js, dlp.js, vendor/libsodium.js, served at /shared/) · `frontend/web/` (v2) ·
`frontend/legacy-insecure/` (v1) · `attacks/` · `docs/` · `plan/` · `prompts/` · `contracts/` · `scripts/` · `secrets/`

## Commands (run from the repo root)
```powershell
python -m pip install -r backend/requirements.txt              # install
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload   # run
python attacks\run_all_attacks.py                              # check (starts the server if needed)
powershell -File scripts\check.ps1                             # same check, plus URL smoke test
```
Slash commands: `/start`, `/task`, `/checkpoint`, `/handoff`, `/attack`, `/explain`, `/review`.
Agents: security-reviewer, crypto-auditor (read-only), red-teamer, test-writer, telegram-expert, docs-writer.

## Hooks
- SessionStart prints PROGRESS, LESSONS and git state.
- guard.mjs (after Edit/Write) blocks tokens, keys, `innerHTML` with data and overclaims.
- plan-sync.mjs (Stop) asks for a PROGRESS/TASKS update if code changed after the last PROGRESS edit.

Commit on the current branch with `feat:`, `fix:`, `docs:` or `chore:`. Never push without being asked.
