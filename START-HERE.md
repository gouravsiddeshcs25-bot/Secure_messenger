# Start here (10 minutes)

## 1. What this is (1 min)
A cybersecurity lab: an **insecure** messenger (v1) and a **hardened end-to-end encrypted** one (v2) share the same server.
Ten automated attacks (MITM key swap, replay, tamper, DB dump, expired message, unauthorized access, forged Telegram login,
Telegram reading the chat, stolen sessions, script injection) prove that v1 falls and v2 holds.
v2 has accounts, keys stored on the device, and runs inside Telegram as the CipherBridge Mini App.

## 2. Set up (4 min) from the repo root
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1            # bash: source .venv/Scripts/activate (Windows) or .venv/bin/activate
python -m pip install -r backend/requirements.txt
node --version                         # needs Node 18+ for the attack suite
copy secrets\.env.example secrets\.env # fill only when you reach the Telegram step (see secrets/README.md)
```

## 3. Prove it works (2 min)
```powershell
python scripts\run_demo.py --no-telegram   # starts the server; leave it running
python attacks\run_all_attacks.py          # in a second terminal: expect 10/10 PASS
```
Open http://127.0.0.1:8000/v1/ and /v2/. Try the Alice/Bob walkthrough in `README.md`. For the presentation follow `docs/DEMO.md`.

## 4. Find your work (2 min)
- `plan/PROGRESS.md` shows where we are, `plan/TASKS.md` shows the next unticked step, and `prompts/NN-*.md` has the ready prompt for it.
- Backend person: `backend/` + `contracts/` and read `backend/CLAUDE.md`.
- Frontend person: `frontend/` and read `frontend/CLAUDE.md`.
- API changes go to `contracts/API.md` first.

## 5. Working with Claude Code (1 min)
`/start` begins a session. `/task` does a step. `/review` checks your diff. `/checkpoint "feat: ..."` tests, updates the plan and commits (no push).
`/handoff` writes the next prompt before a break.

Rules you must not break: v1 stays insecure, crypto is libsodium only, secrets only in `secrets/.env`, and attacks pass before every commit.
