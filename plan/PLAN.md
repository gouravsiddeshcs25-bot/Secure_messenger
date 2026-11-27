# Plan: Secure Messenger upgrade

## Goal
Turn the cybersecurity skill lab (insecure v1 vs hardened E2EE v2, measured by an automated attack suite)
into a demo-ready project with real accounts, persisted keys, honest security claims and a Telegram Mini App,
without breaking the v1 vs v2 comparison.

## Never break
- v1 (`/v1/`, `frontend/legacy-insecure/`) stays insecure. It is the control group.
- Crypto is libsodium (browser) / PyNaCl (server) only.
- Secrets live only in `secrets/.env`.
- `python attacks/run_all_attacks.py` passes after every change.

## Steps (tracked in TASKS.md, prompts in prompts/)
1. Base project runs and 5 attacks pass. **Done.**
2. Team folder structure (backend/, frontend/, plan/, .claude/, secrets/, contracts/).
3. Accounts: Argon2id login, session tokens, ownership checks, rate limiting, locked dump endpoint.
4. Client keys: persisted keys, key-change warning, fix the green tick, honest wording (and remove `innerHTML` in v2).
5. Telegram: bot + Mini App + server-side initData check.
6. New attack tests for steps 3–5 (IDOR, brute force, session reuse, forged initData, key swap after persistence).
7. Docs and report (threat model, protocol, results, limitations).
8. Demo prep (script, seed data, fallback recording).

## Ownership
- Backend (`backend/`, `contracts/`): auth, routes, bot.
- Frontend (`frontend/`): v2 UI, shared crypto, Mini App.
- Shared: `attacks/`, `docs/`, `plan/`.

API changes go to `contracts/API.md` first, then the backend, then the frontend.
