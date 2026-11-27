# Decisions

Format: date, decision, why, alternatives considered.

- **2026-11-27: Team layout with backend/ and frontend/ split.** Two people can work in parallel, and each half has its own CLAUDE.md.
  Moves were done with `git mv` to keep history. Alternative: keep `server/` and `client_v*/`, rejected because it mixes concerns.
- **2026-11-27: Shared crypto in `frontend/shared/`, served at `/shared/`.** v2, the future Mini App and the attack suite
  (`attacks/crypto_helper.js`) all use the same `crypto.js`, so there is one implementation to audit.
- **2026-11-27: URLs `/v1/` and `/v2/` unchanged.** Demos, docs and tests depend on them.
- **2026-11-27: DB in `backend/data/` (git-ignored), with the `MESSENGER_DB_PATH` override kept.** Runtime data stays out of git.
- **2026-11-27: Secrets only in `secrets/.env`, loaded by python-dotenv in `backend/app/main.py`.** Claude is denied
  Read/Edit on `secrets/**`, and guard.mjs blocks token patterns in code.
- **2026-11-27: guard.mjs exempts `frontend/legacy-insecure/` from the innerHTML check.** v1 is deliberately insecure.
  v2's existing innerHTML uses stay as they are for now and are fixed in step 4.
- **2026-11-27: Python packages are `backend/` and `backend/app/` (with `__init__.py`).** The server starts with
  `python -m uvicorn backend.app.main:app` from the repo root.
