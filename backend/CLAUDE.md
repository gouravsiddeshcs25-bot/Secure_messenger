# Backend rules (backend/ only)

Read the root `CLAUDE.md` first. Detailed conventions are in `.claude/skills/backend-conventions/SKILL.md`.

- Package: `backend.app`. Start it from the repo root with `python -m uvicorn backend.app.main:app --port 8000`.
- `main.py` loads `secrets/.env` (python-dotenv) **before** importing the routes. Mounts: `/v1` maps to frontend/legacy-insecure,
  `/v2` to frontend/web and `/shared` to frontend/shared. Don't rename these URLs.
- The DB defaults to `backend/data/messenger.db` (git-ignored). Tests use `MESSENGER_DB_PATH` for a temp DB.
- **The server never decrypts.** `payload` stays an opaque string.
- SQL is parameterised. Only `int()`-cast values may appear in f-string SQL.
- Config comes only from `os.environ`. Add new keys to `secrets/.env.example` (empty value) and `secrets/README.md`.
- Every API change goes to `contracts/API.md` first. Tell the frontend owner.
- Auth (step 3): Argon2id, `secrets.token_urlsafe` sessions with expiry, `hmac.compare_digest`, ownership checks, 429 rate limits.
  v1's unauthenticated path must keep working, because v1 stays insecure on purpose.
- `/api/dump/messages` is lab-only and returns 404 unless `LAB_MODE=1`. The attack tests read the SQLite file directly instead.
- v2 lives at `/api/...` (login required, `require_user` from `auth.py`). v1 lives at `/api/v1/...` (open on purpose, but it can't touch v2 accounts).
- Telegram (step 5): `backend/bot/` plus server-side initData HMAC check. Follow the `telegram-miniapp` skill.
- Pin new dependencies in `backend/requirements.txt`.
- After each change, run `python attacks\run_all_attacks.py` and make sure every row passes.
