---
name: backend-conventions
description: Conventions for backend/ (FastAPI + SQLite) in Secure Messenger. Use before adding or changing routes, database code, auth, sessions, rate limiting, config or the Telegram bot.
---
# Backend conventions

## Layout
- `backend/app/main.py`: the app, loading `secrets/.env` (python-dotenv), static mounts `/v1`, `/v2`, `/shared` and the `/` switchboard.
- `backend/app/routes.py`: `APIRouter(prefix="/api")` with Pydantic request models.
- `backend/app/database.py`: sqlite3. The DB is `backend/data/messenger.db` (override with `MESSENGER_DB_PATH`).
- `backend/app/auth.py` (step 3): Argon2id, sessions, ownership checks.
- `backend/bot/` (step 5): the Telegram bot.
- Run it from the repo root: `python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload`.

## Rules
1. **Contract first.** Change `contracts/API.md` (+ `contracts/examples/`) before the route.
2. Relative imports inside the package (`from . import database`). Don't use `sys.path` hacks.
3. SQL is always parameterised (`?`). For f-string SQL, only `int()`-cast values are allowed (as in the TTL `datetime()` call).
4. Config comes only from `os.environ` (after dotenv loads it). Keys are listed in `secrets/.env.example`. Never hard-code a value.
5. The server never decrypts. Payloads stay opaque strings. Don't add server-side crypto on message content.
6. Auth (step 3): Argon2id hashes, `secrets.token_urlsafe(32)` session tokens, `hmac.compare_digest`,
   an expiry, and an ownership check on every `/messages` and `/keys` write or read. Errors are 401/403/404 without leaking
   whether a user exists. Rate limits on register, login and send return 429.
7. `/api/dump/messages` is a lab-only endpoint. Keep it disabled (404) unless `LAB_MODE=1`. The attack tests
   simulate a breach by reading the SQLite file read-only (`read_db_messages()` in `attacks/client_sim.py`).
8. v1 compatibility: v1 has its own open router at `/api/v1/...` (no auth, on purpose). v2 is at `/api/...` and every
   route except register/login uses `Depends(require_user)`. v1 routes refuse v2 accounts so they are not a back door.
9. New dependencies get a pinned version in `backend/requirements.txt`.
10. After every change, `python attacks/run_all_attacks.py` must pass.
