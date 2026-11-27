# API contract

The handshake between `backend/` and `frontend/`. **Change this file first**, then the backend, then the frontend.
Base URL: `http://127.0.0.1:8000`. All bodies are JSON. Examples live in `contracts/examples/`.

Status: **current (unauthenticated)**. Step 3 adds auth. See "Planned" below.

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/api/register` | `{"username": str(1..50)}` | 201 `{"status":"created","username"}` or 201 `{"status":"ok","message","username"}` if it already exists |
| GET | `/api/users` | none | 200 `["alice","bob",...]` |
| POST | `/api/keys` | `{"username","identity_pubkey","exchange_pubkey","key_signature"}` (base64) | 200 `{"status":"ok","message"}` |
| GET | `/api/keys/{username}` | none | 200 key bundle / 404 |
| POST | `/api/messages` | `{"sender","recipient","payload","is_sensitive"?:bool,"ttl_seconds"?:int}` | 201 `{"status":"ok","message_id","expires_at"}` |
| GET | `/api/messages/{username}` | none | 200 `{"messages":[...]}` |
| DELETE | `/api/messages/{message_id}` | none | 200 `{"status":"ok","deleted":true}` / 404 |
| GET | `/api/dump/messages` | none | 200 `{"stored_messages":[...]}`. **Lab-only** (simulated DB breach) |

`payload` is opaque to the server: plaintext for v1, and a base64 ciphertext envelope for v2 (see `docs/PROTOCOL.md`).

Static: `/` (switchboard), `/v1/` (frontend/legacy-insecure), `/v2/` (frontend/web), `/shared/` (frontend/shared).

## Planned (step 3, not implemented yet)
- `POST /api/auth/register` `{"username","password"}`, `POST /api/auth/login` returns `{"token","expires_at"}`,
  `POST /api/auth/logout`. Send `Authorization: Bearer <token>` on v2 calls.
- Ownership: `GET /api/messages/{username}` and `DELETE /api/messages/{id}` return 403 unless the session owns them.
- 429 on too many login/register/send attempts.
- `/api/dump/messages` returns 404 unless `LAB_DUMP_ENABLED=1`.
- v1 keeps its unauthenticated path so the comparison still works.

## Planned (step 5)
- `POST /api/telegram/auth` `{"init_data": str}` returns `{"token","expires_at","username"}`, or 401 on a bad or expired hash.
