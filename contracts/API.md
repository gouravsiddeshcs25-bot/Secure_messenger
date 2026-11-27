# API contract

The handshake between `backend/` and `frontend/`. **Change this file first**, then the backend, then the frontend.
Base URL: `http://127.0.0.1:8000`. All bodies are JSON. Examples live in `contracts/examples/`.

There are two separate API paths:
- **v2 (secure)** at `/api/...`. Used by `frontend/web/` (and later the Mini App). Needs a login.
- **v1 (insecure on purpose)** at `/api/v1/...`. Used by `frontend/legacy-insecure/`. No login, no checks. It is the attack-lab target. **Never add security to it.**

## Auth (v2)
- `POST /api/register` or `POST /api/login` returns a session token.
- Send it on every other v2 call: `Authorization: Bearer <token>`.
- The token lasts 24 hours. The server stores only its SHA-256 hash.
- Keep the token in memory in the browser (a JS variable), never in localStorage.

Error codes: `401` = missing, wrong or expired token (or wrong username/password), `403` = not yours, `404` = not found,
`409` = username taken, `422` = bad body, `429` = too many attempts (login: 5/min per IP + username; register: 30/min per IP).

## v2 endpoints (`/api`)
| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| POST | `/api/register` | no | `{"username": str(1..50, a-z 0-9 _ -), "password": str(8..128)}` | 201 `{"token","expires_at","username"}` / 409 / 429 |
| POST | `/api/login` | no | `{"username","password"}` | 200 `{"token","expires_at","username"}` / 401 `Invalid username or password` (same for both cases) / 429 |
| POST | `/api/logout` | yes | none | 200 `{"status":"ok"}` (the session is deleted) |
| GET | `/api/users` | yes | none | 200 `["alice","bob",...]` |
| POST | `/api/keys` | yes | `{"identity_pubkey","exchange_pubkey","key_signature"}` (base64) | 200 `{"status":"ok"}`. Saved under the **session** user. |
| GET | `/api/keys/{username}` | yes | none | 200 key bundle / 404 |
| POST | `/api/messages` | yes | `{"recipient","payload","is_sensitive"?:bool,"ttl_seconds"?:int(0..604800)}` | 201 `{"status":"ok","message_id","expires_at"}` / 404 unknown recipient. The **sender is the session user**. |
| GET | `/api/messages/{username}` | yes | none | 200 `{"messages":[...]}` / 403 if `username` is not you |
| DELETE | `/api/messages/{message_id}` | yes | none | 200 `{"status":"ok","deleted":true}` / 404 if missing **or not addressed to you** |
| GET | `/api/dump/messages` | no | none | 404 unless the server runs with `LAB_MODE=1` in `secrets/.env`. Then 200 `{"stored_messages":[...]}` (simulated DB breach for demos). |

Example:
```
POST /api/login
{"username": "alice", "password": "correct horse battery"}
-> 200 {"token": "Vt3...", "expires_at": "2026-11-28 10:00:00", "username": "alice"}

GET /api/messages/alice
Authorization: Bearer Vt3...
-> 200 {"messages": [...]}
```

## v1 endpoints (`/api/v1`, insecure on purpose)
| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/api/v1/register` | `{"username"}` | 201 `{"status","username"}` |
| POST | `/api/v1/messages` | `{"sender","recipient","payload","is_sensitive"?,"ttl_seconds"?}` | 201 `{"status":"ok","message_id","expires_at"}` |
| GET | `/api/v1/messages/{username}` | none | 200 `{"messages":[...]}` (anyone can read anyone's inbox) |
| DELETE | `/api/v1/messages/{message_id}` | none | 200 / 404 (anyone can delete anything) |

v1 routes only work on v1 users (users with no password). If any username in the request, or the recipient of the message being deleted, is a v2 account, the answer is 404. Without this, `/api/v1` would be a back door around every v2 check.

`payload` is opaque to the server: plaintext for v1, and a base64 ciphertext envelope for v2 (see `docs/PROTOCOL.md`).

Static: `/` (switchboard), `/v1/` (frontend/legacy-insecure), `/v2/` (frontend/web), `/shared/` (frontend/shared).

## Planned (step 5)
- `POST /api/tg/auth` `{"init_data": str}` returns `{"token","expires_at","username"}`, or 401 on a bad or expired hash.
