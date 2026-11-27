# API contract

The handshake between `backend/` and `frontend/`. **Change this file first**, then the backend, then the frontend.
Base URL: `http://127.0.0.1:8000`. All bodies are JSON. Examples live in `contracts/examples/`.

There are two separate API paths:
- **v2 (secure)** at `/api/...`. Used by `frontend/web/` and the Telegram Mini App (`frontend/telegram-miniapp/`). Needs a login.
- **v1 (insecure on purpose)** at `/api/v1/...`. Used by `frontend/legacy-insecure/`. No login, no checks. It is the attack-lab target. **Never add security to it.**

## Auth (v2)
- `POST /api/register` or `POST /api/login` returns a session token. Telegram users get one from `POST /api/tg/auth` instead.
- Send it on every other v2 call: `Authorization: Bearer <token>`.
- The token lasts 24 hours. The server stores only its SHA-256 hash.
- Keep the token in memory in the browser (a JS variable), never in localStorage.

Error codes: `401` = missing, wrong or expired token (or wrong username/password), `403` = not yours, `404` = not found,
`409` = username taken, `422` = bad body, `429` = too many attempts (login: 5/min per IP + username; register: 30/min per IP;
Telegram login: 30/min per IP; Telegram share: 20/min per user), `502` = Telegram refused or couldn't be reached, `503` = Telegram not set up.

Names starting with `tg_` are reserved for Telegram accounts (`tg_<telegram user id>`): `/api/register` and `/api/v1/register` refuse them (400)
and `/api/login` always answers 401 for them.

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
| POST | `/api/tg/auth` | no | `{"init_data": str(1..4096)}`: the raw `Telegram.WebApp.initData` | 200 `{"token","expires_at","username":"tg_<id>","first_name","new_account":bool}` / 401 bad, tampered or expired (over 1 hour) signature / 409 / 429 / 503 no bot token. The account is created on first login. |
| POST | `/api/tg/share` | yes (tg_ accounts only) | `{"text": str(1..4096)}`, must start with `🔒SM2:` | 200 `{"prepared_id"}` for `Telegram.WebApp.shareMessage` / 400 not a 🔒SM2 text / 403 not a Telegram account / 502 / 503 |
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
| POST | `/api/v1/register` | `{"username"}` | 201 `{"status","username"}` / 400 for reserved `tg_` names |
| POST | `/api/v1/messages` | `{"sender","recipient","payload","is_sensitive"?,"ttl_seconds"?}` | 201 `{"status":"ok","message_id","expires_at"}` |
| GET | `/api/v1/messages/{username}` | none | 200 `{"messages":[...]}` (anyone can read anyone's inbox) |
| DELETE | `/api/v1/messages/{message_id}` | none | 200 / 404 (anyone can delete anything) |

v1 routes only work on v1 users (users with no password). If any username in the request, or the recipient of the message being deleted, is a v2 account, the answer is 404. Without this, `/api/v1` would be a back door around every v2 check.

`payload` is opaque to the server: plaintext for v1, and a base64 ciphertext envelope for v2 (see `docs/PROTOCOL.md`).

Static: `/` (home page), `/v1/` (frontend/legacy-insecure), `/v2/` (frontend/web), `/tg/` (frontend/telegram-miniapp), `/shared/` (frontend/shared).

`/v2/?m=<sealed>` and `/tg/?m=<sealed>` open a 🔒SM2 message (the part after `SM2:`) right after sign-in. The bot's Decrypt button uses this.

## The 🔒SM2 text (Telegram)
Not an endpoint: a sealed message that users paste into Telegram chats. It never goes through `/api/messages`.
`🔒SM2:` + base64url (no padding) of the v2 envelope JSON `{header, nonce, ciphertext, signature}`, where
`header.channel = "telegram"`. Clients refuse a `channel` header in the server inbox, and refuse anything without it
when pasted. Full format in `docs/PROTOCOL.md`.
