---
name: telegram-miniapp
description: How to build the Telegram bot and Mini App for Secure Messenger safely, including initData validation, token handling and local HTTPS. Use for step 5 or any Telegram-related change.
---
# Telegram bot + Mini App

## Shape
- `backend/bot/`: a minimal bot. `/start` replies with a WebApp button that opens `MINIAPP_URL`.
- `frontend/telegram-miniapp/`: `index.html` loads `https://telegram.org/js/telegram-web-app.js` (the official
  script; the only allowed external script), then `/shared/vendor/libsodium.js`, `/shared/crypto.js` and its own `app.js`.
- The backend mounts it at `/tg/`. `index.html` is GENERATED from `frontend/web/index.html` by `scripts/build_miniapp.py`
  (only the sign-in block, `auth.html`, differs). The Mini App is the v2 client: it imports `/v2/js/*.js`.
- `POST /api/tg/auth` takes `{ "init_data": "<raw Telegram.WebApp.initData>" }` and returns a session token.
  Write it in `contracts/API.md` first.

## initData validation (server side, mandatory)
```python
pairs = dict(urllib.parse.parse_qsl(init_data, strict_parsing=True))
received = pairs.pop("hash")
check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
ok = hmac.compare_digest(hmac.new(secret, check.encode(), hashlib.sha256).hexdigest(), received)
```
Also reject if `auth_date` is older than about 1 hour, and parse `user` JSON only after the hash checks out.
Confirm the details against core.telegram.org/bots/webapps before implementing (verify-before-use).

## Secrets
`TELEGRAM_BOT_TOKEN`, `MINIAPP_URL` and `SESSION_SECRET` live in `secrets/.env` only. Never log the token.
If it leaks, follow `secrets/README.md` (BotFather `/revoke`).

## Local dev
The Mini App needs HTTPS. Run a tunnel (cloudflared/ngrok) to port 8000 and set `MINIAPP_URL=https://<tunnel>/tg/`.

## Security notes for docs
Bot chats are not E2EE. Message content goes only through our E2EE API, never through the bot.
Telegram gives identity (a signed initData), not secrecy.

## Tests (step 6)
Cover forged hash, missing hash, expired `auth_date`, a field tampered after signing, and a valid one (using a test token
generated inside the test, never the real one).
