# AI log

What the AI did, which files it touched, and what was verified. Newest first.

## 2026-11-27: feat: CipherBridge Telegram bot and Mini App (Claude Code)
- **Checked first:** the initData rules on core.telegram.org/bots/webapps (secret key = HMAC-SHA256 of the bot token keyed with
  "WebAppData"; every field except `hash`, sorted, `key=value`, joined with newlines; `signature` stays in) and the
  python-telegram-bot 22.8 signatures in the installed package.
- **Backend:** `telegram_auth.py` (validator + a signer used only by tests), `POST /api/tg/auth` (creates `tg_<id>` on first login),
  `POST /api/tg/share` (only 🔒SM2 text, only tg_ accounts, never passes the token-bearing URL into errors), `tg_` names reserved in
  v2 register, v1 register and login, `/tg` static mount, new rate limiters.
- **Bot:** `backend/bot/bot.py`: /start with the Mini App button, sets the menu button, Decrypt button for forwarded 🔒SM2 text
  (opens `/tg/?m=...`), inline-mode button, warns against sending readable text. httpx logging muted so the token never hits a log.
- **Frontend:** the Mini App is the v2 client: `scripts/build_miniapp.py` generates `frontend/telegram-miniapp/index.html` from
  `frontend/web/index.html` with a Telegram sign-in + PIN block (`auth.html`); `app.js` there handles login/PIN and imports `/v2/js/*`.
  `chat.js` got Seal for Telegram and Open a 🔒SM2 message (both in the web app too), `sm2.js` holds the format; the inbox refuses
  `channel` envelopes and the paste box requires `channel: "telegram"`; tamper check before the replay check.
- **Attacks:** `test_telegram_auth.py` (forged/missing/odd hash, edited user id, expired, future, repeated field, non-number id, live
  server refuses, tg_ names blocked, share endpoint 401/403) and `test_telegram_view.py` (no plaintext in the Telegram text, other keys
  can't open it, edited text/header fail, second open is a replay, cut-off copy refused). Both go red when the validator is weakened.
- **Verified:** suite 8/8 PASS on a test server with a made-up bot token; Mini App browser test with a stubbed Telegram script
  (outside-Telegram hint, PIN create/mismatch/wrong PIN, seal, share link, open in the web app, replay, tamper, wrong recipient,
  inbox delivery, `?m=` link, dark theme, sensitive refused) and the web regression test, no console errors.
- **Human check needed:** real bot token + cloudflared tunnel, then the steps in README "CipherBridge: Telegram Setup".

## 2026-11-27: fix: messages lost with the same account open in two tabs; landing polish (Claude Code)
- **Bug (reported by the user):** a message sent to `harshitt` never showed up. The DB showed it had been delivered and deleted,
  and `harshitt` had overlapping sessions. Reproduced with Playwright: tab B received and stored the message and deleted it from the
  server; the older tab A still had its stale vault in memory and overwrote it on its next save (opening a chat).
- **Fix:** `vault.js` keeps a version number and refuses to overwrite a newer copy (the stale tab signs out instead);
  `chat.js` writes the message to the vault *before* deleting it from the server; `app.js` uses a BroadcastChannel so the newest
  tab for an account wins and older tabs sign out (and end their server session). Chats with held/unread messages now show in the list.
- **Landing:** header links, tighter headline, "How a message travels" 4-step sequence.
- **Verified:** suite 6/6 PASS; two-user browser run (8 steps) with no console errors; the two-tab repro now keeps the message,
  also with BroadcastChannel disabled (version check alone).

## 2026-11-27: feat: redesigned v2 client with persisted keys and key-change warning (Claude Code)
- **Did:** built a clickable design preview first; the user approved it. Then: `frontend/shared/ui.css` (design system),
  new `frontend/web/index.html` + `app.css` + `js/{app,chat,vault,api,dom}.js` (old `app.js`/`style.css` removed),
  `crypto.js` additions (`sealLocal`/`openLocal` XChaCha20-Poly1305, `exportKeys`/`importKeys`) and honest comments,
  trust-on-first-use in the web client and in `attacks/client_sim.py`, real server-side key swap in `test_mitm_key_swap.py`,
  landing page `frontend/landing/index.html` served at `/`, wording fixes in README/PROTOCOL/THREAT_MODEL, frontend docs.
- **Verified:** suite 6/6 PASS; the MITM test fails with TOFU disabled ("undetected") and passes with it. Node round-trip test
  of sealLocal/openLocal (wrong password rejected). Playwright + Edge two-user run, 8 steps, no console errors.
  Screenshots checked for light, dark and phone width.
- **Human check needed:** two browsers on `/v2/`, the key-change flow with a private window, and the home page at `/`.

## 2026-11-27: feat: argon2id login, sessions and access control (Claude Code)
- **Did:** new `backend/app/auth.py` (Argon2id via PyNaCl, dummy-hash timing equaliser, token_urlsafe sessions stored as SHA-256,
  `require_user`, in-memory rate limiter). `database.py`: `password_hash` column migration, `sessions` table, TTL now a `?` parameter.
  `routes.py`: v2 routes authenticated, sender/key owner from the session, 403/404 ownership checks, dump behind `LAB_MODE=1`,
  v1 moved to `/api/v1` and blocked from touching v2 accounts. v2 client: register/login/logout, Bearer token in memory,
  all `innerHTML` replaced. v1 client: URL paths only. Attacks: client_sim uses tokens and reads the DB file for the breach
  simulation; new `test_unauthorized_access.py`. Contract, examples, `.env.example`, `docs/API-NOTES.md` updated.
- **Verified:** suite 6/6 PASS on a fresh server and on the user's restarted server. The new test failed against the old server.
  `/api/dump/messages` -> 404, `/api/users` without token -> 401, short password -> 422.
- **Human check:** the user registered and logged in two accounts in `/v2/` and confirmed it works.

## 2026-11-27: chore: team folder structure (Claude Code)
- **Did:** used `git mv` to move `server/` to `backend/app/` (`app.py` became `main.py`), `client_v2/` to `frontend/web/`,
  `client_v1/` to `frontend/legacy-insecure/`, and crypto.js, dlp.js and vendor/libsodium.js to `frontend/shared/`.
  Fixed the static mounts (`/v1`, `/v2`, the new `/shared`), the v2 script tags, the default DB path (`backend/data/`),
  the `attacks/crypto_helper.js` requires, the runner start command (`backend.app.main:app`, with `cwd` set to the repo root) and the README.
  Added secrets/.env loading via python-dotenv. Added `.claude/` (settings, 3 hooks, 6 agents, 7 commands, 5 skills),
  `secrets/`, `plan/`, `contracts/`, `prompts/`, `scripts/` and the CLAUDE.md, AGENTS.md and START-HERE.md files.
- **Bug fixed:** the runner wrote RESULTS.md with the cp1252 codec, which crashed on emoji and truncated the file. It now uses UTF-8.
- **Verified:** `/`, `/v1/`, `/v2/`, `/shared/crypto.js`, `/shared/dlp.js` and `/shared/vendor/libsodium.js` all return 200.
  `python attacks/run_all_attacks.py` gives 5/5 PASS. Hooks were tested with sample stdin: the guard blocks a fake bot token and overclaiming
  words, skips docs/, and exits 0 on garbage input. plan-sync exits 0 when `stop_hook_active` is set.
- **Human check needed:** open `/v2/` in two tabs and do the Alice/Bob walkthrough in the README.
