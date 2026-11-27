# Progress

## Current state
- Branch: `upgrades`
- Step 3 (A) done: Argon2id accounts, session tokens (SHA-256 hash stored, 24h), `require_user` on every v2 route,
  ownership checks, rate limits (login 5/min per IP+username, register 30/min per IP), dump endpoint locked behind `LAB_MODE=1`.
- v2 API at `/api/...`, insecure v1 API at `/api/v1/...` (v1 routes refuse v2 accounts so they aren't a back door).
- v2 web client: register / log in / log out, token in memory only, no `innerHTML` left.
- Attack suite: **6/6 PASS** (new: Unauthorized access).

## Last checkpoint
- 2026-11-27 · `upgrades` · feat: argon2id login, sessions and access control. Suite 6/6 PASS. User tested register/login by hand.

## Next step
Frontend redesign together with step 4 (B): persisted keys, key-change warning, verify flow, honest wording.
A static clickable preview (`frontend/web/preview.html`) is shown to the user for approval before the real wiring.

## Known issues
- In-memory rate limiter resets on restart; behind cloudflared all users share one IP (the per-username login limit still protects accounts).
- Keys are regenerated on every login until step B.

## Ideas / later
- (none yet)

## Handoff
(Filled by `/handoff`.)
