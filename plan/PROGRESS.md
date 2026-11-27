# Progress

## Current state
- Branch: `upgrades`
- Repo restructured into the team layout: `backend/app/` (was `server/`), `frontend/web/` (was `client_v2/`),
  `frontend/legacy-insecure/` (was `client_v1/`), `frontend/shared/` (crypto.js, dlp.js, vendor/libsodium.js, served at `/shared/`).
- The SQLite DB now lives in `backend/data/messenger.db` (git-ignored).
- `.claude/` (settings, hooks, agents, commands, skills), `secrets/`, `plan/`, `contracts/` and `prompts/` were added.
- Attack suite: **5/5 PASS** (`python attacks/run_all_attacks.py`).

## Last checkpoint
- 2026-11-27 · `upgrades` · chore: team folder structure. Moves done with git mv, paths fixed, and the runner UTF-8 bug fixed.
  Suite 5/5 PASS.

## Next step
Step 3: Argon2id login, session tokens, ownership checks, rate limiting, locked dump endpoint.
Run `prompts/03-auth-sessions.md`.

## Known issues
- `frontend/web/app.js` uses `innerHTML` with sender/alert data (lines ~70, 398, 491, 504, 529), which is an XSS risk.
  guard.mjs will block edits to that file until those lines are fixed (planned in step 4).
- `/api/dump/messages` is open to anyone (locking it is planned in step 3).
- No auth yet: any client can read or delete any user's messages (step 3).

## Handoff
(Filled by `/handoff`.)
