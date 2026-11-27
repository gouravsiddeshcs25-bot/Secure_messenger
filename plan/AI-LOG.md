# AI log

What the AI did, which files it touched, and what was verified. Newest first.

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
