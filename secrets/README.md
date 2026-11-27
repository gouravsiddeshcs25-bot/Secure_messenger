# secrets/

The only place real secrets live. Git ignores everything here except this file and `.env.example`.
Claude Code is denied Read/Edit access to this folder (see `.claude/settings.json`).

## How to fill it
1. Copy the template: `copy secrets\.env.example secrets\.env` (Windows) or `cp secrets/.env.example secrets/.env`.
2. Fill in each value:
   - `TELEGRAM_BOT_TOKEN`: from @BotFather (`/newbot`). Looks like `123456789:AA...`.
   - `MINIAPP_URL`: the public HTTPS URL serving the Mini App (e.g. an ngrok/cloudflared tunnel to `/miniapp/`).
   - `SESSION_SECRET`: a long random value. Generate one with
     `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
   - `LAB_MODE`: leave empty normally. Set `LAB_MODE=1` only for a demo of the "database breach" view at
     `/api/dump/messages` (it returns 404 otherwise). Remove it again after the demo.
3. Restart the server. `backend/app/main.py` loads `secrets/.env` automatically if it exists.

Share secrets with teammates over a private channel, never in git, chat logs, screenshots or AI prompts.

## If a token leaks
1. **Revoke it at once.** For a Telegram bot token, open @BotFather, then `/revoke`, pick the bot, and paste the new token into `secrets/.env`.
   For `SESSION_SECRET`, generate a new one. Every existing session becomes invalid, which is the point.
2. **If it was committed**, deleting the file is not enough because the old value stays in git history. Rotate the secret first, then tell the team.
   Rewrite history only if the repo is private and everyone agrees.
3. Check bot activity and server logs for misuse during the leak window.
4. Add a line to `plan/LESSONS.md` describing how it leaked and what now prevents it.
