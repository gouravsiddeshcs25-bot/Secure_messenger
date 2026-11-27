# AGENTS.md

For any AI coding tool (Codex, Cursor, Copilot, Gemini, Claude, ...) working in this repo:

1. **Read `CLAUDE.md` first.** It holds the never-break rules, where each truth lives, and the commands.
   Then read `backend/CLAUDE.md` or `frontend/CLAUDE.md` for the half you are touching.
2. Read `plan/PROGRESS.md` (current state) and `plan/TASKS.md` (next step). The prompt for each step is in `prompts/`.
3. Never read, print or commit anything in `secrets/` except `.env.example` and `README.md`.
4. Keep `/v1/` (frontend/legacy-insecure) insecure on purpose. Crypto is libsodium/PyNaCl only.
5. After every change, run `python attacks/run_all_attacks.py`. All rows must PASS.
6. After finishing work, update `plan/PROGRESS.md`, tick `plan/TASKS.md` and log what you did in `plan/AI-LOG.md`.
7. Role definitions for review and testing are in `.claude/agents/*.md`. Reuse them as instructions even if your tool has no subagents.
