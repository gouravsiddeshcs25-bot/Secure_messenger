---
description: Start a work session. Load the plan, check the repo is healthy, and propose the next step.
---
1. Read `CLAUDE.md`, `plan/PROGRESS.md`, `plan/TASKS.md` and `plan/LESSONS.md`.
2. Run `git status` and `git log --oneline -5`. If there are uncommitted changes, summarise them and ask
   whether to continue that work or set it aside. Never discard changes.
3. Run `python attacks/run_all_attacks.py` (Windows: `python attacks\run_all_attacks.py`). Report the table.
   If anything fails, that is the first job. Stop and say so.
4. Find the first unticked step in `plan/TASKS.md` and its prompt in `prompts/`.
5. Reply in 5 lines or fewer: branch, suite status, current step, the first concrete action, and any blocker.
   Wait for the user's go before editing code.
