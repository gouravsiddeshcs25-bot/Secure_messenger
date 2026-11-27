---
description: Verify, update the plan files and commit the current step on this branch. Never pushes.
argument-hint: [commit message, e.g. "feat: argon2id login"]
---
Commit message hint: $ARGUMENTS

1. Run `python attacks\run_all_attacks.py` (bash: `python attacks/run_all_attacks.py`).
   **If the exit code is non-zero or any row shows FAIL, stop.** Show the failing rows and do nothing else.
2. Run `git status` and `git diff --stat`. Make sure nothing from `secrets/`, `backend/data/`, `*.db`,
   `.env` or `.claude/settings.local.json` is staged or about to be staged. If something is, stop and warn.
3. In `plan/TASKS.md`, tick (`[x]`) the step this work completes. Tick only if it is fully done.
4. In `plan/PROGRESS.md`, update "Current state", "Last checkpoint" (date, branch, what changed,
   suite result such as `5/5 PASS`) and "Next step".
5. Add an entry to `plan/AI-LOG.md`: date, what the AI did, files touched, what a human verified.
6. If a bug was fixed, add one line to `plan/LESSONS.md`: `- YYYY-MM-DD: <bug> -> <cause> -> <rule that prevents it>`.
7. Stage the specific files by name with `git add <paths>`. Don't use `git add -A` blindly.
8. Commit on the current branch. Use the prefix `feat:` (new behaviour), `fix:` (bug), `docs:` (docs/plan only)
   or `chore:` (structure/tooling). If `$ARGUMENTS` is given, use it as the subject.
   End the message with the attribution lines required by the session.
9. **Do not push.** Print the commit hash and a one-line summary.
