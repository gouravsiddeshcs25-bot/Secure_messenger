---
description: Work on one step from plan/TASKS.md, using a plan, small edits and the attack suite.
argument-hint: [step number or name, default = first unticked]
---
Step: $ARGUMENTS (if empty, use the first unticked step in `plan/TASKS.md`).

1. Open the matching prompt in `prompts/` and the relevant `backend/CLAUDE.md` / `frontend/CLAUDE.md`.
2. If the step changes the API, update `contracts/API.md` (and `contracts/examples/`) **first**, then
   the backend, then the frontend.
3. Write a short plan: the files to touch, the tests to add, and the risks to the never-break rules in `CLAUDE.md`.
   Wait for OK if the plan touches crypto, auth or v1.
4. Implement in small steps. After each meaningful change, run `python attacks/run_all_attacks.py`.
5. Use subagents where they fit: test-writer for new tests, security-reviewer / crypto-auditor before
   you finish, and red-teamer for new attack surface.
6. Record any non-obvious choice in `plan/DECISIONS.md` (date, decision, why, alternatives).
7. When it's done and the suite is green, tell the user to run `/checkpoint`. Do not commit yourself.
