---
description: Before a break or a hand-over to a teammate, write the exact next step as a ready prompt.
---
1. Run `git status` and `python attacks/run_all_attacks.py`. Note anything uncommitted or failing.
2. Update `plan/PROGRESS.md` under "Handoff":
   - date and branch
   - what is done, what is half-done (with file:line), and what is broken
   - the **next action** as a ready-to-paste prompt in a fenced block, specific enough that someone
     with no context can run it (files, acceptance check, which agent to use)
   - open questions for the human
3. If the next step's prompt in `prompts/` is out of date, update it.
4. Do not commit unless the user asks. If they do, run `/checkpoint docs: handoff`.
5. Reply with the ready prompt only.
