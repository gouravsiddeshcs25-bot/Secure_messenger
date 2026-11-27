---
description: Review the current uncommitted changes against the project rules before /checkpoint.
---
1. Run `git status`, `git diff` and `git diff --cached`.
2. Check the diff against the never-break rules in `CLAUDE.md`:
   v1 stays insecure, libsodium/PyNaCl only, secrets only in `secrets/`, and API changes go through `contracts/API.md` first.
3. Run the **security-reviewer** subagent on the diff. If `frontend/shared/crypto.js`, key handling, replay or
   expiry changed, also run **crypto-auditor**.
4. Run `python attacks/run_all_attacks.py`.
5. Report the findings as `severity | file:line | issue | fix`, the suite table, and a verdict:
   **READY for /checkpoint** or **FIX FIRST** (with the list of fixes). Don't apply fixes unless asked.
