---
name: verify-before-use
description: Check that a library API, function, file, flag or external spec exists and behaves as assumed before using it in code or docs. Use when adding a dependency, calling an unfamiliar libsodium/PyNaCl/FastAPI/Telegram API, or acting on a remembered fact.
---
# Verify before use

Wrong assumptions are the main source of bugs in this project. Before relying on something, prove it.

| Claim | How to verify |
|---|---|
| A libsodium.js function exists | `node -e "require('./frontend/shared/vendor/libsodium.js'); ..."` or grep the bundle for its name |
| A PyNaCl / FastAPI / argon2 API | `python -c "import nacl.pwhash; help(nacl.pwhash.argon2id.str)"` |
| A package version | `python -m pip show <pkg>`, then pin it in `backend/requirements.txt` |
| A project file, function or route | Grep or Glob for it. Read the code, not the README |
| An API field | `contracts/API.md` + `backend/app/routes.py` |
| A Telegram Bot/WebApp detail | core.telegram.org docs (cite the URL in a code comment) |
| A security property holds | An attack test in `attacks/` demonstrates it, and `python attacks/run_all_attacks.py` passes |
| A memory or LESSONS note | Re-check it against the current code. It may be stale |

Rules:
1. If you can't verify something, say "unverified" and don't build on it.
2. Write down what you verified and how in the `plan/AI-LOG.md` entry for the step.
3. Never claim "tests pass" without pasting the actual runner output.
