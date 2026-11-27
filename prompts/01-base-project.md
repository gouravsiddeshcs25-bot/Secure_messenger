# Step 1: Base project runs and 5 attacks pass (DONE)

Use this prompt to re-verify the baseline on a fresh machine.

```
Set up and verify Secure Messenger from a clean checkout.
1. python -m venv .venv, activate it, then python -m pip install -r backend/requirements.txt
2. Check Node 18+ is installed (node --version). The attack suite uses it through attacks/crypto_helper.js.
3. Run python attacks\run_all_attacks.py from the repo root. It starts the server itself.
4. Confirm 5/5 PASS and that docs/RESULTS.md was regenerated.
5. Start the server (python -m uvicorn backend.app.main:app --port 8000) and confirm /, /v1/, /v2/ and /shared/crypto.js return 200.
Report the table. Do not change any code.
```
