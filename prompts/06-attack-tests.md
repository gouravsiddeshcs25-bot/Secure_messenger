# Step 6: New attack tests

```
/task 6. Use the red-teamer and test-writer agents.
Add attacks/test_*.py modules (same run() result shape) and register them in attacks/run_all_attacks.py:
- IDOR: read/delete another user's messages (v1 succeeds, v2 403)
- Password brute force (v2 429)
- Session reuse after logout / expired token (v2 401)
- Dump endpoint locked by default (v2 404 without LAB_DUMP_ENABLED)
- Key swap after persistence (v2 blocking warning)
- Forged / expired / tampered Telegram initData (v2 401)
- XSS through username / message (v1 executes, v2 renders as text), checked statically or headless
Every new test must fail against the vulnerable path and pass against the fix. Never weaken or harden v1.
Run python attacks\run_all_attacks.py, extend the RESULTS.md commentary in the runner,
then /checkpoint "feat: new attack tests".
```
