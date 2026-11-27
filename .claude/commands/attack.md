---
description: Run the attack suite (or one attack) and explain the result.
argument-hint: [optional: mitm | replay | tamper | dump | expired | <new test name>]
---
Target: $ARGUMENTS

- With no argument, run `python attacks\run_all_attacks.py` (bash: `python attacks/run_all_attacks.py`).
  It starts `python -m uvicorn backend.app.main:app` itself if nothing is listening on port 8000.
- With an argument, run only the matching module:
  `python -c "import sys; sys.path.insert(0,'attacks'); import test_<name> as t; print(t.run())"`
  (start the server first if needed: `python -m uvicorn backend.app.main:app --port 8000`).

Then report:
1. The results table (v1 expected/actual, v2 expected/actual, PASS/FAIL).
2. For each FAIL: which side broke, the likely cause (read the test and the code it hits), and the smallest fix.
   A v1 attack that *stops working* is also a failure, because v1 must stay insecure.
3. Never edit `docs/RESULTS.md` by hand. The runner regenerates it.
