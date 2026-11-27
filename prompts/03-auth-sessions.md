# Step 3: Accounts, sessions, ownership, rate limits, locked dump

```
/task 3. Read backend/CLAUDE.md and the backend-conventions skill first.
1. Update contracts/API.md "Planned (step 3)" into the real contract (endpoints, headers, error codes) and add examples.
2. Create backend/app/auth.py:
   - Argon2id password hashing (PyNaCl nacl.pwhash.argon2id or argon2-cffi; pin it in backend/requirements.txt;
     verify the API with the verify-before-use skill).
   - Session tokens: secrets.token_urlsafe(32), stored hashed with an expiry, compared with hmac.compare_digest.
   - A FastAPI dependency current_user() that reads "Authorization: Bearer".
   - A simple in-memory rate limiter (per IP + username) on login/register/send that returns 429.
3. Add the users.password_hash and sessions tables in database.py (migrate safely; the DB is in backend/data/).
4. Ownership: v2 reads/deletes of /api/messages/* return 403 unless the session owns them. v1 keeps its
   unauthenticated path, because v1 must stay insecure. Document how the two paths are told apart.
5. /api/dump/messages returns 404 unless LAB_DUMP_ENABLED=1. Make the dump attack test and the runner enable it
   for the lab run only.
6. Update frontend/web to log in and send the token (coordinate through contracts/API.md).
7. Ask test-writer for tests covering IDOR, brute-force 429, expired/invalid tokens and dump locked by default.
8. Run python attacks\run_all_attacks.py (all must pass), then the security-reviewer agent,
   then /checkpoint "feat: argon2id auth and sessions".
```
