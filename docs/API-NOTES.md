# API notes (things we checked before using them)

## PyNaCl Argon2id (`nacl.pwhash.argon2id`): checked 2026-11-27 with PyNaCl 1.6.2
Checked by running it in the project `.venv`:
- `nacl.pwhash.argon2id.str(password: bytes, opslimit=..., memlimit=...)` returns `bytes` like
  `b'$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>'`. The string carries its own random salt and settings, so we store it as is.
- `nacl.pwhash.argon2id.verify(hash: bytes, password: bytes)` returns `True` on a match and **raises
  `nacl.exceptions.InvalidkeyError`** on a wrong password (it does not return False).
- We use `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE` (64 MiB, 2 passes), which is libsodium's preset for online logins.
- Used in `backend/app/auth.py`.

## Python stdlib used for sessions
- `secrets.token_urlsafe(32)`: 32 random bytes from the OS, encoded as about 43 URL-safe characters.
- `hashlib.sha256(...).hexdigest()`: only this hash of the token is stored in the `sessions` table.
- `hmac.compare_digest(a, b)`: constant-time string comparison.

## SQLite read-only open (attack lab)
- `sqlite3.connect(Path(p).resolve().as_uri() + "?mode=ro", uri=True)` opens the DB read-only (on Windows the URI
  is `file:///D:/...`). Used by `read_db_messages()` in `attacks/client_sim.py` to simulate a stolen database.
