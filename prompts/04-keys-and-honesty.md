# Step 4: Persisted keys, key-change warning, green tick, honest wording

```
/task 4. Read frontend/CLAUDE.md and the crypto-rules skill first.
1. Persist the identity keypair in IndexedDB, with the secret key wrapped by a passphrase
   (crypto_pwhash then crypto_secretbox from frontend/shared/vendor/libsodium.js). Reload means the same identity.
2. Persist known contacts' identity keys and replay counters. If a known contact's identity key changes, show a
   blocking warning and render none of their messages until the user accepts the new fingerprint.
3. Fix the green "verified" tick so it only appears after the user manually confirms the fingerprint. Store that per contact.
4. Replace every innerHTML that takes dynamic data in frontend/web/app.js with textContent/createElement
   (guard.mjs blocks edits to the file until this is done).
5. Honest wording across the v2 UI and README: state what is protected and its limits (metadata is visible, endpoint compromise).
6. attacks/crypto_helper.js must still work with any crypto.js API change.
7. Ask crypto-auditor to review, then test-writer to add a "key swap after persistence" test.
8. Run python attacks\run_all_attacks.py, then /checkpoint "feat: persisted keys and key-change warning".
```
