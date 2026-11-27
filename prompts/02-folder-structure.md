# Step 2: Team folder structure

```
Verify the team folder structure is complete and nothing broke.
- The layout matches CLAUDE.md: .claude/, secrets/, plan/, contracts/, backend/app, backend/data (ignored),
  frontend/shared, frontend/web, frontend/legacy-insecure, attacks/, docs/, prompts/, scripts/.
- git log --follow works on backend/app/main.py and frontend/shared/crypto.js (history kept).
- /v1/, /v2/ and /shared/crypto.js return 200. python attacks\run_all_attacks.py gives 5/5 PASS.
- git check-ignore confirms secrets/.env, backend/data/messenger.db and .claude/settings.local.json are ignored,
  and that secrets/.env.example and secrets/README.md are not.
Then run /checkpoint "chore: team folder structure".
```
