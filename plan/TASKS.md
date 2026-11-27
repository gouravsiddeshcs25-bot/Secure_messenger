# Tasks

Tick a step only when it is fully done and `python attacks/run_all_attacks.py` passes. `/checkpoint` does this.
Each step has a ready prompt in `prompts/`.

- [x] 1. Base project runs and 5 attacks pass (`prompts/01-base-project.md`)
- [x] 2. Folder structure (`prompts/02-folder-structure.md`)
- [x] 3. Argon2id login, session tokens, ownership checks, rate limiting, locked dump endpoint (`prompts/03-auth-sessions.md`)
- [x] 4. Persisted keys, key-change warning, fix green tick, honest wording (`prompts/04-keys-and-honesty.md`)
- [x] 5. Telegram bot + Mini App + initData check (`prompts/05-telegram.md`)
- [x] 6. New attack tests (`prompts/06-attack-tests.md`)
- [x] 7. Docs and report (`prompts/07-docs-report.md`)
- [ ] 8. Demo prep (`prompts/08-demo-prep.md`): launcher, seed, DEMO.md, VIVA.md and clean-clone dry run done; left: the user's screen recording + printed RESULTS.md
- [ ] 9. Public deployment: v2 + Mini App + bot online for anyone (after 6-8). v1 and lab endpoints off in public; real database with backups; bot in webhook mode; hosting choice TBD (Render/Railway/Fly vs Vercel + hosted Postgres); teacher suggested Floci (free local AWS emulator, Docker, port 4566) to build and test the AWS parts locally first: S3 for encrypted backups, DynamoDB for sessions/rate limits, Secrets Manager for the bot token, SES for reset emails
- [ ] 10. Email + forgot password: verified email at sign-up, single-use hashed reset links (30 min), same answer for unknown accounts, all sessions ended on reset, optional recovery key so a reset keeps keys/history; attack tests for token guessing/reuse/expiry/enumeration (after the presentation, with step 9)
