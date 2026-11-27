# Frontend rules (frontend/ only)

Read the root `CLAUDE.md` first. Detailed conventions are in `.claude/skills/frontend-conventions/SKILL.md`.

| Folder | URL | Rule |
|---|---|---|
| `legacy-insecure/` | `/v1/` | Client v1. **Deliberately insecure. Only path fixes are allowed; never add security.** |
| `web/` | `/v2/` | Client v2. Hardened E2EE UI |
| `shared/` | `/shared/` | `crypto.js`, `dlp.js`, `vendor/libsodium.js`. Shared by v2, the Mini App and `attacks/crypto_helper.js` |
| `telegram-miniapp/` | `/miniapp/` (step 5) | Telegram Mini App. Reuses `/shared/` |

- Plain JS with no build step and no CDN (the only exception is Telegram's own `telegram-web-app.js` in the Mini App).
- Script order: `/shared/vendor/libsodium.js`, then `/shared/crypto.js`, then `/shared/dlp.js`, then `app.js`. Use absolute `/shared/` paths.
- Crypto only through `shared/crypto.js`. Any API change must keep `attacks/crypto_helper.js` working. Run the suite.
- **No `innerHTML` with dynamic data** in v2 or the Mini App. Use `textContent`/`createElement`. guard.mjs blocks it.
  `web/app.js` still has some (fixed in step 4), so the guard flags that file on every edit until then.
- The green "verified" tick appears only after manual fingerprint confirmation. A key change for a known contact means a blocking warning.
- UI text is honest: say what is protected and what isn't (metadata, endpoint compromise).
- Follow `contracts/API.md`. If you need a new field, change the contract first.
- After each change, run `python attacks\run_all_attacks.py`, then open `/v2/` in two tabs to smoke-test.
