# Frontend rules (frontend/ only)

Read the root `CLAUDE.md` first. Detailed conventions are in `.claude/skills/frontend-conventions/SKILL.md`.

| Folder | URL | Rule |
|---|---|---|
| `legacy-insecure/` | `/v1/` | Client v1. **Deliberately insecure. Only path fixes are allowed; never add security.** |
| `web/` | `/v2/` | Client v2. `index.html` + `app.css` + ES modules in `web/js/` (`app.js` auth/boot, `chat.js` contacts/send/receive, `vault.js` encrypted local storage, `api.js`, `dom.js`) |
| `landing/` | `/` | Home page (served by `main.py` with `FileResponse`) |
| `shared/` | `/shared/` | `crypto.js`, `dlp.js`, `ui.css` (design tokens + components, light/dark), `vendor/libsodium.js`. Shared by v2, the landing page, the Mini App and `attacks/crypto_helper.js` |
| `telegram-miniapp/` | `/tg/` (step 5) | Telegram Mini App. Reuses `/shared/` (including `ui.css`) |

- Plain JS with no build step and no CDN (the only exception is Telegram's own `telegram-web-app.js` in the Mini App).
- Script order: `/shared/vendor/libsodium.js`, then `/shared/crypto.js`, then `/shared/dlp.js`, then `app.js`. Use absolute `/shared/` paths.
- Crypto only through `shared/crypto.js`. Any API change must keep `attacks/crypto_helper.js` working. Run the suite.
- **No `innerHTML` with dynamic data** in v2 or the Mini App. Use the `el()` helper in `web/js/dom.js` (textContent only). guard.mjs blocks it.
- Design rules: colours only from the tokens in `shared/ui.css`; green/amber/red only for security states; SVG icons from the sprite
  in `index.html` (no emoji icons); sentence case; toasts and `<dialog>` instead of `alert()`/`prompt()`; respect reduced motion.
- Private keys, contacts, counters and history are stored only through `web/js/vault.js` (Argon2id + XChaCha20-Poly1305). Never write
  readable secrets or message text to localStorage.
- The green "verified" tick appears only after manual fingerprint confirmation. A key change for a known contact means a blocking warning.
- UI text is honest: say what is protected and what isn't (metadata, endpoint compromise).
- Follow `contracts/API.md`. If you need a new field, change the contract first.
- After each change, run `python attacks\run_all_attacks.py`, then open `/v2/` in two tabs to smoke-test.
