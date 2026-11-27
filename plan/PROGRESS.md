# Progress

## Current state
- Branch: `upgrades`
- Step 3 (A) done: Argon2id accounts, hashed session tokens, `require_user`, ownership checks, rate limits, dump behind `LAB_MODE=1`,
  v1 on `/api/v1` (can't touch v2 accounts).
- Step 4 (B) done together with a full frontend redesign:
  - New design system `frontend/shared/ui.css` (light + dark, tokens, SVG icon sprite, no emoji/gradients), approved by the user via a preview.
  - v2 rewritten as ES modules in `frontend/web/js/` (app, chat, vault, api, dom). Sidebar chats, user search, safety-number dialog,
    "How this message was protected" dialog, sensitive cards with countdown ring / reveal / burn, toasts and dialogs instead of alerts.
  - Keys persist per browser, sealed with Argon2id + XChaCha20-Poly1305 (`vault.js`); contacts, counters and history too.
  - Trust on first use: key change -> red banner, sending blocked, incoming held until the user reviews; "Verified" only after confirming.
  - Home page at `/` (`frontend/landing/index.html`).
  - Honest wording: "per-message keys", not forward secrecy; nonce is 12 bytes.
- Attack suite: **6/6 PASS**. MITM test now does a real server-side key swap after first contact.
- Browser end-to-end check (Playwright + Edge, two users): register, chat both ways, verify, reload keeps history,
  sensitive reveal/burn, key change blocks sending, accept and deliver again. No console errors.

## Last checkpoint
- 2026-11-27 · `upgrades` · feat: redesigned v2 client with persisted keys and key-change warning. Suite 6/6 PASS.

## Next step
Step 5 (C): Telegram bot + Mini App + initData check (`prompts/05-telegram.md`). Reuse `frontend/shared/ui.css` and `crypto.js`.

## Known issues
- In-memory rate limiter resets on restart; behind cloudflared all users share one IP (per-username login limit still protects accounts).
- Keys live in one browser. Signing in on another browser makes new keys (with a warning), and contacts see "key changed".
- Sensitive messages not opened before a reload are lost on this device (they still expire on the server).

## Ideas / later
- (none yet)

## Handoff
(Filled by `/handoff`.)
