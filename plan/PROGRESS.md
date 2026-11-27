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
- Step 5 (C) done, checked by the user on a real phone (2026-11-27): `/api/tg/auth` (initData HMAC check), `/api/tg/share`, bot in `backend/bot/bot.py`,
  Mini App at `/tg/` = the v2 client signed in through Telegram with a PIN. "Seal for Telegram" / "Open a 🔒SM2 message" in both apps.
  Real run: sealed in the Mini App, sent through WhatsApp, opened in the web app as another user; safety numbers matched.
- Phone layout fixed (chat no longer runs off the right edge; checked at 320/360/412 px).
- Attack suite: **8/8 PASS** (added Forged Telegram login, Telegram reads the chat). Earlier: 6/6. MITM test now does a real server-side key swap after first contact.
- Browser end-to-end check (Playwright + Edge, two users): register, chat both ways, verify, reload keeps history,
  sensitive reveal/burn, key change blocks sending, accept and deliver again. No console errors.

## Last checkpoint
- 2026-11-27 · `upgrades` · step 5 ticked after the phone check, phone layout fix. Suite 8/8 PASS.
- 2026-11-27 · `upgrades` · feat: CipherBridge Telegram bot and Mini App. Suite 8/8 PASS (step 5 not ticked until tested in real Telegram).
- 2026-11-27 · `upgrades` · fix: two-tab message loss + landing polish. Suite 6/6 PASS.
- 2026-11-27 · `upgrades` · feat: redesigned v2 client with persisted keys and key-change warning. Suite 6/6 PASS.

## Next step
Presentation on 2026-11-28, run from the laptop (server + `cloudflared tunnel --protocol http2` + bot).
Before it: one-command launcher, `docs/DEMO.md` (demo script), `docs/VIVA.md` (likely questions), demo seed users.
After it: step 6 (more attack tests), 7 (report), 9 (public deployment).

## Known issues
- In-memory rate limiter resets on restart; behind cloudflared all users share one IP (per-username login limit still protects accounts).
- Keys live in one browser. Signing in on another browser makes new keys (with a warning), and contacts see "key changed".
- Sensitive messages not opened before a reload are lost on this device (they still expire on the server).
- The cloudflared quick-tunnel address changes on every restart; then `MINIAPP_URL` must be updated and the bot restarted.
  QUIC (UDP) is blocked on the user's network: use `--protocol http2`.
- A copied initData string works for up to 1 hour (documented in THREAT_MODEL).
- Only one tab per account at a time: opening a second tab signs the first one out (by design, keeps the vault consistent).

## Ideas / later
- One-tap "Open" button under every sealed Telegram message: the server keeps the sealed text under a short id (still only
  ciphertext), the button opens the Mini App with that id and decrypts on the receiver's phone. No forwarding or pasting.
- Seal from inside any chat: `@botname` -> Seal a message -> the sealed text is posted back into that same chat.
  The text is still typed in the Mini App, never in Telegram's own box (an inline query reaches Telegram and the bot as plaintext).
- Bigger: an Android keyboard or a browser extension (WhatsApp Web / Telegram Web) that seals before the app sees the text.
- Public deployment (TASKS step 9): an always-on host (Render/Railway/Fly), not Vercel; v1 and lab endpoints off.

## Handoff
(Filled by `/handoff`.)
