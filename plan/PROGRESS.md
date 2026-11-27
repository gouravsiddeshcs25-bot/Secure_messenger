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
- Step 5 (C) built, waiting for the real-Telegram check: `/api/tg/auth` (initData HMAC check), `/api/tg/share`, bot in `backend/bot/bot.py`,
  Mini App at `/tg/` = the v2 client signed in through Telegram with a PIN. "Seal for Telegram" / "Open a 🔒SM2 message" in both apps.
- Attack suite: **8/8 PASS** (added Forged Telegram login, Telegram reads the chat). Earlier: 6/6. MITM test now does a real server-side key swap after first contact.
- Browser end-to-end check (Playwright + Edge, two users): register, chat both ways, verify, reload keeps history,
  sensitive reveal/burn, key change blocks sending, accept and deliver again. No console errors.

## Last checkpoint
- 2026-11-27 · `upgrades` · feat: CipherBridge Telegram bot and Mini App. Suite 8/8 PASS (step 5 not ticked until tested in real Telegram).
- 2026-11-27 · `upgrades` · fix: two-tab message loss + landing polish. Suite 6/6 PASS.
- 2026-11-27 · `upgrades` · feat: redesigned v2 client with persisted keys and key-change warning. Suite 6/6 PASS.

## Next step
Finish step 5 by hand: BotFather token + cloudflared tunnel in `secrets/.env`, run the bot, test on a phone (README "CipherBridge: Telegram Setup").
Then step 6 (more attack tests) or D (final security pass).

## Known issues
- In-memory rate limiter resets on restart; behind cloudflared all users share one IP (per-username login limit still protects accounts).
- Keys live in one browser. Signing in on another browser makes new keys (with a warning), and contacts see "key changed".
- Sensitive messages not opened before a reload are lost on this device (they still expire on the server).
- Not yet tried in real Telegram: `shareMessage` (needs Bot API 8.0 and maybe inline mode on), the t.me share-link fallback, and
  how long a Decrypt-button URL may be (the bot falls back to "paste it" above 2048 characters).
- A copied initData string works for up to 1 hour (documented in THREAT_MODEL).
- Only one tab per account at a time: opening a second tab signs the first one out (by design, keeps the vault consistent).

## Ideas / later
- (none yet)

## Handoff
(Filled by `/handoff`.)
