# Step 5: Telegram bot + Mini App + initData check

```
/task 5. Use the telegram-expert agent and the telegram-miniapp skill.
Prerequisite (human): create the bot with @BotFather and fill secrets/.env (see secrets/README.md). Claude cannot read it.
1. contracts/API.md: add POST /api/telegram/auth first.
2. backend/app/telegram_auth.py: server-side initData HMAC validation (WebAppData key, sorted data-check-string,
   compare_digest, auth_date max age). Verify against core.telegram.org/bots/webapps before writing it.
3. backend/bot/: a minimal bot (/start sends a WebApp button to MINIAPP_URL). Token from os.environ only. Pin the dependencies.
4. frontend/telegram-miniapp/: index.html + app.js reusing /shared/ crypto. Mount it at /miniapp/ in backend/app/main.py.
5. Message content goes only through our E2EE API, never through the bot.
6. Ask red-teamer for forged/expired/tampered initData tests (with a test token generated inside the test).
7. Run python attacks\run_all_attacks.py, then /checkpoint "feat: telegram bot and mini app".
```
