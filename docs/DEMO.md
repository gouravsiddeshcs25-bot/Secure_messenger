# Demo Script (about 6 minutes)

The story: **v1 falls to each attack, v2 holds, and CipherBridge brings the same protection into Telegram.**

## Before the presentation (15 minutes before)

1. **Laptop:** plugged in, and set to never sleep (Settings → System → Power → "When plugged in, put my device to
   sleep after: Never"). `secrets\.env` has `TELEGRAM_BOT_TOKEN` and **no** `LAB_MODE=1`.
2. **Start everything** in one terminal from the project folder:
   ```powershell
   cd D:\Secure_Messenger
   python scripts\run_demo.py
   ```
   Wait for `[demo] all running`. Leave this window open for the whole presentation.
3. **Seed the v1 example** in a second terminal: `python scripts\demo_seed.py`.
4. **Open these, ready to switch between:**
   - Browser 1: http://127.0.0.1:8000/ (home page), plus a tab with http://127.0.0.1:8000/api/v1/messages/bob_v1demo
   - Browser 1, another tab: http://127.0.0.1:8000/v2/ signed in as **ishan**
   - Browser 2 (or a private window): http://127.0.0.1:8000/v2/ signed in as a second account, for example **harshit_khetan**
   - Phone: Telegram → your bot → **Open CipherBridge**, PIN entered, chat with **ishan** open
   - WhatsApp Web on the laptop (to receive the sealed text)
5. **Run the attack suite once** (second terminal) so you know it is green: `python attacks\run_all_attacks.py` → 10/10 PASS.
6. Have [RESULTS.md](RESULTS.md) printed or open as a backup.

## The demo

### 1. The idea (30 s) — home page
"Two messengers on one server. v1 is how a naive app works. v2 is what we built. We attack both with the same scripts."

### 2. v1 falls (1 min) — tab with `/api/v1/messages/bob_v1demo`
- Refresh the tab. "No login, no password. Anyone who knows Bob's name gets his inbox: the wifi password, a full card
  number, a bank OTP. And it's stored like this in the database too."

### 3. v2 holds (2 min) — the two v2 browsers
1. Send a message from one account to the other. It appears on the other side.
2. Click the small lock line under the message (**Sent encrypted**). It opens "How this message was protected". "This is exactly what the server received: a counter, a nonce
   and ciphertext. The server never had the key."
3. Click the **Not verified** chip. "Both screens show the same safety number. If someone swapped keys in the middle,
   the numbers would differ, and our app would turn the chat red and block sending."
4. Turn on **Sensitive**, choose **30 s**, send it. Reveal it on the other side and let it burn. "View once, a timer,
   and the key is wiped. The server deletes it as well."
5. Optional: type `4111 1111 1111 1111` — Sensitive switches on by itself (DLP).

### 4. CipherBridge (1.5 min) — phone + laptop
1. On the phone, in the chat with ishan, type a message and tap the **seal** button (next to Send). Tap **Copy**.
2. Send it to yourself on **WhatsApp**. Show it on WhatsApp Web: "WhatsApp only sees `🔒SM2:` gibberish."
3. On the laptop as **ishan**: **Open a 🔒SM2 message** → paste → **Open**. The real message appears.
4. Paste the **same** text again → *"Replay blocked: you already opened message number …"*.
5. Change one letter in the middle of the text and paste → refused (*"failed its tamper check"* or *"damaged"*,
   depending on where the change lands). "Nobody can change a sealed message without us noticing."
6. One line: "The bot never sees the message. It has no keys; the phone locks the message before Telegram gets it."

### 5. All ten attacks (1 min) — terminal
Run `python attacks\run_all_attacks.py`, or show the result you ran before. Point at two rows:
- **MITM swaps keys:** v1 "succeeds silently", v2 "key change detected".
- **Reuse old/stolen session:** v1 "no session needed", v2 "old/stolen token refused".

"Each row runs a real attack against both versions. A test only passes if v1 breaks *and* v2 holds."

### 6. Limits and next steps (30 s)
- "Not forward secrecy yet: that needs a Double Ratchet."
- "Telegram still sees who talks to whom, just not what."
- "Next: deploy it publicly, a one-tap Open button in Telegram, and a keyboard that seals in any app."

## If something goes wrong
| Problem | Fix |
| :--- | :--- |
| Mini App won't load | The tunnel or laptop stopped. Ctrl+C the launcher and run `python scripts\run_demo.py` again (the bot gets the new address by itself). Reopen the Mini App. |
| "Telegram login is not set up" | The token is missing in `secrets\.env`. Add it and restart the launcher. |
| No internet at all | Skip part 4: show the web parts on `127.0.0.1` (they don't need the internet), and the printed RESULTS.md. |
| Port 8000 already in use | An old server is still running. Close that terminal, or restart the laptop's terminal windows, then start again. |
| Attack suite shows a FAIL for the dump endpoint | `LAB_MODE=1` is set in `secrets\.env`. Remove it and restart. |
| Black screen / endless loading in Telegram | You tapped an old button with a dead tunnel address. Send `/start` to the bot and use the new button (or the menu button). |
| Mini App asks to create a new PIN | The tunnel address changed, and the phone keeps the keys per address. Create a PIN (new keys), then in the web app accept the key change for your Telegram account and compare safety numbers again. To avoid it: don't restart `run_demo.py` between the rehearsal and the presentation. |
| Phone layout looks old | Close Telegram fully and reopen it (it keeps an old copy). |
