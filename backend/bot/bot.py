"""
CipherBridge Telegram bot.

What it does:
- /start and /help: a short explanation and a button that opens the Mini App.
- Sets the chat menu button to open the Mini App, so it's always one tap away.
- When you forward or paste a 🔒SM2 message to the bot, it replies with a "Decrypt" button that opens the
  Mini App with that message filled in.
- Inline mode (type @YourBot in any chat): shows a button that opens the Mini App.

What it never does: decrypt anything or see readable messages. Bot chats are NOT end-to-end encrypted, so the
bot only ever handles 🔒SM2 ciphertext. Decryption happens inside the Mini App, with keys only the user has.

Run it (from the repo root, with the virtual environment active):
    python backend\\bot\\bot.py

Settings come from secrets/.env: TELEGRAM_BOT_TOKEN and MINIAPP_URL (the https tunnel URL ending in /tg/).
Bot API docs: https://core.telegram.org/bots/api and https://docs.python-telegram-bot.org/en/v22.8/
"""

import logging
import os
import sys
import urllib.parse

from telegram import (InlineKeyboardButton, InlineKeyboardMarkup, InlineQueryResultsButton,
                      MenuButtonWebApp, Update, WebAppInfo)
from telegram.ext import (Application, CommandHandler, ContextTypes, InlineQueryHandler,
                          MessageHandler, filters)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SM2_PREFIX = "\U0001F512SM2:"
MAX_BUTTON_URL = 2048   # keep "Decrypt" links short enough for every Telegram app; longer ones open empty

# Load secrets/.env (never committed). Values are read from the environment only.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(REPO_ROOT, "secrets", ".env"))
except ImportError:
    pass

# python-telegram-bot logs every request URL at DEBUG level, and the URL contains the bot token.
# Keep the HTTP libraries quiet so the token never ends up in a log.
logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
for noisy in ("httpx", "httpcore", "telegram.ext.ExtBot", "telegram.Bot"):
    logging.getLogger(noisy).setLevel(logging.WARNING)
log = logging.getLogger("cipherbridge")


def miniapp_url() -> str:
    return os.environ.get("MINIAPP_URL", "").strip()


def open_button(text: str = "Open CipherBridge", url: str = "") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(text, web_app=WebAppInfo(url=url or miniapp_url()))]])


START_TEXT = (
    "CipherBridge adds end-to-end encryption on top of Telegram.\n\n"
    "Write a message in CipherBridge and tap Seal for Telegram. You get a 🔒SM2 text that you can paste "
    "into any chat. Telegram (and this bot) only see scrambled text; only the person you sealed it for can open it.\n\n"
    "Got a 🔒SM2 message? Forward it here and tap Decrypt."
)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(START_TEXT, reply_markup=open_button())


async def sealed_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Someone forwarded or pasted a 🔒SM2 text. Offer to open it in the Mini App. Never decrypt here."""
    text = update.effective_message.text or ""
    start_at = text.find("SM2:")
    body = text[start_at + 4:].split()[0] if start_at >= 0 and text[start_at + 4:].strip() else ""
    url = miniapp_url()
    if body:
        joiner = "&" if "?" in url else "?"
        candidate = url + joiner + "m=" + urllib.parse.quote(body, safe="")
        if len(candidate) <= MAX_BUTTON_URL:
            url = candidate
    note = ("This is a sealed CipherBridge message. Telegram and this bot can only see the scrambled text.\n"
            + ("Tap Decrypt to open it." if url != miniapp_url()
               else "It's too long for a button: open CipherBridge, tap Open a 🔒SM2 message and paste it."))
    await update.effective_message.reply_text(note, reply_markup=open_button("Decrypt", url))


async def other_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "Please don't send readable messages here: bot chats are not end-to-end encrypted. "
        "Open CipherBridge to write one.", reply_markup=open_button())


async def inline_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Typing @bot in any chat shows a button that opens CipherBridge."""
    await update.inline_query.answer(
        results=[],
        cache_time=60,
        is_personal=True,
        button=InlineQueryResultsButton(text="Seal a message with CipherBridge", web_app=WebAppInfo(url=miniapp_url())),
    )


async def post_init(app: Application):
    # The menu button next to the message box opens the Mini App in every private chat with the bot.
    await app.bot.set_chat_menu_button(menu_button=MenuButtonWebApp(text="CipherBridge", web_app=WebAppInfo(url=miniapp_url())))
    me = await app.bot.get_me()
    log.info("CipherBridge bot @%s is running. Mini App: %s", me.username, miniapp_url())


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        sys.exit("TELEGRAM_BOT_TOKEN is missing. Put it in secrets/.env (see secrets/README.md).")
    if not miniapp_url().startswith("https://"):
        sys.exit("MINIAPP_URL must be an https:// address ending in /tg/ (Telegram only opens https Mini Apps).")

    app = Application.builder().token(token).post_init(post_init).build()
    app.add_handler(CommandHandler(["start", "help"], start))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"SM2:"), sealed_message))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, other_message))
    app.add_handler(InlineQueryHandler(inline_query))
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
