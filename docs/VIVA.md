# Viva Preparation: Likely Questions and Short Answers

Each answer is meant to be said in under a minute. The file or test to point at is in brackets.

## 1. What does "end-to-end encrypted" mean in your project, and how do you prove the server can't read messages?
The message is encrypted in the sender's browser and only decrypted in the receiver's browser. The private keys are
made in the browser and never sent anywhere, so the server only ever has ciphertext. Proof: the "Dump server database"
attack copies the whole database file and finds no plaintext (`attacks/test_database_dump.py`), and in the app, the
lock line under each message shows exactly what the server received.

## 2. Walk us through how one message is encrypted.
1. Each user has an Ed25519 key (signing) and an X25519 key (key agreement).
2. Alice combines her X25519 private key with Bob's public key: both sides get the same shared secret without sending it.
3. From that secret and the message counter, a KDF (BLAKE2b) makes a key just for this message.
4. ChaCha20-Poly1305 encrypts the text with a random 12-byte nonce; the header (sender, recipient, counter, time) is
   "associated data", so it can't be changed either.
5. Alice signs the header and ciphertext with Ed25519. Bob checks the signature, then decrypts. Any change fails.
(`frontend/shared/crypto.js`, `docs/PROTOCOL.md`)

## 3. What stops a man-in-the-middle, for example a hacked server, from swapping keys?
Signatures alone don't, because the attacker can sign their own keys. Two things do:
- **Trust on first use:** the app remembers the first identity key it saw for each contact. If it changes, the chat turns
  red, sending is blocked, and incoming messages are held until the user reviews it.
- **Safety numbers:** a hash of both identity keys. Two people compare them in person or on a call; if they match,
  nobody is in the middle. (`attacks/test_mitm_key_swap.py` swaps keys in the server's database and checks the warning.)

## 4. What is a replay attack and how do you stop it?
Re-sending a captured message so it's accepted again ("pay 500" twice). Every message carries a counter inside the
signed header. The receiver drops anything at or below the last counter it saw. For pasted Telegram messages, which
can arrive in any order, the app remembers every counter it has opened. We check the signature first and the replay
second, so a changed copy is reported as tampering, not as a replay. (`test_replay_attack.py`, `test_telegram_view.py`)

## 5. How are passwords and logins protected?
- Passwords are hashed with Argon2id, which is slow and memory-hard on purpose, so guessing is expensive.
- Login gives a random 32-byte token; the database stores only its SHA-256 hash, so a stolen database has no usable tokens.
- Tokens expire after 24 hours and logout deletes them.
- The server takes "who you are" from the token, never from the request, and checks ownership.
- 5 wrong tries a minute → HTTP 429. Unknown user and wrong password give the same answer.
(`backend/app/auth.py`, `test_unauthorized_access.py`, `test_session_theft.py`)

## 6. How does the Telegram Mini App login work? Couldn't someone fake it?
Telegram gives the Mini App `initData` (who the user is), signed with a key derived from our bot token. The server
recomputes the HMAC-SHA256 over all fields, compares it in constant time, and refuses anything older than one hour.
Without the bot token you can't make a valid signature. We never trust `initDataUnsafe` from the page. Telegram users
get reserved `tg_` names that can't be registered with a password. (`backend/app/telegram_auth.py`, `test_telegram_auth.py`)

## 7. Why can't the bot just encrypt messages for the user? It would be easier.
Because then Telegram and our bot would see the message before it's encrypted. Anything typed to a bot travels to
Telegram's servers and to the bot as plain text. Also, the bot has no keys: the private keys are only on the users'
devices. So the message is typed and sealed inside the Mini App, on the phone, and only the `🔒SM2` ciphertext reaches
Telegram.

## 8. What does a sealed 🔒SM2 message contain, and what can Telegram learn from it?
It is the same signed and encrypted v2 envelope, base64url-encoded, with `channel: "telegram"` in the signed header so
it can't be pushed into the normal inbox. Telegram can't read or change it without detection. It does still see who
is in the chat, when, and roughly how long the message is (metadata).

## 9. Is this forward secrecy?
No, and we say so. Each message has its own key, but all keys come from one long-term shared secret. If someone saved
the ciphertext and later steals a private key, they can read those messages. Signal fixes this with the Double
Ratchet, which is our first item of future work.

## 10. Sensitive messages "disappear" — can the receiver still keep them?
Yes, if they really want to: take a photo of the screen, or modify their app. The timer, view-once and key wiping
protect against the server, a later device theft, and accidental keeping, not against a determined receiver. That's
why we call it "sensitive mode" and list it as a limit.

## 11. Where are the private keys stored, and what if the laptop is stolen?
In the browser's storage, but sealed with XChaCha20-Poly1305 under a key made from the password with Argon2id (a PIN
in the Mini App). Without the password the thief only has ciphertext. While the app is unlocked and open, the keys are
in memory, so a stolen unlocked laptop is still a risk.

## 12. How do you know your attack tests aren't just passing by accident?
Each test must see v1 break **and** v2 hold. We also broke v2 on purpose (removed the `initData` age check, removed the
hash check, added an `innerHTML` line) and the matching test turned red. The Telegram tests use a made-up bot token,
never the real one.

## 13. What would you change to make it public?
An always-on host with HTTPS end to end, a real database with backups, the bot in webhook mode, the v1 target and lab
endpoints switched off, rate limits that survive restarts, and a Content-Security-Policy header.
