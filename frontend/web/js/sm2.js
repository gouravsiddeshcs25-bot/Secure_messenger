// The 🔒SM2 text format: a sealed message that can be pasted into any Telegram chat (or anywhere else).
//
//   🔒SM2:<base64url of the JSON envelope>
//
// The envelope is exactly the v2 envelope ({header, nonce, ciphertext, signature}), with one extra header
// field: channel = "telegram". That field is inside the signed, authenticated header, so a pasted message
// can't be slipped into the server inbox and an inbox message can't be passed off as a pasted one.
// Telegram (and our server) only ever see the scrambled string. Only the recipient's keys can open it.

export const PREFIX = "\u{1F512}SM2:";
export const CHANNEL = "telegram";
export const MAX_TEXT_CHARS = 1500;   // keeps the whole string under Telegram's 4096-character message limit
export const MAX_SEALED_CHARS = 4000;

export function encode(envelope) {
    const bytes = Crypto.sodium.from_string(JSON.stringify(envelope));
    return PREFIX + Crypto.sodium.to_base64(bytes, Crypto.sodium.base64_variants.URLSAFE_NO_PADDING);
}

// Finds a 🔒SM2 string inside pasted text (people often copy a few extra words) and returns the envelope.
// Throws an Error with a plain-language message if it isn't one.
export function decode(text) {
    const raw = String(text || "").trim();
    const at = raw.indexOf("SM2:");
    if (at < 0) throw new Error("That isn't a 🔒SM2 message. It should start with 🔒SM2:");
    const body = raw.slice(at + 4).match(/^[A-Za-z0-9_-]+/);
    if (!body) throw new Error("The 🔒SM2 message is empty or cut off. Copy the whole message.");
    let env;
    try {
        const bytes = Crypto.sodium.from_base64(body[0], Crypto.sodium.base64_variants.URLSAFE_NO_PADDING);
        env = JSON.parse(Crypto.sodium.to_string(bytes));
    } catch (e) {
        throw new Error("The 🔒SM2 message is damaged or cut off. Copy the whole message again.");
    }
    const h = env && env.header;
    if (!h || h.version !== 2 || h.channel !== CHANNEL || typeof env.nonce !== "string"
        || typeof env.ciphertext !== "string" || typeof env.signature !== "string") {
        throw new Error("The 🔒SM2 message is not in the expected format.");
    }
    return env;
}
