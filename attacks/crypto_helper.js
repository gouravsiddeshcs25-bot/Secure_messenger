/**
 * CLI Cryptographic Helper for Python Attack Scripts.
 * Leverages the exact same libsodium.js and crypto.js code used by Client v2.
 */

global.window = {};
global.self = global.window;
global.crypto = require('crypto').webcrypto;
window.crypto = global.crypto;

require('../frontend/shared/vendor/libsodium.js');
require('../frontend/shared/crypto.js');

const Crypto = window.Crypto;

async function main() {
    await Crypto.init();
    const action = process.argv[2];
    const input = process.argv[3] ? JSON.parse(process.argv[3]) : {};

    try {
        if (action === "generate_keys") {
            const keys = Crypto.generateUserKeys();
            console.log(JSON.stringify({
                identity_pub: keys.identity.publicKeyB64,
                identity_priv: Crypto.toBase64(keys.identity.privateKey),
                exchange_pub: keys.exchange.publicKeyB64,
                exchange_priv: Crypto.toBase64(keys.exchange.privateKey),
                key_signature: keys.keySignatureB64
            }));
        } else if (action === "verify_key_sig") {
            const valid = Crypto.verifyKeySignature(input.identity_pub, input.exchange_pub, input.key_signature);
            console.log(JSON.stringify({ valid }));
        } else if (action === "compute_fingerprint") {
            const fp = Crypto.computeFingerprint(input.pub_a, input.pub_b);
            console.log(JSON.stringify({ fingerprint: fp }));
        } else if (action === "encrypt") {
            const privEx = Crypto.fromBase64(input.sender_exchange_priv);
            const sharedSecret = Crypto.computeSharedSecret(privEx, input.recipient_exchange_pub);
            const msgKey = Crypto.deriveMessageKey(sharedSecret, input.counter);
            const privId = Crypto.fromBase64(input.sender_identity_priv);

            const header = {
                version: 2,
                sender: input.sender,
                recipient: input.recipient,
                counter: input.counter,
                timestamp: input.timestamp || Date.now(),
                is_sensitive: !!input.is_sensitive,
                ttl_seconds: input.ttl_seconds || 60,
                one_time_view: !!input.one_time_view,
                require_passphrase: !!input.require_passphrase
            };

            const env = Crypto.encryptEnvelope(privId, msgKey, input.plaintext, header);
            Crypto.scrub(msgKey);

            console.log(JSON.stringify({
                header,
                nonce: env.nonceB64,
                ciphertext: env.ciphertextB64,
                signature: env.signatureB64
            }));
        } else if (action === "decrypt") {
            const privEx = Crypto.fromBase64(input.recipient_exchange_priv);
            const sharedSecret = Crypto.computeSharedSecret(privEx, input.sender_exchange_pub);
            const msgKey = Crypto.deriveMessageKey(sharedSecret, input.header.counter);

            const plaintext = Crypto.decryptEnvelope(
                input.sender_identity_pub,
                msgKey,
                input.nonce,
                input.ciphertext,
                input.header,
                input.signature
            );
            Crypto.scrub(msgKey);

            console.log(JSON.stringify({ status: "success", plaintext }));
        } else {
            console.error(JSON.stringify({ status: "error", error: "Unknown action" }));
            process.exit(1);
        }
    } catch (err) {
        console.log(JSON.stringify({ status: "error", error: err.message }));
    }
}

main();
