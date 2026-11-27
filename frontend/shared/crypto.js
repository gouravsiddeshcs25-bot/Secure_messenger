/**
 * Cryptographic Subsystem for Secure Messenger v2.
 * 
 * DESIGN PRINCIPLES & CRYPTO RULES:
 * 1. Proven primitives only via libsodium: No invented or home-rolled algorithms.
 * 2. Identity & Authentication: Ed25519 (crypto_sign) for long-term user signing keys.
 *    - WHY: Binds every message and exchange key to an immutable identity.
 * 3. Key Exchange: X25519 (crypto_kx / crypto_scalarmult) for Diffie-Hellman secret agreement.
 *    - WHY: Provides 128-bit post-computation curve security without transmitting private keys.
 * 4. Out-of-band Verification: Deterministic safety number / fingerprint computed over
 *    lexicographically ordered public identity keys.
 *    - WHY: Alice and Bob can compare fingerprints over a voice/in-person channel to detect MITM key swaps.
 * 5. Per-Message Keys: Key Derivation Function (crypto_kdf_derive_from_key).
 *    - WHY: Each message uses its own 256-bit key derived from the shared secret + counter, so one leaked
 *      message key does not reveal other message keys.
 *    - LIMIT: every message key comes from the same shared secret. Anyone who steals that secret (or a private
 *      key) can derive all of them. This is NOT forward secrecy; a Double Ratchet would add that (future work).
 * 6. Authenticated Encryption: ChaCha20-Poly1305 IETF (crypto_aead_chacha20poly1305_ietf).
 *    - WHY: Provides 256-bit encryption with a 128-bit authentication tag covering both ciphertext
 *      and message header (associated data). Any server or network tampering immediately fails decryption.
 * 7. Local key storage: Argon2id (crypto_pwhash) turns the password into a storage key, and
 *    XChaCha20-Poly1305 encrypts private keys and chat history before they go into localStorage.
 *    - WHY: Memory-hard hashing slows down GPU brute-forcing if someone copies the browser's storage.
 * 8. Zeroization: libsodium.memzero() immediately clears sensitive key material from memory.
 */

const Crypto = {
    // Reference to ready libsodium instance
    sodium: null,

    /**
     * Initializes libsodium asynchronously.
     */
    async init() {
        if (this.sodium) return this.sodium;
        if (!window.sodium) {
            throw new Error("libsodium vendor script not loaded.");
        }
        await window.sodium.ready;
        this.sodium = window.sodium;
        return this.sodium;
    },

    /**
     * Converts Uint8Array to URL-safe / standard Base64 string.
     */
    toBase64(bytes) {
        return this.sodium.to_base64(bytes, this.sodium.base64_variants.ORIGINAL);
    },

    /**
     * Converts Base64 string to Uint8Array.
     */
    fromBase64(b64Str) {
        return this.sodium.from_base64(b64Str, this.sodium.base64_variants.ORIGINAL);
    },

    /**
     * Generates a complete user key bundle:
     * - Ed25519 identity keypair (for signatures)
     * - X25519 exchange keypair (for Diffie-Hellman key agreement)
     * - Signature of the exchange public key using the identity private key
     * 
     * WHY: Prevents an adversary from replacing Bob's exchange key with their own
     * while retaining Bob's public identity.
     */
    generateUserKeys() {
        const s = this.sodium;
        const identityKeypair = s.crypto_sign_keypair();
        const exchangeKeypair = s.crypto_kx_keypair();

        // Sign the exchange public key with identity private key
        const keySignature = s.crypto_sign_detached(
            exchangeKeypair.publicKey,
            identityKeypair.privateKey
        );

        return {
            identity: {
                publicKey: identityKeypair.publicKey,
                privateKey: identityKeypair.privateKey,
                publicKeyB64: this.toBase64(identityKeypair.publicKey)
            },
            exchange: {
                publicKey: exchangeKeypair.publicKey,
                privateKey: exchangeKeypair.privateKey,
                publicKeyB64: this.toBase64(exchangeKeypair.publicKey)
            },
            keySignatureB64: this.toBase64(keySignature)
        };
    },

    /**
     * Verifies that an exchange public key was genuinely signed by the corresponding identity key.
     * Returns true if valid, false if tampered or forged.
     */
    verifyKeySignature(identityPubkeyB64, exchangePubkeyB64, signatureB64) {
        const s = this.sodium;
        try {
            const idPub = this.fromBase64(identityPubkeyB64);
            const exPub = this.fromBase64(exchangePubkeyB64);
            const sig = this.fromBase64(signatureB64);
            return s.crypto_sign_verify_detached(sig, exPub, idPub);
        } catch (e) {
            return false;
        }
    },

    /**
     * Computes a deterministic Safety Number / Fingerprint for two participants.
     * Public keys are sorted lexicographically so both Alice and Bob compute
     * the exact same fingerprint regardless of who initiates the conversation.
     * 
     * Returns a human-readable 6-chunk string: "1234 5678 9012 3456 7890 1234"
     */
    computeFingerprint(identityPubkeyA_B64, identityPubkeyB_B64) {
        const s = this.sodium;
        const keys = [identityPubkeyA_B64, identityPubkeyB_B64].sort();
        const combined = s.from_string(keys[0] + ":" + keys[1]);
        const hash = s.crypto_generichash(32, combined);

        // Convert the first 12 bytes of the hash into a 24-digit formatted string
        let numStr = "";
        for (let i = 0; i < 12; i++) {
            numStr += ("0" + hash[i]).slice(-2);
        }
        // Format into chunks of 4 digits
        return numStr.match(/.{1,4}/g).join(" ");
    },

    /**
     * Computes X25519 Diffie-Hellman Shared Secret:
     * K = crypto_scalarmult(myExchangePrivKey, peerExchangePubKey)
     */
    computeSharedSecret(myExchangePrivKey, peerExchangePubKeyB64) {
        const s = this.sodium;
        const peerPub = this.fromBase64(peerExchangePubKeyB64);
        return s.crypto_scalarmult(myExchangePrivKey, peerPub);
    },

    /**
     * Derives a dedicated 256-bit per-message key from the master shared secret.
     * Uses libsodium's BLAKE2b-based KDF with an 8-character context string and counter.
     * 
     * WHY: Each message gets its own key. Leaking message key N does not expose key N-1 or N+1
     * (but leaking the shared secret exposes all of them; see the header comment).
     */
    deriveMessageKey(sharedSecret, counter) {
        const s = this.sodium;
        const context = "MsgKey__"; // Exactly 8 bytes required by crypto_kdf
        return s.crypto_kdf_derive_from_key(32, counter, context, sharedSecret);
    },

    /**
     * Encrypts message plaintext with Authenticated Encryption (AEAD):
     * - Primitive: ChaCha20-Poly1305 (IETF variant)
     * - Associated Data (AD): JSON-serialized header (counter, timestamps, sender, recipient, flags)
     * - Returns: { ciphertextB64, nonceB64, signatureB64 }
     * 
     * WHY AEAD: The Poly1305 MAC tag authenticates BOTH the ciphertext AND the unencrypted header.
     * If an attacker modifies the counter, timestamp, or payload, decryption fails with an error.
     */
    encryptEnvelope(myIdentityPrivKey, messageKey, plaintextStr, headerObj) {
        const s = this.sodium;
        // Random 12-byte nonce (crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12).
        // Every message also has its own key, so a nonce is never reused with the same key.
        const nonce = s.randombytes_buf(s.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
        const headerBytes = s.from_string(JSON.stringify(headerObj));
        const plaintextBytes = s.from_string(plaintextStr);

        // Encrypt with ChaCha20-Poly1305 AEAD
        const ciphertextBytes = s.crypto_aead_chacha20poly1305_ietf_encrypt(
            plaintextBytes,
            headerBytes,
            null,
            nonce,
            messageKey
        );

        // Sign (header || ciphertext) with sender's Ed25519 identity key
        const signPayload = s.from_string(JSON.stringify(headerObj) + "|" + this.toBase64(ciphertextBytes));
        const signature = s.crypto_sign_detached(signPayload, myIdentityPrivKey);

        return {
            nonceB64: this.toBase64(nonce),
            ciphertextB64: this.toBase64(ciphertextBytes),
            signatureB64: this.toBase64(signature)
        };
    },

    /**
     * Verifies sender signature and decrypts AEAD ciphertext:
     * 1. Checks Ed25519 signature over (header || ciphertext).
     * 2. Checks ChaCha20-Poly1305 AEAD authentication tag.
     * Throws an Error if signature is invalid or ciphertext was altered.
     */
    decryptEnvelope(senderIdentityPubkeyB64, messageKey, nonceB64, ciphertextB64, headerObj, signatureB64) {
        const s = this.sodium;

        // 1. Verify Ed25519 identity signature
        const senderIdPub = this.fromBase64(senderIdentityPubkeyB64);
        const sig = this.fromBase64(signatureB64);
        const signPayload = s.from_string(JSON.stringify(headerObj) + "|" + ciphertextB64);
        const sigValid = s.crypto_sign_verify_detached(sig, signPayload, senderIdPub);

        if (!sigValid) {
            throw new Error("AUTHENTICATION_FAILED: Sender signature verification failed! Message was forged or tampered.");
        }

        // 2. Decrypt & authenticate with ChaCha20-Poly1305 AEAD
        const nonce = this.fromBase64(nonceB64);
        const ciphertext = this.fromBase64(ciphertextB64);
        const headerBytes = s.from_string(JSON.stringify(headerObj));

        try {
            const decryptedBytes = s.crypto_aead_chacha20poly1305_ietf_decrypt(
                null,
                ciphertext,
                headerBytes,
                nonce,
                messageKey
            );
            return s.to_string(decryptedBytes);
        } catch (err) {
            throw new Error("INTEGRITY_CHECK_FAILED: AEAD Poly1305 authentication tag failed! Ciphertext or header was modified.");
        }
    },

    /**
     * Derives a local unlocking key from a user passphrase using Argon2id.
     * WHY: Memory-hard password hashing prevents offline brute-force attacks if a device is seized.
     */
    derivePassphraseKey(passphraseStr, saltB64) {
        const s = this.sodium;
        const salt = saltB64 ? this.fromBase64(saltB64) : s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
        const key = s.crypto_pwhash(
            32,
            passphraseStr,
            salt,
            s.crypto_pwhash_OPSLIMIT_INTERACTIVE,
            s.crypto_pwhash_MEMLIMIT_INTERACTIVE,
            s.crypto_pwhash_ALG_ARGON2ID13
        );
        return {
            key: key,
            saltB64: this.toBase64(salt)
        };
    },

    /**
     * Encrypts a JS object for storage on this device (localStorage).
     * XChaCha20-Poly1305 with a random 24-byte nonce; the fixed associated data ties it to this app.
     * Returns { n, c } (base64). Only this ciphertext ever goes into storage.
     */
    sealLocal(storageKey, obj) {
        const s = this.sodium;
        const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
            s.from_string(JSON.stringify(obj)), s.from_string("sm2-local-v1"), null, nonce, storageKey
        );
        return { n: this.toBase64(nonce), c: this.toBase64(ct) };
    },

    /**
     * Opens what sealLocal() stored. Throws if the key is wrong or the data was changed.
     */
    openLocal(storageKey, sealed) {
        const s = this.sodium;
        const pt = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, this.fromBase64(sealed.c), s.from_string("sm2-local-v1"), this.fromBase64(sealed.n), storageKey
        );
        return JSON.parse(s.to_string(pt));
    },

    /**
     * Turns a key bundle from generateUserKeys() into plain base64 fields (to be sealed with sealLocal).
     */
    exportKeys(keys) {
        return {
            idPub: keys.identity.publicKeyB64,
            idPriv: this.toBase64(keys.identity.privateKey),
            exPub: keys.exchange.publicKeyB64,
            exPriv: this.toBase64(keys.exchange.privateKey),
            sig: keys.keySignatureB64
        };
    },

    /**
     * The reverse of exportKeys(): rebuilds the same structure generateUserKeys() returns.
     */
    importKeys(o) {
        return {
            identity: { publicKey: this.fromBase64(o.idPub), privateKey: this.fromBase64(o.idPriv), publicKeyB64: o.idPub },
            exchange: { publicKey: this.fromBase64(o.exPub), privateKey: this.fromBase64(o.exPriv), publicKeyB64: o.exPub },
            keySignatureB64: o.sig
        };
    },

    /**
     * Securely zeroes Uint8Array memory buffers.
     */
    scrub(uint8Arr) {
        if (uint8Arr && this.sodium) {
            this.sodium.memzero(uint8Arr);
        }
    }
};

// Export to window
window.Crypto = Crypto;
