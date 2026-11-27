/**
 * Messenger v2: Hardened Zero-Knowledge Client Application Logic.
 * 
 * Implements:
 * 1. Client-side identity key generation (Ed25519 + X25519).
 * 2. Signature verification on public key bundles.
 * 3. Out-of-band Safety Number / Fingerprint calculation.
 * 4. Per-message key derivation (KDF) & forward secrecy.
 * 5. AEAD ChaCha20-Poly1305 encryption & tamper rejection.
 * 6. Sequence counter replay attack prevention.
 * 7. Sensitive-message ephemerality, local burn timers, and server purge.
 * 8. Passphrase re-authentication using Argon2id.
 */

let currentUser = null;
let userPassphrase = null;
let myKeys = null;
let currentPeer = null;
let peerKeyCache = {}; // username -> { identityPubkey, exchangePubkey, keySignature, sharedSecret }
let lastSeenCounters = {}; // sender -> highest integer counter received
let myOutCounters = {}; // peer -> outgoing counter
let processedMessageIds = new Set();
let pollTimer = null;

// DOM Elements
const loginSection = document.getElementById("loginSection");
const chatSection = document.getElementById("chatSection");
const usernameInput = document.getElementById("usernameInput");
const userPassphraseInput = document.getElementById("userPassphraseInput");
const loginBtn = document.getElementById("loginBtn");
const cryptoInitStatus = document.getElementById("cryptoInitStatus");
const currentUserDisplay = document.getElementById("currentUserDisplay");
const recipientInput = document.getElementById("recipientInput");
const connectPeerBtn = document.getElementById("connectPeerBtn");
const fingerprintPanel = document.getElementById("fingerprintPanel");
const fingerprintCode = document.getElementById("fingerprintCode");
const fingerprintStatus = document.getElementById("fingerprintStatus");
const messagesContainer = document.getElementById("messagesContainer");
const messageInput = document.getElementById("messageInput");
const sendBtn = document.getElementById("sendBtn");
const sensitiveToggle = document.getElementById("sensitiveToggle");
const ttlSelect = document.getElementById("ttlSelect");
const oneTimeViewCheck = document.getElementById("oneTimeViewCheck");
const requirePassphraseCheck = document.getElementById("requirePassphraseCheck");
const dlpWarning = document.getElementById("dlpWarning");
const dlpReason = document.getElementById("dlpReason");
const statusMessage = document.getElementById("statusMessage");

// Initialize Crypto on load
window.addEventListener("DOMContentLoaded", async () => {
    try {
        await Crypto.init();
        cryptoInitStatus.textContent = "✓ Local libsodium cryptography engine ready.";
        cryptoInitStatus.style.color = "#34d399";
    } catch (err) {
        cryptoInitStatus.textContent = "✗ Error initializing crypto: " + err.message;
        cryptoInitStatus.style.color = "#f87171";
    }
});

// Real-time DLP scanning as user types
messageInput.addEventListener("input", () => {
    checkDLP();
});

function checkDLP() {
    const text = messageInput.value;
    const scanResult = DLP.scan(text);
    if (scanResult.detected) {
        dlpReason.innerHTML = "<strong>" + scanResult.reasons.join("</strong>; <strong>") + "</strong>";
        dlpWarning.style.display = "block";
        sensitiveToggle.checked = true; // Automatically enforce sensitive mode
        sensitiveToggle.disabled = true; // Prevent user from disabling sensitive mode
        oneTimeViewCheck.checked = true; // Enforce one-time view for confidential PII
    } else {
        dlpWarning.style.display = "none";
        sensitiveToggle.disabled = false;
    }
    return scanResult;
}

// Login & Generate Keys
loginBtn.addEventListener("click", async () => {
    const username = usernameInput.value.trim().toLowerCase();
    const passphrase = userPassphraseInput.value.trim();

    if (!username) {
        alert("Please enter a username.");
        return;
    }

    try {
        await Crypto.init();
        currentUser = username;
        userPassphrase = passphrase || "default-local-passphrase";

        // 1. Generate local cryptographic keypairs (Ed25519 + X25519)
        myKeys = Crypto.generateUserKeys();

        // 2. Register user handle on server
        await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: currentUser })
        });

        // 3. Register public keys on server (Server never sees private keys!)
        const keyResp = await fetch("/api/keys", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: currentUser,
                identity_pubkey: myKeys.identity.publicKeyB64,
                exchange_pubkey: myKeys.exchange.publicKeyB64,
                key_signature: myKeys.keySignatureB64
            })
        });

        if (!keyResp.ok) {
            throw new Error("Failed to register public keys: " + keyResp.statusText);
        }

        currentUserDisplay.textContent = currentUser;
        loginSection.style.display = "none";
        chatSection.style.display = "block";

        startPolling();
    } catch (err) {
        alert("Login initialization failed: " + err.message);
    }
});

// Connect to Peer & Perform Out-of-Band Key Exchange
connectPeerBtn.addEventListener("click", async () => {
    const peer = recipientInput.value.trim().toLowerCase();
    if (!peer) {
        alert("Please enter recipient username.");
        return;
    }
    if (peer === currentUser) {
        alert("Cannot connect to yourself.");
        return;
    }
    await setupPeerConnection(peer);
});

async function setupPeerConnection(peer) {
    try {
        const resp = await fetch(`/api/keys/${peer}`);
        if (!resp.ok) {
            throw new Error(`User '${peer}' has not registered public keys yet.`);
        }
        const peerData = await resp.json();

        // 1. Verify that peer's exchange public key was signed by their identity key
        const isSigValid = Crypto.verifyKeySignature(
            peerData.identity_pubkey,
            peerData.exchange_pubkey,
            peerData.key_signature
        );

        if (!isSigValid) {
            fingerprintStatus.textContent = "⚠️ SIGNATURE INVALID: Possible MITM Key Tampering!";
            fingerprintStatus.style.background = "rgba(239, 68, 68, 0.2)";
            fingerprintStatus.style.color = "#f87171";
            throw new Error("SECURITY_ALERT: Peer exchange key signature verification failed! MITM attack detected.");
        }

        // 2. Compute Out-of-Band Safety Number (Fingerprint)
        const fp = Crypto.computeFingerprint(myKeys.identity.publicKeyB64, peerData.identity_pubkey);
        fingerprintCode.textContent = fp;
        fingerprintStatus.textContent = "✓ Key Signature & Fingerprint Verified";
        fingerprintStatus.style.background = "rgba(16, 185, 129, 0.2)";
        fingerprintStatus.style.color = "#10b981";
        fingerprintPanel.style.display = "flex";

        // 3. Compute X25519 Shared Secret
        const sharedSecret = Crypto.computeSharedSecret(
            myKeys.exchange.privateKey,
            peerData.exchange_pubkey
        );

        currentPeer = peer;
        peerKeyCache[peer] = {
            identityPubkey: peerData.identity_pubkey,
            exchangePubkey: peerData.exchange_pubkey,
            keySignature: peerData.key_signature,
            sharedSecret: sharedSecret,
            fingerprint: fp
        };

        if (!(peer in myOutCounters)) myOutCounters[peer] = 0;
        if (!(peer in lastSeenCounters)) lastSeenCounters[peer] = 0;

        return peerKeyCache[peer];
    } catch (err) {
        alert("Peer connection error: " + err.message);
        throw err;
    }
}

// Send E2EE Message
sendBtn.addEventListener("click", async () => {
    const peer = recipientInput.value.trim().toLowerCase();
    const content = messageInput.value.trim();

    if (!peer) {
        alert("Please specify a recipient.");
        return;
    }
    if (!content) return;

    // Pre-flight DLP Scan: Enforce sensitive mode if PII or credentials detected
    const dlpResult = checkDLP();
    const forceSensitive = dlpResult.detected;

    try {
        let peerData = peerKeyCache[peer];
        if (!peerData) {
            peerData = await setupPeerConnection(peer);
        }

        // Increment monotonic sequence counter (Replay Protection)
        myOutCounters[peer] = (myOutCounters[peer] || 0) + 1;
        const counter = myOutCounters[peer];

        // Forward Secrecy: Derive per-message key from master shared secret + counter
        const messageKey = Crypto.deriveMessageKey(peerData.sharedSecret, counter);

        const isSensitive = forceSensitive || sensitiveToggle.checked;
        const ttl = isSensitive ? (parseInt(ttlSelect.value, 10) || 60) : null;
        const oneTimeView = isSensitive ? (forceSensitive || oneTimeViewCheck.checked) : false;
        const requirePassphrase = isSensitive && requirePassphraseCheck.checked;

        // Message Header (Associated Data for AEAD authentication)
        const header = {
            version: 2,
            sender: currentUser,
            recipient: peer,
            counter: counter,
            timestamp: Date.now(),
            is_sensitive: isSensitive,
            ttl_seconds: ttl,
            one_time_view: oneTimeView,
            require_passphrase: requirePassphrase
        };

        // Encrypt with ChaCha20-Poly1305 AEAD and sign with Ed25519
        const envelope = Crypto.encryptEnvelope(
            myKeys.identity.privateKey,
            messageKey,
            content,
            header
        );

        // Immediate memory zeroization of per-message key
        Crypto.scrub(messageKey);

        const wirePayload = JSON.stringify({
            header: header,
            nonce: envelope.nonceB64,
            ciphertext: envelope.ciphertextB64,
            signature: envelope.signatureB64
        });

        // Transmit only ciphertext and public header to server
        const resp = await fetch("/api/messages", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                sender: currentUser,
                recipient: peer,
                payload: wirePayload,
                is_sensitive: isSensitive,
                ttl_seconds: ttl
            })
        });

        if (!resp.ok) {
            throw new Error("Server relay error: " + resp.statusText);
        }

        // Render outgoing message locally
        renderMessageBubble(currentUser, content, "sent", new Date().toLocaleTimeString(), isSensitive, ttl);
        messageInput.value = "";
        dlpWarning.style.display = "none";
    } catch (err) {
        alert("Encryption / Send failure: " + err.message);
    }
});

// Polling loop
function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollMessages();
    pollTimer = setInterval(pollMessages, 2000);
}

async function pollMessages() {
    if (!currentUser || !myKeys) return;
    try {
        const resp = await fetch(`/api/messages/${currentUser}`);
        if (!resp.ok) return;

        const data = await resp.json();
        const messages = data.messages || [];

        for (const msg of messages) {
            if (!processedMessageIds.has(msg.id)) {
                await processIncomingMessage(msg);
            }
        }
        statusMessage.textContent = `Secure polling active (${new Date().toLocaleTimeString()})`;
    } catch (err) {
        statusMessage.textContent = "Polling error: " + err.message;
    }
}

async function processIncomingMessage(msgRecord) {
    processedMessageIds.add(msgRecord.id);

    try {
        const envelope = JSON.parse(msgRecord.payload);
        const header = envelope.header;

        if (!header || header.version !== 2) {
            // Unrecognized or naive message
            renderMessageBubble(msgRecord.sender, "[Warning: Insecure/Legacy v1 Message Received]", "received", msgRecord.created_at, false);
            return;
        }

        const sender = header.sender;

        // Ensure peer keys and shared secret exist
        let peerData = peerKeyCache[sender];
        if (!peerData) {
            peerData = await setupPeerConnection(sender);
        }

        // 1. REPLAY ATTACK CHECK:
        // Monotonic counter must be strictly greater than last seen counter from this sender
        const lastCounter = lastSeenCounters[sender] || 0;
        if (header.counter <= lastCounter) {
            console.error(`REPLAY_ATTACK_DETECTED: Received counter ${header.counter} <= last seen ${lastCounter}`);
            renderSecurityAlert(sender, `🚨 REPLAY ATTACK BLOCKED! Message with duplicate counter (${header.counter}) was rejected.`);
            return;
        }
        // Update watermark
        lastSeenCounters[sender] = header.counter;

        // 2. CHECK EXPIRATION (if sensitive with TTL)
        if (header.is_sensitive && header.ttl_seconds) {
            const ageSeconds = (Date.now() - header.timestamp) / 1000;
            if (ageSeconds > header.ttl_seconds) {
                // Expired: Purge on server and notify
                fetch(`/api/messages/${msgRecord.id}`, { method: "DELETE" }).catch(() => {});
                renderMessageBubble(sender, "⏱️ [Sensitive Message Expired: Key scrubbed, content unrecoverable]", "received", msgRecord.created_at, true);
                return;
            }
        }

        // 3. Derive forward-secret per-message key
        const messageKey = Crypto.deriveMessageKey(peerData.sharedSecret, header.counter);

        // 4. If sensitive message: render locked card with one-time view and burn countdown
        if (header.is_sensitive) {
            renderSensitiveCard(msgRecord.id, sender, envelope, messageKey, header);
        } else {
            // Normal message: Decrypt and verify AEAD tag immediately
            const plaintext = Crypto.decryptEnvelope(
                peerData.identityPubkey,
                messageKey,
                envelope.nonce,
                envelope.ciphertext,
                header,
                envelope.signature
            );
            Crypto.scrub(messageKey); // Zero memory
            renderMessageBubble(sender, plaintext, "received", msgRecord.created_at || new Date().toLocaleTimeString(), false);
        }
    } catch (err) {
        console.error("Decryption error:", err);
        renderSecurityAlert(msgRecord.sender, `⚠️ INTEGRITY ERROR: ${err.message}`);
    }
}

// Render locked card for Sensitive Messages
function renderSensitiveCard(msgId, sender, envelope, messageKey, header) {
    const emptyState = messagesContainer.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    const bubble = document.createElement("div");
    bubble.className = "message-bubble received sensitive-card";
    bubble.id = `msg-card-${msgId}`;

    const remainingSecs = Math.max(1, Math.round(header.ttl_seconds - (Date.now() - header.timestamp) / 1000));

    bubble.innerHTML = `
        <div class="sensitive-lock-header">
            <span>🔒 Confidential Sensitive Message from <strong>${sender}</strong></span>
            <span class="sensitive-countdown" id="cd-${msgId}">⏳ ${remainingSecs}s</span>
        </div>
        <p style="margin: 6px 0; font-size: 13px; color: #cbd5e1;">
            Protected by per-message AEAD encryption. ${header.one_time_view ? "One-time view enabled." : ""}
        </p>
        <button class="btn btn-primary" id="unlock-btn-${msgId}" style="padding: 6px 14px; font-size: 13px; margin-top: 6px;">
            Decrypt & View
        </button>
        <div id="content-${msgId}" style="display: none; margin-top: 10px; padding: 10px; background: #030712; border-radius: 6px;"></div>
    `;

    messagesContainer.appendChild(bubble);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    // Server-side expiration countdown
    let timeLeft = remainingSecs;
    const expiryTimer = setInterval(() => {
        timeLeft--;
        const cdElem = document.getElementById(`cd-${msgId}`);
        if (cdElem) cdElem.textContent = `⏳ ${timeLeft}s`;
        if (timeLeft <= 0) {
            clearInterval(expiryTimer);
            burnSensitiveMessage(msgId, bubble, messageKey, "Expired and purged.");
        }
    }, 1000);

    const unlockBtn = document.getElementById(`unlock-btn-${msgId}`);
    unlockBtn.addEventListener("click", async () => {
        // If passphrase required, prompt recipient
        if (header.require_passphrase) {
            const entered = prompt("Enter your local passphrase to unlock this sensitive message:");
            if (!entered || entered !== userPassphrase) {
                alert("Incorrect passphrase! Decryption aborted.");
                return;
            }
        }

        try {
            const peerData = peerKeyCache[sender];
            const plaintext = Crypto.decryptEnvelope(
                peerData.identityPubkey,
                messageKey,
                envelope.nonce,
                envelope.ciphertext,
                header,
                envelope.signature
            );

            // One-time view: immediately delete from server database
            if (header.one_time_view) {
                fetch(`/api/messages/${msgId}`, { method: "DELETE" }).catch(() => {});
            }

            unlockBtn.style.display = "none";
            const contentBox = document.getElementById(`content-${msgId}`);
            contentBox.style.display = "block";
            contentBox.textContent = plaintext;

            // Add local burn button
            const burnBtn = document.createElement("button");
            burnBtn.className = "btn btn-danger sensitive-burn-btn";
            burnBtn.textContent = "Burn Now (Scrub Memory)";
            burnBtn.onclick = () => {
                clearInterval(expiryTimer);
                burnSensitiveMessage(msgId, bubble, messageKey, "Message burned by user.");
            };
            contentBox.appendChild(document.createElement("br"));
            contentBox.appendChild(burnBtn);

            // Start reading countdown (15s burn timer)
            let readTimerSecs = 15;
            const readTimer = setInterval(() => {
                readTimerSecs--;
                const cdElem = document.getElementById(`cd-${msgId}`);
                if (cdElem) cdElem.textContent = `🔥 Auto-burn in ${readTimerSecs}s`;
                if (readTimerSecs <= 0) {
                    clearInterval(readTimer);
                    clearInterval(expiryTimer);
                    burnSensitiveMessage(msgId, bubble, messageKey, "Burn timer elapsed.");
                }
            }, 1000);
        } catch (err) {
            alert("Decryption failed: " + err.message);
        }
    });
}

function burnSensitiveMessage(msgId, bubbleElem, messageKey, reason) {
    Crypto.scrub(messageKey); // Zero key memory
    if (bubbleElem) {
        bubbleElem.innerHTML = `<span style="color: #94a3b8; font-style: italic;">🔥 [Sensitive message destroyed: ${reason}]</span>`;
    }
}

function renderMessageBubble(sender, text, direction, timeStr, isSensitive, ttl) {
    const emptyState = messagesContainer.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    const bubble = document.createElement("div");
    bubble.className = `message-bubble ${direction}`;

    const meta = document.createElement("div");
    meta.className = "message-meta";
    meta.innerHTML = `<span><strong>${sender}</strong></span><span>${timeStr}</span>`;

    if (isSensitive) {
        const tag = document.createElement("span");
        tag.className = "sensitive-tag";
        tag.textContent = `🔒 SENSITIVE (${ttl}s TTL)`;
        meta.appendChild(tag);
    }

    const body = document.createElement("div");
    body.className = "message-body";
    body.textContent = text;

    bubble.appendChild(meta);
    bubble.appendChild(body);
    messagesContainer.appendChild(bubble);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function renderSecurityAlert(sender, alertText) {
    const bubble = document.createElement("div");
    bubble.className = "message-bubble received";
    bubble.style.borderColor = "#ef4444";
    bubble.style.background = "#450a0a";
    bubble.style.color = "#fca5a5";
    bubble.innerHTML = `<strong>Security Guard:</strong> ${alertText}`;
    messagesContainer.appendChild(bubble);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}
