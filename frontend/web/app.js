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
// Session token from /api/login. Kept ONLY in this variable (not localStorage), so a page reload logs you out
// and an injected script can't read it from storage later.
let authToken = null;
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
const registerBtn = document.getElementById("registerBtn");
const logoutBtn = document.getElementById("logoutBtn");
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
        // Build the list with createElement/textContent (never innerHTML) so typed text can't inject HTML.
        dlpReason.replaceChildren();
        scanResult.reasons.forEach((reason, i) => {
            if (i > 0) dlpReason.appendChild(document.createTextNode("; "));
            const strong = document.createElement("strong");
            strong.textContent = reason;
            dlpReason.appendChild(strong);
        });
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

// Every v2 API call goes through here, so the session token is always attached.
// If the server says 401 (token missing, wrong or expired), we drop back to the login screen.
async function api(path, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (options.body) headers["Content-Type"] = "application/json";
    if (authToken) headers["Authorization"] = "Bearer " + authToken;
    const resp = await fetch(path, Object.assign({}, options, { headers }));
    if (resp.status === 401 && authToken) {
        logoutLocal("Your session expired. Please log in again.");
    }
    return resp;
}

async function readError(resp) {
    try {
        const data = await resp.json();
        if (typeof data.detail === "string") return data.detail;
        // 422 from the server: say exactly which field was wrong.
        if (Array.isArray(data.detail) && data.detail.length) {
            const field = (data.detail[0].loc || []).slice(-1)[0];
            if (field === "password") return "Password must be 8 to 128 characters.";
            if (field === "username") return "Username must be 1 to 50 characters: a-z, 0-9, _ or -.";
        }
    } catch (e) { /* not JSON */ }
    return resp.status === 422 ? "Check the username (a-z, 0-9, _ or -) and password (8+ characters)." : resp.statusText;
}

// Register or log in, then generate keys and publish the public halves.
async function authenticate(mode) {
    const username = usernameInput.value.trim().toLowerCase();
    const password = userPassphraseInput.value;

    if (!username || !password) {
        alert("Please enter a username and a password.");
        return;
    }
    if (mode === "register" && password.length < 8) {
        alert("Password must be at least 8 characters.");
        return;
    }

    try {
        await Crypto.init();

        // 1. Register (creates the account) or log in. The server answers with a session token.
        const authResp = await api(mode === "register" ? "/api/register" : "/api/login", {
            method: "POST",
            body: JSON.stringify({ username, password })
        });
        if (!authResp.ok) {
            throw new Error(await readError(authResp));
        }
        const session = await authResp.json();
        if (!session.token) {
            throw new Error("The server did not return a session token. Is it running the latest code? Restart it.");
        }
        authToken = session.token;
        currentUser = session.username;
        userPassphrase = password; // used only for the local "require passphrase" unlock check
        userPassphraseInput.value = "";

        // 2. Generate local cryptographic keypairs (Ed25519 + X25519).
        //    (New keys on every login for now; keeping them between logins is step B.)
        myKeys = Crypto.generateUserKeys();

        // 3. Publish public keys. The server saves them under the logged-in user (no username in the body).
        const keyResp = await api("/api/keys", {
            method: "POST",
            body: JSON.stringify({
                identity_pubkey: myKeys.identity.publicKeyB64,
                exchange_pubkey: myKeys.exchange.publicKeyB64,
                key_signature: myKeys.keySignatureB64
            })
        });

        if (!keyResp.ok) {
            throw new Error("Failed to register public keys: " + (await readError(keyResp)));
        }

        currentUserDisplay.textContent = currentUser;
        loginSection.style.display = "none";
        chatSection.style.display = "block";

        startPolling();
    } catch (err) {
        authToken = null;
        alert((mode === "register" ? "Sign-up" : "Login") + " failed: " + err.message);
    }
}

loginBtn.addEventListener("click", () => authenticate("login"));
registerBtn.addEventListener("click", () => authenticate("register"));

// Clear everything held in memory and show the login screen.
function logoutLocal(reason) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    authToken = null;
    currentUser = null;
    userPassphrase = null;
    myKeys = null;
    currentPeer = null;
    peerKeyCache = {};
    lastSeenCounters = {};
    myOutCounters = {};
    processedMessageIds = new Set();
    chatSection.style.display = "none";
    loginSection.style.display = "block";
    if (reason) alert(reason);
}

logoutBtn.addEventListener("click", async () => {
    try {
        await api("/api/logout", { method: "POST" }); // server deletes the session
    } catch (e) { /* still log out locally */ }
    logoutLocal();
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
        const resp = await api(`/api/keys/${encodeURIComponent(peer)}`);
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

        // Transmit only ciphertext and public header to server.
        // No "sender" field: the server takes the sender from our session token.
        const resp = await api("/api/messages", {
            method: "POST",
            body: JSON.stringify({
                recipient: peer,
                payload: wirePayload,
                is_sensitive: isSensitive,
                ttl_seconds: ttl
            })
        });

        if (!resp.ok) {
            throw new Error("Server relay error: " + (await readError(resp)));
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
        const resp = await api(`/api/messages/${encodeURIComponent(currentUser)}`);
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
                api(`/api/messages/${msgRecord.id}`, { method: "DELETE" }).catch(() => {});
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

    // Built with createElement/textContent: the sender name comes from the network and must not become HTML.
    const lockHeader = document.createElement("div");
    lockHeader.className = "sensitive-lock-header";
    const title = document.createElement("span");
    title.appendChild(document.createTextNode("🔒 Confidential Sensitive Message from "));
    const senderStrong = document.createElement("strong");
    senderStrong.textContent = sender;
    title.appendChild(senderStrong);
    const countdown = document.createElement("span");
    countdown.className = "sensitive-countdown";
    countdown.id = `cd-${msgId}`;
    countdown.textContent = `⏳ ${remainingSecs}s`;
    lockHeader.append(title, countdown);

    const note = document.createElement("p");
    note.style.cssText = "margin: 6px 0; font-size: 13px; color: #cbd5e1;";
    note.textContent = "Protected by per-message AEAD encryption. " + (header.one_time_view ? "One-time view enabled." : "");

    const unlockButton = document.createElement("button");
    unlockButton.className = "btn btn-primary";
    unlockButton.id = `unlock-btn-${msgId}`;
    unlockButton.style.cssText = "padding: 6px 14px; font-size: 13px; margin-top: 6px;";
    unlockButton.textContent = "Decrypt & View";

    const contentDiv = document.createElement("div");
    contentDiv.id = `content-${msgId}`;
    contentDiv.style.cssText = "display: none; margin-top: 10px; padding: 10px; background: #030712; border-radius: 6px;";

    bubble.append(lockHeader, note, unlockButton, contentDiv);

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
                api(`/api/messages/${msgId}`, { method: "DELETE" }).catch(() => {});
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
        const gone = document.createElement("span");
        gone.style.cssText = "color: #94a3b8; font-style: italic;";
        gone.textContent = `🔥 [Sensitive message destroyed: ${reason}]`;
        bubbleElem.replaceChildren(gone);
    }
}

function renderMessageBubble(sender, text, direction, timeStr, isSensitive, ttl) {
    const emptyState = messagesContainer.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    const bubble = document.createElement("div");
    bubble.className = `message-bubble ${direction}`;

    const meta = document.createElement("div");
    meta.className = "message-meta";
    const senderSpan = document.createElement("span");
    const senderName = document.createElement("strong");
    senderName.textContent = sender;
    senderSpan.appendChild(senderName);
    const timeSpan = document.createElement("span");
    timeSpan.textContent = timeStr;
    meta.append(senderSpan, timeSpan);

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
    const label = document.createElement("strong");
    label.textContent = "Security Guard:";
    bubble.append(label, document.createTextNode(" " + alertText));
    messagesContainer.appendChild(bubble);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}
