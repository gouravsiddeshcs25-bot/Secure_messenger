/**
 * Messenger v1: Deliberately Insecure Client Implementation.
 * 
 * Flaws demonstrated:
 * 1. Sends plaintext directly in payload (no E2EE).
 * 2. Does not fetch or verify public keys (vulnerable to MITM).
 * 3. Does not use counters, nonces, or timestamps to filter replays (vulnerable to replay attacks).
 * 4. Displays whatever the server returns without integrity checks (vulnerable to server/network tampering).
 */

let currentUser = null;
let pollTimer = null;
let displayedMessageIds = new Set();

const loginSection = document.getElementById("loginSection");
const chatSection = document.getElementById("chatSection");
const usernameInput = document.getElementById("usernameInput");
const loginBtn = document.getElementById("loginBtn");
const currentUserDisplay = document.getElementById("currentUserDisplay");
const recipientInput = document.getElementById("recipientInput");
const messagesContainer = document.getElementById("messagesContainer");
const messageInput = document.getElementById("messageInput");
const sendBtn = document.getElementById("sendBtn");
const statusMessage = document.getElementById("statusMessage");

loginBtn.addEventListener("click", async () => {
    const username = usernameInput.value.trim().toLowerCase();
    if (!username) {
        alert("Please enter a username.");
        return;
    }

    try {
        const resp = await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username })
        });
        if (!resp.ok) {
            throw new Error("Registration failed: " + resp.statusText);
        }

        currentUser = username;
        currentUserDisplay.textContent = currentUser;
        loginSection.style.display = "none";
        chatSection.style.display = "block";

        // Start polling for incoming messages
        startPolling();
    } catch (err) {
        alert("Error connecting to server: " + err.message);
    }
});

sendBtn.addEventListener("click", async () => {
    const recipient = recipientInput.value.trim().toLowerCase();
    const content = messageInput.value.trim();

    if (!recipient) {
        alert("Please specify a recipient username.");
        return;
    }
    if (!content) {
        return;
    }

    // INSECURE: Send raw plaintext payload with no encryption or signature
    const payload = JSON.stringify({
        sender: currentUser,
        recipient: recipient,
        content: content,
        timestamp: Date.now()
    });

    try {
        const resp = await fetch("/api/messages", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                sender: currentUser,
                recipient: recipient,
                payload: payload,
                is_sensitive: false
            })
        });

        if (!resp.ok) {
            throw new Error("Failed to send: " + resp.statusText);
        }

        // Render outgoing message locally
        renderMessageBubble(currentUser, content, "sent", new Date().toLocaleTimeString());
        messageInput.value = "";
    } catch (err) {
        alert("Send error: " + err.message);
    }
});

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    fetchMessages();
    pollTimer = setInterval(fetchMessages, 2000);
}

async function fetchMessages() {
    if (!currentUser) return;
    try {
        const resp = await fetch(`/api/messages/${currentUser}`);
        if (!resp.ok) return;

        const data = await resp.json();
        const messages = data.messages || [];

        messages.forEach(msg => {
            // Note: v1 does not check message IDs or replay nonces.
            // If the same message is returned, it is displayed.
            if (!displayedMessageIds.has(msg.id)) {
                displayedMessageIds.add(msg.id);
                
                let text = msg.payload;
                try {
                    // Try to parse the JSON if v1 envelope was used
                    const parsed = JSON.parse(msg.payload);
                    if (parsed.content) text = parsed.content;
                } catch (e) {
                    // Raw string
                }

                // INSECURE: Directly rendering payload without integrity/auth verification
                renderMessageBubble(msg.sender, text, "received", msg.created_at || new Date().toLocaleTimeString());
            }
        });

        statusMessage.textContent = `Active polling (${new Date().toLocaleTimeString()})`;
    } catch (err) {
        statusMessage.textContent = "Polling error: " + err.message;
    }
}

function renderMessageBubble(sender, text, direction, timeStr) {
    // Clear empty state if present
    const emptyState = messagesContainer.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    const bubble = document.createElement("div");
    bubble.className = `message-bubble ${direction}`;

    const meta = document.createElement("div");
    meta.className = "message-meta";
    meta.innerHTML = `<span>${sender}</span><span>${timeStr}</span>`;

    const body = document.createElement("div");
    body.className = "message-body";
    body.textContent = text; // Escapes HTML

    bubble.appendChild(meta);
    bubble.appendChild(body);
    messagesContainer.appendChild(bubble);

    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}
