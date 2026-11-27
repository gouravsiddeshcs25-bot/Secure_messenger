// Chats: contacts (trust on first use), sending, receiving, and drawing the conversation.
// All crypto goes through window.Crypto (frontend/shared/crypto.js). The server only ever sees
// the JSON envelope built in send().

import { $, el, icon, toast, scramble, noise, sleep, askPassword, timeLabel, dayLabel } from "./dom.js";
import { api, readError } from "./api.js";
import * as vault from "./vault.js";

const POLL_MS = 2000;
const KEY_REFRESH_TICKS = 5;      // re-check the open chat's keys every ~10 s
const READ_WINDOW_SECONDS = 15;   // how long an opened sensitive message stays visible

let me = null;
let myKeys = null;
let current = null;               // username of the open chat
let peers = {};                   // name -> { bundle, shared, fingerprint, status, fetchedAt }
let liveSecrets = {};             // name -> [card elements still on screen this session]
let pollTimer = null;
let ticks = 0;
let polling = false;
let usersCache = { at: 0, list: [] };

// ======================================================================
// Start / stop
// ======================================================================
export function start(username, keys) {
    me = username;
    myKeys = keys;
    current = null;
    peers = {};
    liveSecrets = {};
    $("meName").textContent = me;
    $("meAvatar").textContent = me[0];
    renderChatList();
    showEmptyConvo();
    poll();
    pollTimer = setInterval(poll, POLL_MS);
}

export function stop() {
    clearInterval(pollTimer);
    pollTimer = null;
    for (const p of Object.values(peers)) Crypto.scrub(p.shared);
    peers = {};
    liveSecrets = {};
    myKeys = null;
    me = null;
    current = null;
    $("thread").replaceChildren();
    $("chatList").replaceChildren();
}

// ======================================================================
// Contacts and trust on first use
// ======================================================================
function contactStatus(name) {
    const c = vault.data().contacts[name];
    const p = peers[name];
    if (p && p.status === "bad") return "bad";
    if (c && c.pending) return "changed";
    if (c && c.verified) return "verified";
    return "unverified";
}

// Fetches a contact's public keys and checks them against what we saw the first time.
async function loadPeer(name, fresh) {
    const cached = peers[name];
    if (cached && !fresh) return cached;

    const resp = await api(`/api/keys/${encodeURIComponent(name)}`);
    if (resp.status === 404) throw new Error(name + " hasn't finished setting up their account yet.");
    if (!resp.ok) throw new Error(await readError(resp));
    const bundle = await resp.json();

    const entry = { bundle, shared: cached ? cached.shared : null, status: "ok", fetchedAt: Date.now() };

    // 1. The exchange key must be signed by the identity key.
    if (!Crypto.verifyKeySignature(bundle.identity_pubkey, bundle.exchange_pubkey, bundle.key_signature)) {
        entry.status = "bad";
        peers[name] = entry;
        return entry;
    }

    // 2. Trust on first use: remember the first identity key; flag any later change.
    const contacts = vault.data().contacts;
    const known = contacts[name];
    if (!known) {
        contacts[name] = { identity: bundle.identity_pubkey, verified: false, since: Date.now() };
        vault.save();
    } else if (known.identity !== bundle.identity_pubkey) {
        if (known.pending !== bundle.identity_pubkey) {
            known.pending = bundle.identity_pubkey;
            vault.save();
        }
    } else if (known.pending) {
        delete known.pending; // the server went back to the key we trust
        vault.save();
    }

    // 3. Only derive a shared secret from a key we trust.
    const trusted = contacts[name] && !contacts[name].pending;
    if (trusted && (!cached || cached.bundle.exchange_pubkey !== bundle.exchange_pubkey || !entry.shared)) {
        if (cached && cached.shared) Crypto.scrub(cached.shared);
        entry.shared = Crypto.computeSharedSecret(myKeys.exchange.privateKey, bundle.exchange_pubkey);
    }
    if (!trusted) entry.shared = null;
    entry.fingerprint = Crypto.computeFingerprint(myKeys.identity.publicKeyB64, bundle.identity_pubkey);
    peers[name] = entry;
    return entry;
}

function paintTrust() {
    if (!current) return;
    const status = contactStatus(current);
    const states = {
        unverified: ["chip chip-warn", "shield", "Not verified"],
        verified: ["chip chip-ok", "check", "Verified"],
        changed: ["chip chip-danger", "alert", "Key changed"],
        bad: ["chip chip-danger", "alert", "Keys invalid"],
    };
    const [cls, ic, label] = states[status];
    const chip = $("trustChip");
    if (chip.dataset.state !== status) {
        chip.className = cls;
        chip.dataset.state = status;
        chip.replaceChildren(icon(ic, "icon-sm"), el("span", { text: label }));
    }
    const blocked = status === "changed" || status === "bad";
    $("composer").classList.toggle("blocked", blocked);
    $("text").disabled = blocked;

    const slot = $("bannerSlot");
    const existing = slot.firstElementChild;
    if (!blocked) { slot.replaceChildren(); return; }
    if (existing && existing.dataset.state === status && existing.dataset.peer === current) return;
    const peer = current;
    const banner = status === "changed"
        ? el("div", { class: "banner banner-danger", role: "alert", "data-state": status, "data-peer": peer },
            icon("alert"),
            el("div", {}, el("strong", { text: peer + "'s security key changed" }),
                el("p", { text: "Sending is paused until you compare the new safety number. Messages from " + peer + " are held until then." })),
            el("button", { class: "btn btn-danger", onclick: () => openSafety(true) }, el("span", { text: "Review" })))
        : el("div", { class: "banner banner-danger", role: "alert", "data-state": status, "data-peer": peer },
            icon("alert"),
            el("div", {}, el("strong", { text: peer + "'s keys failed the signature check" }),
                el("p", { text: "Someone may have tampered with them on the server. Don't send anything to " + peer + "." })));
    slot.replaceChildren(banner);
}

// ---------- safety number dialog ----------
function openSafety(changed) {
    const peer = current;
    const p = peers[peer];
    if (!p) return;
    const groups = p.fingerprint.split(" ");
    $("safetyTitle").textContent = changed ? peer + "'s security key changed" : "Verify " + peer;
    $("safetyText").textContent = changed
        ? "This happens when " + peer + " signs in on a new browser, or if someone is trying to intercept your chat. Compare this new number with " + peer + " in person or on a call before you continue."
        : "Compare this number with " + peer + " in person or on a call. If it matches on both screens, nobody is sitting in the middle.";
    $("safetyNumber").replaceChildren(...groups.map((g) => el("span", { text: g })));
    const verified = contactStatus(peer) === "verified";
    $("safetyConfirm").textContent = changed ? "I checked, continue" : (verified ? "Still matches" : "Numbers match");
    $("safetyLater").textContent = changed ? "Keep blocked" : "Not now";
    $("safetyDialog").dataset.changed = changed ? "1" : "";
    $("safetyDialog").dataset.peer = peer;
    $("safetyDialog").showModal();
}

async function confirmSafety() {
    const d = $("safetyDialog");
    const peer = d.dataset.peer;
    const changed = d.dataset.changed === "1";
    d.close();
    const c = vault.data().contacts[peer];
    if (!c) return;
    if (changed) {
        c.identity = c.pending;
        delete c.pending;
        c.verified = false;
        vault.addHistory(peer, { kind: "notice", tone: "neutral", text: "You accepted " + peer + "'s new security key. Verify the safety number when you can.", ts: Date.now() });
        vault.save();
        await loadPeer(peer, true);
        toast("New key accepted. " + peer + " is not verified yet.");
        if (current === peer) renderThread();
        poll(); // deliver any messages that were held
    } else {
        c.verified = true;
        vault.save();
        toast(peer + " is verified");
    }
    paintTrust();
    renderChatList();
}

// ======================================================================
// Chat list and opening chats
// ======================================================================
function chatNames() {
    const d = vault.data();
    // Include contacts with unread or held messages (e.g. waiting for a key review), even with no history yet.
    const names = new Set([...Object.keys(d.history), ...Object.keys(liveSecrets), ...Object.keys(d.unread)]);
    if (current) names.add(current);
    return [...names].sort((a, b) => lastTs(b) - lastTs(a));
}

function lastTs(name) {
    const h = vault.data().history[name] || [];
    return h.length ? h[h.length - 1].ts : 0;
}

function summary(item) {
    if (!item) return "No messages yet";
    if (item.kind === "notice") return item.text;
    const prefix = item.dir === "out" ? "You: " : "";
    if (item.sensitive) return prefix + "Sensitive message";
    return prefix + item.text;
}

export function renderChatList() {
    const d = vault.data();
    if (!d) return;
    const names = chatNames();
    if (!names.length) {
        $("chatList").replaceChildren(el("p", { class: "list-empty", text: "No chats yet. Search for a username above to start one." }));
        return;
    }
    $("chatList").replaceChildren(...names.map((name) => {
        const h = d.history[name] || [];
        const last = h[h.length - 1];
        const status = contactStatus(name);
        const mark = status === "verified" ? icon("check", "icon-sm state-ok")
            : (status === "changed" || status === "bad") ? icon("alert", "icon-sm state-danger") : null;
        return el("button", { class: "chat-item", "aria-current": String(name === current), onclick: () => openChat(name) },
            el("span", { class: "avatar", text: name[0] }),
            el("span", { class: "name" }, el("span", { text: name }), mark),
            el("span", { class: "when", text: last ? timeLabel(last.ts) : "" }),
            el("span", { class: "last", text: summary(last) }),
            d.unread[name] ? el("span", { class: "unread", "aria-label": "Unread" }) : el("span"));
    }));
}

function showEmptyConvo() {
    $("convoEmpty").hidden = false;
    $("convoMain").hidden = true;
}

export async function openChat(name) {
    current = name;
    $("convoEmpty").hidden = true;
    $("convoMain").hidden = false;
    $("peerName").textContent = name;
    $("peerAvatar").textContent = name[0];
    $("trustChip").dataset.state = "";
    $("bannerSlot").replaceChildren();
    delete vault.data().unread[name];
    vault.save();
    renderThread();
    renderChatList();
    $("appScreen").classList.add("chat-open");
    try {
        await loadPeer(name, true);
    } catch (e) {
        toast(e.message, "danger");
    }
    if (current === name) { paintTrust(); renderChatList(); }
    $("text").focus({ preventScroll: true });
}

// ======================================================================
// Drawing the conversation
// ======================================================================
function renderThread() {
    const items = vault.data().history[current] || [];
    const nodes = [];
    let lastDay = null;
    for (const item of items) {
        const day = dayLabel(item.ts);
        if (day !== lastDay) { nodes.push(el("div", { class: "day", text: day })); lastDay = day; }
        nodes.push(renderItem(item));
    }
    for (const card of liveSecrets[current] || []) nodes.push(card);
    if (!nodes.length) {
        nodes.push(el("div", { class: "thread-empty" },
            el("p", { text: "No messages with " + current + " yet." }),
            el("p", { text: "Before you share anything sensitive, compare your safety number." }),
            el("button", { class: "btn btn-quiet", onclick: () => openSafety(contactStatus(current) === "changed") }, icon("shield", "icon-sm"), el("span", { text: "Compare safety number" }))));
    }
    $("thread").replaceChildren(...nodes);
    scrollDown();
}

function scrollDown() {
    const t = $("thread");
    t.scrollTop = t.scrollHeight;
}

function renderItem(item) {
    if (item.kind === "notice") {
        return el("div", { class: "notice" + (item.tone === "neutral" ? " neutral" : ""), role: item.tone === "neutral" ? null : "alert" },
            icon(item.tone === "neutral" ? "info" : "alert", "icon-sm"), el("span", { text: item.text }));
    }
    if (item.sensitive) {
        return el("div", { class: "msg " + item.dir },
            el("div", { class: "bubble gone-bubble" }, icon("flame", "icon-sm"),
                el("span", { text: item.dir === "out" ? "Sensitive message (not kept on this device)" : "Sensitive message (opened once, not kept)" })),
            el("div", { class: "meta" }, el("span", { text: timeLabel(item.ts) })));
    }
    return el("div", { class: "msg " + item.dir },
        el("div", { class: "bubble", text: item.text }),
        el("div", { class: "meta" },
            el("span", { text: timeLabel(item.ts) }),
            el("button", { onclick: () => showProtection(item), "aria-label": "How this message was protected" },
                icon("lock", "icon-sm lock"), el("span", { text: item.dir === "out" ? "Sent encrypted" : "Encrypted" }))));
}

function addNotice(peer, text, tone) {
    const item = { kind: "notice", tone: tone || "danger", text, ts: Date.now() };
    vault.addHistory(peer, item);
    vault.save();
    if (peer === current) { $("thread").append(renderItem(item)); scrollDown(); }
    else vault.data().unread[peer] = true;
    renderChatList();
}

// "How was this protected?"
function showProtection(item) {
    let env = null;
    try { env = JSON.parse(item.wire); } catch (e) { /* older entry */ }
    const header = env ? env.header : {};
    const ctBytes = env ? Math.floor(env.ciphertext.replace(/=+$/, "").length * 3 / 4) : 0;
    const sender = item.dir === "out" ? me : header.sender;
    const facts = [
        ["Message number", String(header.counter ?? "?")],
        ["Encryption", "ChaCha20-Poly1305 with a key made only for this message number"],
        ["Signed by", sender + "'s identity key (Ed25519)" + (item.dir === "in" ? ", signature checked" : "")],
        ["Replay check", item.dir === "in" ? "Accepted: number was higher than any seen before" : "The receiver rejects this number if it ever arrives again"],
        ["Ciphertext", ctBytes + " bytes (your text plus a 16-byte tamper-check tag)"],
    ];
    $("protectFacts").replaceChildren(...facts.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]));
    $("protectWire").textContent = env ? JSON.stringify(env, null, 2) : "(not available for this message)";
    $("protectDialog").showModal();
}

// ======================================================================
// Sending
// ======================================================================
let sensitive = false;
let forcedByDlp = false;

export function setSensitive(on) {
    sensitive = on;
    $("sensitiveBtn").setAttribute("aria-pressed", String(on));
    $("options").hidden = !on;
}

export function onType() {
    const text = $("text");
    text.style.height = "auto";
    text.style.height = Math.min(text.scrollHeight, 140) + "px";
    const scan = DLP.scan(text.value);
    $("dlp").hidden = !scan.detected;
    if (scan.detected) {
        $("dlpText").textContent = "This looks like " + scan.reasons.join(", ") + ". It will be sent as a sensitive, view-once message.";
        setSensitive(true);
        $("oneTime").checked = true;
        forcedByDlp = true;
    } else if (forcedByDlp) {
        forcedByDlp = false;
    }
    $("sensitiveBtn").disabled = scan.detected;
}

function selectedTtl() {
    const b = $("ttlChips").querySelector('[aria-pressed="true"]');
    return b ? parseInt(b.dataset.ttl, 10) : 60;
}

export async function send() {
    const textBox = $("text");
    const value = textBox.value.trim();
    const peer = current;
    if (!value || !peer) return;

    let p;
    try {
        p = await loadPeer(peer, true); // always re-check keys right before encrypting
    } catch (e) {
        toast(e.message, "danger");
        return;
    }
    paintTrust();
    if (contactStatus(peer) === "changed" || contactStatus(peer) === "bad" || !p.shared) {
        toast("Not sent. " + peer + "'s key needs your review first.", "danger");
        return;
    }

    const d = vault.data();
    const isSensitive = sensitive || DLP.scan(value).detected;
    const ttl = isSensitive ? selectedTtl() : null;
    const counter = (d.out[peer] || 0) + 1;
    d.out[peer] = counter;
    vault.save();

    const header = {
        version: 2,
        sender: me,
        recipient: peer,
        counter,
        timestamp: Date.now(),
        is_sensitive: isSensitive,
        ttl_seconds: ttl,
        one_time_view: isSensitive ? $("oneTime").checked : false,
        require_passphrase: isSensitive && $("askPass").checked,
    };
    const messageKey = Crypto.deriveMessageKey(p.shared, counter);
    const envelope = Crypto.encryptEnvelope(myKeys.identity.privateKey, messageKey, value, header);
    Crypto.scrub(messageKey);
    const wire = JSON.stringify({ header, nonce: envelope.nonceB64, ciphertext: envelope.ciphertextB64, signature: envelope.signatureB64 });

    // Clear the composer right away, then play the seal animation while the request is in flight.
    textBox.value = "";
    textBox.style.height = "auto";
    $("dlp").hidden = true;
    $("sensitiveBtn").disabled = false;
    setSensitive(false);

    const bubble = el("div", { class: "bubble sealing", text: value });
    const meta = el("div", { class: "meta" }, el("span", { class: "spinner mini" }), el("span", { text: "Encrypting" }));
    const node = el("div", { class: "msg out" }, bubble, meta);
    $("thread").querySelector(".thread-empty")?.remove();
    $("thread").append(node);
    scrollDown();

    const sealed = envelope.ciphertextB64.slice(0, Math.max(16, Math.min(value.length + 12, 64)));
    const request = api("/api/messages", {
        method: "POST",
        body: JSON.stringify({ recipient: peer, payload: wire, is_sensitive: isSensitive, ttl_seconds: ttl }),
    });
    await scramble(bubble, value, sealed, 520);
    await sleep(240);

    let resp;
    try { resp = await request; } catch (e) { resp = null; }
    await scramble(bubble, sealed, value, 360);
    bubble.classList.remove("sealing");

    if (!resp || !resp.ok) {
        const why = resp ? await readError(resp) : "Can't reach the server.";
        meta.replaceChildren(icon("alert", "icon-sm"), el("span", { class: "failed", text: "Not sent. " + why }));
        node.classList.add("failed");
        return;
    }

    const item = { dir: "out", text: value, ts: header.timestamp, wire, sensitive: isSensitive };
    if (isSensitive) delete item.text; // sensitive text is never written to this device
    vault.addHistory(peer, item);
    vault.save();
    meta.replaceChildren(
        el("span", { text: timeLabel(header.timestamp) }),
        el("button", { onclick: () => showProtection({ ...item, text: value }), "aria-label": "How this message was protected" },
            icon(isSensitive ? "clock" : "lock", "icon-sm lock"),
            el("span", { text: isSensitive ? "Sensitive, disappears for " + peer : "Sent encrypted" })));
    renderChatList();
}

// ======================================================================
// Receiving
// ======================================================================
async function poll() {
    if (polling || !me) return;
    polling = true;
    try {
        ticks += 1;
        if (current && ticks % KEY_REFRESH_TICKS === 0) {
            try { await loadPeer(current, true); paintTrust(); renderChatList(); } catch (e) { /* shown on send */ }
        }
        const resp = await api(`/api/messages/${encodeURIComponent(me)}`);
        if (!resp.ok) { setLive(false); return; }
        setLive(true);
        const { messages } = await resp.json();
        for (const m of messages) {
            const id = m.id + "@" + m.created_at;
            if (vault.isProcessed(id)) continue;
            await handleIncoming(m, id);
        }
    } catch (e) {
        setLive(false);
    } finally {
        polling = false;
    }
}

function setLive(ok) {
    $("liveDot").classList.toggle("off", !ok);
    $("liveText").textContent = ok ? "Checking for new messages" : "Can't reach the server, retrying";
}

function deleteFromServer(m) {
    api(`/api/messages/${m.id}`, { method: "DELETE" }).catch(() => {});
}

// Store first, delete second: the server copy is removed only after the message is safely
// written to this device. If saving fails, the message stays on the server and is tried again.
function done(m, id) {
    vault.markProcessed(id);
    if (vault.flush()) deleteFromServer(m);
}

async function handleIncoming(m, id) {
    const sender = m.sender; // set by the server from the sender's session, so it can't be faked
    let env;
    try { env = JSON.parse(m.payload); } catch (e) { env = null; }
    if (!env || !env.header || env.header.version !== 2) {
        addNotice(sender, "Dropped a message from " + sender + " that wasn't in the encrypted format.");
        return done(m, id);
    }
    const header = env.header;
    if (header.sender !== sender || header.recipient !== me) {
        addNotice(sender, "Dropped a message whose sender or recipient didn't match its envelope.");
        return done(m, id);
    }

    let p;
    try { p = await loadPeer(sender, !peers[sender]); } catch (e) { return; }
    const status = contactStatus(sender);
    if (status === "changed") {
        // Hold it: don't decrypt with keys we haven't approved. It stays on the server until review.
        if (!vault.data().unread[sender]) { vault.data().unread[sender] = true; vault.save(); renderChatList(); }
        if (current === sender) paintTrust();
        return;
    }
    if (status === "bad" || !p.shared) {
        addNotice(sender, "Dropped a message from " + sender + " because their keys failed the signature check.");
        return done(m, id);
    }

    // Replay check: every message number may be used only once and must go up.
    const seen = vault.data().seen[sender] || 0;
    if (!Number.isInteger(header.counter) || header.counter <= seen) {
        addNotice(sender, "Blocked a replayed message from " + sender + " (message number " + header.counter + " was already used).");
        return done(m, id);
    }

    const messageKey = Crypto.deriveMessageKey(p.shared, header.counter);

    if (header.is_sensitive) {
        const ageSec = (Date.now() - header.timestamp) / 1000;
        if (header.ttl_seconds && ageSec > header.ttl_seconds) {
            Crypto.scrub(messageKey);
            addNotice(sender, "A sensitive message from " + sender + " expired before you opened it.", "neutral");
            vault.data().seen[sender] = header.counter;
            return done(m, id);
        }
        // Check signature + tag now (so tampering is caught at once), but keep the text hidden until "Reveal".
        let plaintext;
        try {
            plaintext = Crypto.decryptEnvelope(p.bundle.identity_pubkey, messageKey, env.nonce, env.ciphertext, header, env.signature);
        } catch (e) {
            Crypto.scrub(messageKey);
            addNotice(sender, "A message from " + sender + " failed its tamper check and was dropped.");
            return done(m, id);
        }
        Crypto.scrub(messageKey);
        vault.data().seen[sender] = header.counter;
        vault.addHistory(sender, { dir: "in", sensitive: true, ts: header.timestamp });
        vault.markProcessed(id);
        if (!vault.flush()) return;
        addSecretCard(sender, m, header, plaintext);
        return;
    }

    let plaintext;
    try {
        plaintext = Crypto.decryptEnvelope(p.bundle.identity_pubkey, messageKey, env.nonce, env.ciphertext, header, env.signature);
    } catch (e) {
        addNotice(sender, "A message from " + sender + " failed its tamper check and was dropped.");
        return done(m, id);
    } finally {
        Crypto.scrub(messageKey);
    }

    vault.data().seen[sender] = header.counter;
    const item = { dir: "in", text: plaintext, ts: header.timestamp, wire: m.payload };
    vault.addHistory(sender, item);
    if (sender !== current) vault.data().unread[sender] = true;
    done(m, id);
    if (sender === current) {
        $("thread").querySelector(".thread-empty")?.remove();
        $("thread").append(renderItem(item));
        scrollDown();
    }
    renderChatList();
}

// ---------- sensitive message card ----------
function addSecretCard(sender, m, header, plaintext) {
    const total = Math.max(1, Math.round(header.ttl_seconds - (Date.now() - header.timestamp) / 1000));
    let left = total;
    let windowTotal = total;
    const C = 2 * Math.PI * 14;
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    const track = document.createElementNS(ns, "circle");
    const arc = document.createElementNS(ns, "circle");
    for (const c of [track, arc]) { c.setAttribute("cx", "17"); c.setAttribute("cy", "17"); c.setAttribute("r", "14"); }
    track.setAttribute("class", "track");
    arc.setAttribute("class", "left");
    arc.style.strokeDasharray = String(C);
    svg.append(track, arc);
    const ringLabel = el("span", { text: String(left) });

    const rules = [header.one_time_view ? "View once." : "Disappears on its timer.", header.require_passphrase ? "Asks for your password." : ""].join(" ").trim();
    const textBox = el("div", { class: "secret-text veiled cipher", text: noise(Math.min(60, plaintext.length + 10)) });
    const reveal = el("button", { class: "btn btn-primary" }, icon("eye", "icon-sm"), el("span", { text: "Reveal" }));
    const burnBtn = el("button", { class: "btn btn-quiet" }, icon("flame", "icon-sm"), el("span", { text: "Burn now" }));
    const card = el("div", { class: "secret" },
        el("div", { class: "secret-head" },
            el("div", { class: "ring", "aria-label": "Seconds left" }, svg, ringLabel),
            el("div", { class: "title" }, el("span", { text: "Sensitive message" }), el("span", { class: "sub", text: rules }))),
        el("div", { class: "secret-body" }, textBox, el("div", { class: "secret-actions" }, reveal, burnBtn)));
    const wrap = el("div", { class: "msg in" }, card);

    (liveSecrets[sender] || (liveSecrets[sender] = [])).push(wrap);
    if (sender === current) {
        $("thread").querySelector(".thread-empty")?.remove();
        $("thread").append(wrap);
        scrollDown();
    } else {
        vault.data().unread[sender] = true;
        vault.save();
    }
    renderChatList();

    let secret = plaintext;
    let burned = false;
    let removed = false;
    const removeOnce = () => { if (!removed) { removed = true; deleteFromServer(m); } };
    const tick = () => {
        left -= 1;
        ringLabel.textContent = String(Math.max(0, left));
        arc.style.strokeDashoffset = String(C * (1 - Math.max(0, left) / windowTotal));
        if (left <= 0) burn("Expired");
    };
    let timer = setInterval(tick, 1000);

    async function burn(why) {
        if (burned) return;
        burned = true;
        clearInterval(timer);
        secret = null; // drop our only reference to the text
        removeOnce();
        card.classList.add("burning");
        await sleep(700);
        card.classList.add("gone");
        await sleep(420);
        const list = liveSecrets[sender] || [];
        liveSecrets[sender] = list.filter((x) => x !== wrap);
        const notice = el("div", { class: "notice neutral" }, icon("flame", "icon-sm"),
            el("span", { text: why + ": the sensitive message was destroyed and its key wiped." }));
        if (wrap.isConnected) wrap.replaceWith(notice);
    }
    burnBtn.addEventListener("click", () => burn("Burned"));
    reveal.addEventListener("click", async () => {
        if (header.require_passphrase) {
            const ok = await askPassword(async (pw) => vault.checkPassword(pw));
            if (!ok || burned) return;
        }
        reveal.disabled = true;
        if (header.one_time_view) removeOnce();
        textBox.classList.remove("veiled");
        await scramble(textBox, textBox.textContent, secret || "", 600);
        textBox.classList.remove("cipher");
        clearInterval(timer);
        left = Math.min(left, READ_WINDOW_SECONDS);
        windowTotal = left;
        arc.style.stroke = "var(--danger)";
        arc.style.strokeDashoffset = "0";
        timer = setInterval(tick, 1000);
    });
}

// ======================================================================
// New chat search
// ======================================================================
export async function search(query) {
    const box = $("searchResults");
    const q = query.trim().toLowerCase();
    if (!q) { box.hidden = true; return; }
    if (Date.now() - usersCache.at > 15000) {
        const resp = await api("/api/users");
        if (resp.ok) usersCache = { at: Date.now(), list: await resp.json() };
    }
    const hits = usersCache.list.filter((u) => u.includes(q) && u !== me).slice(0, 8);
    box.replaceChildren(...(hits.length
        ? hits.map((u) => el("button", { onclick: () => { box.hidden = true; $("search").value = ""; openChat(u); } },
            el("span", { class: "avatar", text: u[0] }), el("span", { text: u })))
        : [el("div", { class: "empty", text: "No one called “" + q + "”. Usernames are exact." })]));
    box.hidden = false;
}

// ======================================================================
// Wiring that only needs to happen once
// ======================================================================
export function wire() {
    $("text").addEventListener("input", onType);
    $("text").addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
    });
    $("sendBtn").addEventListener("click", send);
    $("sensitiveBtn").addEventListener("click", () => setSensitive(!sensitive));
    $("ttlChips").addEventListener("click", (e) => {
        const b = e.target.closest("button");
        if (!b) return;
        for (const c of $("ttlChips").children) c.setAttribute("aria-pressed", String(c === b));
    });
    $("trustChip").addEventListener("click", () => openSafety(contactStatus(current) === "changed"));
    $("safetyConfirm").addEventListener("click", confirmSafety);
    $("safetyLater").addEventListener("click", () => $("safetyDialog").close());
    $("protectClose").addEventListener("click", () => $("protectDialog").close());
    $("backBtn").addEventListener("click", () => $("appScreen").classList.remove("chat-open"));
    let searchTimer = null;
    $("search").addEventListener("input", () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => search($("search").value).catch(() => {}), 120);
    });
    $("search").addEventListener("keydown", (e) => {
        if (e.key === "Escape") { $("search").value = ""; $("searchResults").hidden = true; }
        if (e.key === "Enter") { const first = $("searchResults").querySelector("button"); if (first) first.click(); }
    });
    document.addEventListener("click", (e) => {
        if (!e.target.closest(".search")) $("searchResults").hidden = true;
    });
    // Browsers slow down timers in background tabs; check straight away when the tab is back.
    document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });
    window.addEventListener("focus", () => poll());
}
