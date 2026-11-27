// CipherBridge Mini App: the v2 messenger, signed in through Telegram.
//
// Flow:
// 1. Telegram opens this page and gives it Telegram.WebApp.initData (signed by Telegram).
// 2. We send that string to /api/tg/auth. The SERVER checks Telegram's signature and gives back a session for
//    the account tg_<telegram id>. We never trust initDataUnsafe or any name from the page itself.
// 3. The private keys live in this device's storage, locked with a PIN (Argon2id, same vault as the web app).
// 4. Then it's the normal v2 chat (chat.js). On top of that, any message can be sealed as a 🔒SM2 text
//    and shared into a Telegram chat, where Telegram only sees ciphertext.
//
// Telegram Mini App API: https://core.telegram.org/bots/webapps

import { $, el, icon, toast, sleep, nextFrame, confirmDialog } from "/v2/js/dom.js";
import { api, readError, setToken, whenUnauthorized } from "/v2/js/api.js";
import * as vault from "/v2/js/vault.js";
import * as chat from "/v2/js/chat.js";
import { PREFIX } from "/v2/js/sm2.js";

const tg = window.Telegram && window.Telegram.WebApp;
const inTelegram = !!(tg && tg.initData);
const MIN_PIN = 6;

let session = null;     // { username, first_name, new_account } from /api/tg/auth
let pinMode = "unlock"; // "unlock" | "create"
let signedInAs = null;

// ---------- Telegram look ----------
function followTelegramTheme() {
    if (!tg) return;
    document.documentElement.dataset.theme = tg.colorScheme === "dark" ? "dark" : "light";
    try {
        if (tg.isVersionAtLeast("6.1")) {
            const bg = getComputedStyle(document.documentElement).getPropertyValue("--surface").trim();
            tg.setHeaderColor(bg);
            tg.setBackgroundColor(bg);
        }
    } catch (e) { /* older Telegram app: keep its colours */ }
}
if (tg) {
    tg.ready();
    tg.expand();
    followTelegramTheme();
    tg.onEvent("themeChanged", followTelegramTheme);
}

// ---------- one active tab per account (same rule as the web app) ----------
const tabId = Math.random().toString(36).slice(2); // only identifies this tab, not security-related
let tabs = null;
try { tabs = new BroadcastChannel("sm2-tabs"); } catch (e) { /* the vault version check still protects data */ }
if (tabs) {
    tabs.onmessage = (e) => {
        const m = e.data || {};
        if (m.type === "active" && m.user === signedInAs && m.tab !== tabId) lockAndRestart("You opened this account somewhere else, so it was locked here.");
    };
}

// ---------- small UI helpers ----------
function setError(msg) {
    $("formError").textContent = msg || "";
    $("formError").hidden = !msg;
}

async function runSteps(steps) {
    const list = $("authSteps");
    const items = steps.map(([label]) => el("li", {}, el("span", { class: "dot" }), el("span", { text: label })));
    list.replaceChildren(...items);
    list.hidden = false;
    $("pinForm").hidden = true;
    setError("");
    try {
        for (let i = 0; i < steps.length; i++) {
            items[i].classList.add("active");
            await nextFrame(); // show the step before heavy work (Argon2id) blocks the page
            const started = performance.now();
            await steps[i][1]();
            const spent = performance.now() - started;
            if (spent < 300) await sleep(300 - spent);
            items[i].classList.remove("active");
            items[i].classList.add("done");
            items[i].querySelector(".dot").append(icon("check"));
        }
        await sleep(200);
    } finally {
        list.hidden = true;
    }
}

function showPinForm(mode) {
    pinMode = mode;
    const create = mode === "create";
    $("tgTitle").textContent = create ? "Choose a PIN" : "Welcome back" + (session.first_name ? ", " + session.first_name : "");
    $("tgLede").textContent = create
        ? "Your keys are made on this device and locked with this PIN. Nobody else, not even our server, can unlock them."
        : "Enter your PIN to unlock your keys on this device.";
    $("pinLabel").textContent = create ? "New PIN" : "Your PIN";
    $("pinHint").textContent = create ? "At least " + MIN_PIN + " characters" : "";
    $("pin2Field").hidden = !create;
    $("pinSubmit").textContent = create ? "Create my keys" : "Unlock";
    $("forgotPin").hidden = create;
    $("pin").value = "";
    $("pin2").value = "";
    $("pinField").classList.remove("has-error");
    $("pinForm").hidden = false;
    $("pin").focus();
}

async function publishKeys(keys) {
    const resp = await api("/api/keys", {
        method: "POST",
        body: JSON.stringify({
            identity_pubkey: keys.identity.publicKeyB64,
            exchange_pubkey: keys.exchange.publicKeyB64,
            key_signature: keys.keySignatureB64,
        }),
    });
    if (!resp.ok) throw new Error("Couldn't publish your public keys: " + (await readError(resp)));
}

async function serverKeys() {
    const resp = await api(`/api/keys/${encodeURIComponent(session.username)}`);
    return resp.ok ? resp.json() : null;
}

// ---------- start-up ----------
async function boot() {
    chat.wire();
    if (!inTelegram) {
        $("tgLede").textContent = "End-to-end encrypted messages inside Telegram.";
        $("notInTelegram").hidden = false;
        return;
    }
    try {
        await runSteps([
            ["Loading the encryption library", () => Crypto.init()],
            ["Checking your Telegram sign-in", async () => {
                const resp = await api("/api/tg/auth", { method: "POST", body: JSON.stringify({ init_data: tg.initData }) });
                if (!resp.ok) throw new Error(await readError(resp));
                session = await resp.json();
                setToken(session.token);
            }],
        ]);
    } catch (e) {
        setError(e.message + (e.message.includes("expired") ? "" : " Close CipherBridge and open it again from the bot."));
        return;
    }
    showPinForm(vault.hasVault(session.username) ? "unlock" : "create");
}

$("pinForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pin = $("pin").value;
    if (pin.length < MIN_PIN) {
        $("pinField").classList.add("has-error");
        $("pinHint").textContent = "Use at least " + MIN_PIN + " characters";
        return;
    }
    if (pinMode === "create" && pin !== $("pin2").value) {
        $("pinField").classList.add("has-error");
        $("pinHint").textContent = "The two PINs are different";
        return;
    }
    $("pinSubmit").disabled = true;
    try {
        const keys = pinMode === "create" ? await createKeys(pin) : await unlockKeys(pin);
        if (keys) enter(keys);
    } catch (err) {
        vault.lock({ save: false });
        setError(err.message);
        showPinForm(pinMode);
    } finally {
        $("pinSubmit").disabled = false;
    }
});

async function unlockKeys(pin) {
    let keys = null;
    await runSteps([
        ["Unlocking your keys", () => {
            try { keys = vault.unlock(session.username, pin); }
            catch (e) { throw new Error("That PIN is not right."); }
        }],
        ["Loading your chats", async () => {
            const onServer = await serverKeys();
            if (!onServer || onServer.identity_pubkey !== keys.identity.publicKeyB64) {
                await publishKeys(keys);
                if (onServer) toast("This device is now your active device.");
            }
        }],
    ]);
    return keys;
}

async function createKeys(pin) {
    // A returning user on a new phone already has keys on the server from another device.
    if (!session.new_account && await serverKeys()) {
        const ok = await confirmDialog({
            title: "Make new keys on this device?",
            text: "Your old private keys stay on the device that made them. With new keys, people you chat with "
                + "will see that your security key changed, and messages sealed for your old keys can't be opened here.",
            ok: "Make new keys",
            cancel: "Cancel",
        });
        if (!ok) { showPinForm("create"); return null; }
    }
    let keys = null;
    await runSteps([
        ["Generating keys on this device", () => { keys = Crypto.generateUserKeys(); }],
        ["Locking them with your PIN", () => vault.create(session.username, pin, keys)],
        ["Publishing your public keys", () => publishKeys(keys)],
    ]);
    return keys;
}

$("forgotPin").addEventListener("click", async () => {
    const ok = await confirmDialog({
        title: "Forgot your PIN?",
        text: "The PIN is the only way to open your saved keys, and nobody can reset it. You can make new keys instead: "
            + "your old chats on this device are lost and your contacts will see that your key changed.",
        ok: "Make new keys",
        cancel: "Cancel",
        danger: true,
    });
    if (ok) showPinForm("create");
});

function enter(keys) {
    signedInAs = session.username;
    $("pin").value = "";
    $("pin2").value = "";
    if (tabs) tabs.postMessage({ type: "active", user: signedInAs, tab: tabId });
    vault.whenConflict(() => lockAndRestart("This account was opened somewhere else, so it was locked here."));
    chat.setShareHandler(shareToTelegram);
    $("authScreen").hidden = true;
    $("appScreen").hidden = false;
    chat.start(session.username, keys);
    // Others find you by your account name (tg_ + your Telegram id), so show it next to your first name.
    if (session.first_name) $("meName").textContent = session.first_name + " (" + session.username + ")";
    toast(pinMode === "create" ? "Your keys are ready and locked with your PIN." : "Unlocked");

    // The bot's "Decrypt" button opens us with ?m=<sealed message>.
    const pending = new URLSearchParams(location.search).get("m");
    if (pending) chat.promptOpen(PREFIX + pending);
}

// ---------- share a 🔒SM2 text into a Telegram chat ----------
async function shareToTelegram(text) {
    // Best: Telegram's own share sheet (Bot API 8.0+). Our server asks Telegram to prepare the message.
    if (tg.isVersionAtLeast("8.0") && typeof tg.shareMessage === "function") {
        const resp = await api("/api/tg/share", { method: "POST", body: JSON.stringify({ text }) });
        if (resp.ok) {
            const { prepared_id } = await resp.json();
            tg.shareMessage(prepared_id, (sent) => { if (sent) toast("Shared. Only the person you sealed it for can open it."); });
            return;
        }
    }
    // Fallback: Telegram's share link, which lets the user pick a chat with the text filled in.
    tg.openTelegramLink("https://t.me/share/url?url=" + encodeURIComponent(text));
}

// ---------- locking ----------
function lockAndRestart(message) {
    signedInAs = null;
    chat.stop();
    vault.lock({ save: false });
    setToken(null);
    toast(message);
    setTimeout(() => location.reload(), 1200);
}

$("logoutBtn").setAttribute("aria-label", "Lock");
$("logoutBtn").addEventListener("click", async () => {
    try { await api("/api/logout", { method: "POST" }); } catch (e) { /* lock locally anyway */ }
    signedInAs = null;
    chat.stop();
    vault.lock();
    setToken(null);
    location.reload();
});
whenUnauthorized(() => { if (signedInAs) lockAndRestart("Your session ended. Opening again."); });

boot();
