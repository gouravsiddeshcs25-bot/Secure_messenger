// Secure Messenger v2: start-up, sign in / create account, sign out, theme.
// Flow on sign-up : create account -> generate keys in this browser -> seal them with the password -> publish public keys.
// Flow on sign-in : check password -> open this browser's sealed keys (or make new ones on a new browser) -> load chats.

import { $, el, icon, toast, sleep, nextFrame, confirmDialog } from "./dom.js";
import { api, readError, setToken, whenUnauthorized } from "./api.js";
import * as vault from "./vault.js";
import * as chat from "./chat.js";

let mode = "login";

// ---------- theme ----------
function currentTheme() {
    return document.documentElement.dataset.theme
        || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}
function paintThemeIcon() {
    $("themeBtn").querySelector("use").setAttribute("href", currentTheme() === "dark" ? "#i-sun" : "#i-moon");
}
try { const t = localStorage.getItem("sm.theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; } catch (e) { /* storage blocked */ }
$("themeBtn").addEventListener("click", () => {
    const next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("sm.theme", next); } catch (e) { /* ignore */ }
    paintThemeIcon();
});
paintThemeIcon();

// ---------- screens ----------
function show(screen) {
    for (const id of ["authScreen", "appScreen"]) {
        const node = $(id);
        node.hidden = id !== screen;
        if (id === screen) { node.classList.remove("entering"); void node.offsetWidth; node.classList.add("entering"); }
    }
}

// ---------- sign-in form ----------
$("authTabs").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-mode]");
    if (!b) return;
    mode = b.dataset.mode;
    $("authTabs").dataset.index = mode === "login" ? "0" : "1";
    for (const t of $("authTabs").querySelectorAll("button")) t.setAttribute("aria-selected", String(t === b));
    $("authTitle").textContent = mode === "login" ? "Sign in" : "Create your account";
    $("authSubmit").textContent = mode === "login" ? "Sign in" : "Create account";
    $("password").autocomplete = mode === "login" ? "current-password" : "new-password";
    setFormError("");
});
$("showPass").addEventListener("click", () => {
    const shown = $("password").type === "text";
    $("password").type = shown ? "password" : "text";
    $("showPass").querySelector("use").setAttribute("href", shown ? "#i-eye" : "#i-eye-off");
    $("showPass").setAttribute("aria-label", shown ? "Show password" : "Hide password");
});
for (const f of [$("userField"), $("passField")]) f.dataset.hint = f.querySelector(".field-hint").textContent;
function setFieldError(field, msg) {
    field.classList.toggle("has-error", !!msg);
    field.querySelector(".field-hint").textContent = msg || field.dataset.hint;
}
function setFormError(msg) {
    $("formError").textContent = msg;
    $("formError").hidden = !msg;
}

// Runs the sign-in steps one by one, ticking each off as its real work finishes.
async function runSteps(steps) {
    const list = $("authSteps");
    const items = steps.map(([label]) => el("li", {}, el("span", { class: "dot" }), el("span", { text: label })));
    list.replaceChildren(...items);
    list.hidden = false;
    $("authForm").hidden = true;
    setFormError("");
    let result;
    for (let i = 0; i < steps.length; i++) {
        items[i].classList.add("active");
        await nextFrame(); // let the step show before heavy work (Argon2id) blocks the page
        const started = performance.now();
        result = await steps[i][1](result);
        const spent = performance.now() - started;
        if (spent < 350) await sleep(350 - spent); // keep each step readable
        items[i].classList.remove("active");
        items[i].classList.add("done");
        items[i].querySelector(".dot").append(icon("check"));
    }
    await sleep(250);
    return result;
}

function resetForm() {
    $("authSteps").hidden = true;
    $("authForm").hidden = false;
    $("authSubmit").disabled = false;
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

async function authenticate(path, username, password) {
    const resp = await api(path, { method: "POST", body: JSON.stringify({ username, password }) });
    if (!resp.ok) throw new Error(await readError(resp));
    const session = await resp.json();
    if (!session.token) throw new Error("The server didn't return a session. Restart it and try again.");
    setToken(session.token);
    return session.username;
}

async function signUp(username, password) {
    let keys;
    return runSteps([
        ["Creating your account", () => authenticate("/api/register", username, password)],
        ["Generating keys in this browser", () => { keys = Crypto.generateUserKeys(); }],
        ["Locking them with your password", () => vault.create(username, password, keys)],
        ["Publishing your public keys", () => publishKeys(keys)],
    ]).then(() => keys);
}

async function signIn(username, password) {
    let keys = null;
    await runSteps([
        ["Checking your password", () => authenticate("/api/login", username, password)],
        ["Unlocking your keys on this device", async () => {
            if (vault.hasVault(username)) {
                try {
                    keys = vault.unlock(username, password);
                    return;
                } catch (e) {
                    // The account exists, but this browser's saved keys belong to an older account with this name.
                }
            }
            const ok = await confirmDialog({
                title: "No keys for " + username + " on this browser",
                text: "Your private keys never leave the browser that made them. If you continue, this browser makes new keys. "
                    + "People you chat with will see that your security key changed, and messages sent to your old keys can't be read here.",
                ok: "Make new keys",
                cancel: "Cancel",
            });
            if (!ok) throw new Error("Sign-in cancelled. Use the browser where you created the account, or make new keys.");
            keys = Crypto.generateUserKeys();
            vault.create(username, password, keys);
        }],
        ["Loading your chats", async () => {
            // Make sure the server has this browser's public keys (another browser may have replaced them).
            const resp = await api(`/api/keys/${encodeURIComponent(username)}`);
            const onServer = resp.ok ? await resp.json() : null;
            if (!onServer || onServer.identity_pubkey !== keys.identity.publicKeyB64) {
                await publishKeys(keys);
                if (onServer) toast("This browser is now your active device.");
            }
        }],
    ]);
    return keys;
}

$("authForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = $("username").value.trim().toLowerCase();
    const password = $("password").value;
    let ok = true;
    if (!/^[a-z0-9_-]{1,50}$/.test(username)) { setFieldError($("userField"), "Use 1–50 lowercase letters, numbers, _ or -"); ok = false; } else setFieldError($("userField"));
    if (mode === "register" && password.length < 8) { setFieldError($("passField"), "Password needs at least 8 characters"); ok = false; }
    else if (!password) { setFieldError($("passField"), "Enter your password"); ok = false; }
    else setFieldError($("passField"));
    if (!ok) return;

    $("authSubmit").disabled = true;
    try {
        await Crypto.init();
        const keys = mode === "register" ? await signUp(username, password) : await signIn(username, password);
        $("password").value = "";
        resetForm();
        show("appScreen");
        chat.start(username, keys);
        toast(mode === "register" ? "Account created. Your keys are locked on this device." : "Signed in as " + username);
    } catch (err) {
        setToken(null);
        vault.lock();
        resetForm();
        setFormError(err.message);
    }
});

// ---------- sign out ----------
function signOutLocal(message) {
    chat.stop();
    vault.lock();
    setToken(null);
    $("appScreen").classList.remove("chat-open");
    show("authScreen");
    if (message) toast(message);
}
$("logoutBtn").addEventListener("click", async () => {
    try { await api("/api/logout", { method: "POST" }); } catch (e) { /* sign out locally anyway */ }
    signOutLocal("Signed out. Your keys stay locked on this device.");
});
whenUnauthorized(() => signOutLocal("Your session ended. Sign in again."));

// ---------- boot ----------
chat.wire();
Crypto.init().then(() => {
    $("cryptoStatus").hidden = true;
}).catch(() => {
    setFormError("The encryption library didn't load. Reload the page.");
});
