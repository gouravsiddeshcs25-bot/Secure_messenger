// Small DOM helpers for the v2 client.
// Everything goes through textContent / createElement: we never build HTML from strings,
// so a username or message can't inject markup or scripts (XSS).

export const $ = (id) => document.getElementById(id);
export const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
export const sleep = (ms) => new Promise((r) => setTimeout(r, reduceMotion ? 0 : ms));
export const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));

export function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
        if (v == null || v === false) continue;
        if (k === "class") node.className = v;
        else if (k === "text") node.textContent = v;
        else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
        else node.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children) if (c != null && c !== false) node.append(c);
    return node;
}

export function icon(name, cls) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "icon " + (cls || ""));
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS(ns, "use");
    use.setAttribute("href", "#i-" + name);
    svg.append(use);
    return svg;
}

export function toast(text, kind) {
    const t = el("div", { class: "toast" + (kind === "danger" ? " toast-danger" : "") },
        icon(kind === "danger" ? "alert" : "check"), el("span", { text }));
    $("toasts").append(t);
    setTimeout(() => { t.classList.add("leaving"); setTimeout(() => t.remove(), 200); }, kind === "danger" ? 5000 : 3200);
}

// ---------- the "seal" animation: text scrambles into ciphertext-looking characters and back ----------
const CIPHER_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

// Only for the animation. Real ciphertext comes from crypto.js.
export function noise(len) {
    let s = "";
    for (let i = 0; i < len; i++) s += CIPHER_CHARS[Math.floor(Math.random() * CIPHER_CHARS.length)];
    return s;
}

export function scramble(node, from, to, ms) {
    return new Promise((resolve) => {
        if (reduceMotion) { node.textContent = to; return resolve(); }
        const len = Math.max(from.length, to.length);
        const start = performance.now();
        function frame(now) {
            const p = Math.min(1, (now - start) / ms);
            const settled = Math.floor(p * len);
            let out = "";
            for (let i = 0; i < len; i++) {
                if (i < settled) out += to[i] || "";
                else if (to[i] === " " || from[i] === " " || to[i] === "\n") out += to[i] === "\n" ? "\n" : " ";
                else out += CIPHER_CHARS[Math.floor(Math.random() * CIPHER_CHARS.length)];
            }
            node.textContent = out;
            if (p < 1) requestAnimationFrame(frame); else { node.textContent = to; resolve(); }
        }
        requestAnimationFrame(frame);
    });
}

// ---------- dialogs ----------
// confirmDialog({title, text, ok, cancel, danger}) -> Promise<boolean>
export function confirmDialog({ title, text, ok, cancel, danger }) {
    return new Promise((resolve) => {
        const d = $("confirmDialog");
        $("confirmTitle").textContent = title;
        $("confirmText").textContent = text;
        const okBtn = $("confirmOk");
        okBtn.textContent = ok || "Continue";
        okBtn.className = "btn " + (danger ? "btn-danger" : "btn-primary");
        $("confirmCancel").textContent = cancel || "Cancel";
        const finish = (v) => { okBtn.onclick = $("confirmCancel").onclick = d.oncancel = null; d.close(); resolve(v); };
        okBtn.onclick = () => finish(true);
        $("confirmCancel").onclick = () => finish(false);
        d.oncancel = (e) => { e.preventDefault(); finish(false); };
        d.showModal();
        okBtn.focus();
    });
}

// askPassword(check) -> Promise<boolean>. `check` is an async function that verifies the password.
export function askPassword(check) {
    return new Promise((resolve) => {
        const d = $("passDialog");
        const input = $("passInput");
        const hint = $("passHint");
        input.value = "";
        hint.textContent = "";
        const finish = (v) => { $("passOk").onclick = $("passCancel").onclick = $("passForm").onsubmit = d.oncancel = null; d.close(); resolve(v); };
        const submit = async () => {
            $("passOk").disabled = true;
            hint.textContent = "Checking…";
            await nextFrame();
            const ok = await check(input.value);
            $("passOk").disabled = false;
            if (ok) finish(true);
            else { hint.textContent = "That password is not right."; input.select(); }
        };
        $("passOk").onclick = submit;
        $("passForm").onsubmit = (e) => { e.preventDefault(); submit(); };
        $("passCancel").onclick = () => finish(false);
        d.oncancel = (e) => { e.preventDefault(); finish(false); };
        d.showModal();
        input.focus();
    });
}

export function timeLabel(ts) {
    return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function dayLabel(ts) {
    const d = new Date(ts);
    const today = new Date();
    const yest = new Date(); yest.setDate(today.getDate() - 1);
    if (d.toDateString() === today.toDateString()) return "Today";
    if (d.toDateString() === yest.toDateString()) return "Yesterday";
    return d.toLocaleDateString([], { weekday: "long", day: "numeric", month: "short" });
}
