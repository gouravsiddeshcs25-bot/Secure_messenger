// The vault: everything this browser keeps for one user, encrypted with their password.
//
// localStorage["sm2.vault.<username>"] = { v, salt, keys: <sealed>, data: <sealed> }
//   salt  : random Argon2id salt (not secret)
//   keys  : private keys, sealed with XChaCha20-Poly1305 (Crypto.sealLocal)
//   data  : contacts (first-seen identity keys + verified flag), message counters, processed ids,
//           chat history and unread flags, also sealed
// The storage key is derived from the password with Argon2id (Crypto.derivePassphraseKey) and only
// kept in memory while signed in. Nothing readable is written to storage.

const PREFIX = "sm2.vault.";
const MAX_PROCESSED = 2000;
const MAX_HISTORY = 300;

let storageKey = null;
let record = null;
let state = null;
let user = null;
let saveTimer = null;

function emptyState() {
    return { contacts: {}, out: {}, seen: {}, processed: [], history: {}, unread: {} };
}

function read(username) {
    try {
        const raw = localStorage.getItem(PREFIX + username);
        return raw ? JSON.parse(raw) : null;
    } catch (e) {
        return null;
    }
}

export function hasVault(username) {
    return !!read(username);
}

// Sign-up (or a new browser): seal freshly generated keys with the password.
export function create(username, password, keys) {
    const { key, saltB64 } = Crypto.derivePassphraseKey(password);
    storageKey = key;
    user = username;
    state = emptyState();
    record = { v: 1, salt: saltB64, keys: Crypto.sealLocal(key, Crypto.exportKeys(keys)), data: null };
    saveNow();
}

// Sign-in on a browser that already has a vault. Throws if the password can't open it.
export function unlock(username, password) {
    const rec = read(username);
    if (!rec) throw new Error("No keys for this account on this browser.");
    const { key } = Crypto.derivePassphraseKey(password, rec.salt);
    let keysObj;
    try {
        keysObj = Crypto.openLocal(key, rec.keys);
    } catch (e) {
        Crypto.scrub(key);
        throw new Error("This browser's saved keys can't be opened with that password.");
    }
    storageKey = key;
    record = rec;
    user = username;
    try {
        state = Object.assign(emptyState(), rec.data ? Crypto.openLocal(key, rec.data) : {});
    } catch (e) {
        state = emptyState(); // data damaged: keep the keys, start a fresh history
    }
    return Crypto.importKeys(keysObj);
}

// Re-checks the password locally (used for "ask for password to open"). Doesn't keep the password.
export function checkPassword(password) {
    if (!record) return false;
    const { key } = Crypto.derivePassphraseKey(password, record.salt);
    try {
        Crypto.openLocal(key, record.keys);
        return true;
    } catch (e) {
        return false;
    } finally {
        Crypto.scrub(key);
    }
}

export function data() { return state; }

export function markProcessed(id) {
    state.processed.push(id);
    if (state.processed.length > MAX_PROCESSED) state.processed.splice(0, state.processed.length - MAX_PROCESSED);
}

export function isProcessed(id) { return state.processed.includes(id); }

export function addHistory(peer, item) {
    const list = state.history[peer] || (state.history[peer] = []);
    list.push(item);
    if (list.length > MAX_HISTORY) list.splice(0, list.length - MAX_HISTORY);
}

export function save() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, 250);
}

function saveNow() {
    if (!storageKey || !record) return;
    record.data = Crypto.sealLocal(storageKey, state);
    try {
        localStorage.setItem(PREFIX + user, JSON.stringify(record));
    } catch (e) {
        console.warn("Could not save the vault (storage full or blocked).");
    }
}

// Sign out: write the last changes, then forget the key and data in memory.
export function lock() {
    clearTimeout(saveTimer);
    saveNow();
    Crypto.scrub(storageKey);
    storageKey = null;
    record = null;
    state = null;
    user = null;
}
