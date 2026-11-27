// Every v2 API call goes through api(), so the session token is always attached.
// The token lives only in this module's memory (never localStorage): reloading the page signs you out.

let token = null;
let onUnauthorized = () => {};

export function setToken(t) { token = t; }
export function hasToken() { return !!token; }
export function whenUnauthorized(fn) { onUnauthorized = fn; }

export async function api(path, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (options.body) headers["Content-Type"] = "application/json";
    if (token) headers["Authorization"] = "Bearer " + token;
    const resp = await fetch(path, Object.assign({}, options, { headers }));
    if (resp.status === 401 && token) {
        token = null;
        onUnauthorized();
    }
    return resp;
}

// Turns an error response into one plain sentence for the user.
export async function readError(resp) {
    try {
        const data = await resp.json();
        if (typeof data.detail === "string") return data.detail;
        if (Array.isArray(data.detail) && data.detail.length) {
            const field = (data.detail[0].loc || []).slice(-1)[0];
            if (field === "password") return "Password must be 8 to 128 characters.";
            if (field === "username") return "Username must be 1 to 50 characters: a-z, 0-9, _ or -.";
        }
    } catch (e) { /* not JSON */ }
    if (resp.status === 429) return "Too many attempts. Wait a minute and try again.";
    return "The server answered " + resp.status + ". Try again.";
}
