// PhantomVault native bridge client (MV3 service worker).
// Host name MUST match the registry manifest installed by the desktop app:
//   HKCU\...\NativeMessagingHosts\com.phantomvault.host
// Persistent port: one host process serves the whole burst (one Argon2id,
// then ~5ms frames) until the 60s host TTL, browser disconnect, or SW
// suspend. Falls back to one-shot connectNative per request if the shared
// port dies. NOTE: the host serves its spawn-time vault snapshot — desktop
// mutations land on the bridge after the TTL window (documented, not a bug).
const HOST_PORT = "com.phantomvault.host";

// E1/E2: shared registrable-domain + equivalent-cluster helpers. A classic
// MV3 service worker, so importScripts() runs synchronously before any use.
importScripts("domain.js");

// Base-domains already pushed to the desktop favicon cache this SW
// lifetime (harvest is idempotent server-side; this just saves fetches).
const faviconPushed = new Set();

// K2: chrome.storage.session defaults to TRUSTED_CONTEXTS only, so content
// scripts CANNOT read the cross-navigation carry (`pvCaptureCarry`,
// `pvPending`). Grant content-script access once per SW lifetime; missing on
// older builds → optional-call, carry simply stays in-tab.
try {
  if (chrome.storage && chrome.storage.session && chrome.storage.session.setAccessLevel) {
    chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" });
  }
} catch (_) {}

// ---- Persistent-port session (FIFO, one in-flight frame) ----
// The host does NOT echo request ids, so multiplexing is by strict
// request→reply ordering: exactly one frame in flight per port.
let sharedPort = null;
let portAlive = false;
const requestQueue = [];
let inflight = null;

function dropSharedPort() {
  const p = sharedPort;
  sharedPort = null;
  portAlive = false;
  try { if (p) p.disconnect(); } catch (_) { /* already gone */ }
}

function ensurePort() {
  if (sharedPort && portAlive) return sharedPort;
  dropSharedPort();
  const port = chrome.runtime.connectNative(HOST_PORT);
  sharedPort = port;
  portAlive = true;
  port.onMessage.addListener((msg) => {
    const cur = inflight;
    inflight = null;
    if (cur) {
      clearTimeout(cur.timer);
      cur.resolve(msg);
    }
    pumpQueue();
  });
  port.onDisconnect.addListener(() => {
    const errMsg = chrome.runtime.lastError
      ? chrome.runtime.lastError.message
      : "native host disconnected (is PhantomVault installed?)";
    portAlive = false;
    sharedPort = null;
    // Fail the in-flight frame and every queued frame; callers retry
    // via the one-shot fallback path below.
    const cur = inflight;
    inflight = null;
    if (cur) {
      clearTimeout(cur.timer);
      cur.reject(new Error(errMsg));
    }
    while (requestQueue.length) {
      const q = requestQueue.shift();
      clearTimeout(q.timer);
      q.reject(new Error(errMsg));
    }
  });
  return port;
}

function pumpQueue() {
  if (inflight || !requestQueue.length) return;
  let port;
  try {
    port = ensurePort();
  } catch (e) {
    const q = requestQueue.shift();
    clearTimeout(q.timer);
    q.reject(e instanceof Error ? e : new Error(String(e)));
    return;
  }
  // Dequeue the head into inflight BEFORE posting: exactly one frame is
  // ever on the wire, so replies always belong to `inflight`.
  const head = requestQueue.shift();
  inflight = head;
  try {
    port.postMessage(head.payload);
  } catch (e) {
    inflight = null;
    clearTimeout(head.timer);
    dropSharedPort();
    head.reject(e instanceof Error ? e : new Error(String(e)));
    pumpQueue();
  }
}

function hostRequest(payload, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const entry = { payload, resolve, reject, timer: 0 };
    entry.timer = setTimeout(() => {
      // Remove from wherever it sits (queued or in-flight on a dead port).
      const qi = requestQueue.indexOf(entry);
      if (qi >= 0) requestQueue.splice(qi, 1);
      if (inflight === entry) {
        inflight = null;
        dropSharedPort();
        pumpQueue();
      }
      reject(new Error("native host timeout"));
    }, timeoutMs);
    requestQueue.push(entry);
    try {
      pumpQueue();
    } catch (e) {
      // ensurePort threw synchronously (host missing) — one-shot fallback.
      oneShotRequest(payload, timeoutMs).then(resolve, reject);
    }
  });
}

// One-shot fallback: fresh host process per request (legacy behavior).
// Used only when the shared port cannot be established.
function oneShotRequest(payload, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let port;
    try {
      port = chrome.runtime.connectNative(HOST_PORT);
    } catch (e) {
      reject(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    const done = (fn, arg) => {
      clearTimeout(timer);
      try { port.disconnect(); } catch (_) { /* already gone */ }
      fn(arg);
    };
    const timer = setTimeout(
      () => done(reject, new Error("native host timeout")),
      timeoutMs
    );
    port.onMessage.addListener((msg) => done(resolve, msg));
    port.onDisconnect.addListener(() => {
      const err = chrome.runtime.lastError
        ? chrome.runtime.lastError.message
        : "native host disconnected (is PhantomVault installed?)";
      done(reject, new Error(err));
    });
    try {
      port.postMessage(payload);
    } catch (e) {
      done(reject, e instanceof Error ? e : new Error(String(e)));
    }
  });
}

// ---- Desktop-synced session + inactivity auto-lock ----
// The extension holds NO lock of its own: unlocked = desktop vault reachable.
// On top, user activity (autofill/popup use) refreshes a timestamp kept in
// session storage (memory-only, cleared on browser exit). Past the configured
// timeout (lock_timeout_min: 5/10/15, 0 = Never) the session counts as locked
// until the popup re-confirms desktop presence via Retry.
async function touchActivity() {
  try { await chrome.storage.session.set({ pv_last_active: Date.now() }); } catch (_) {}
}
async function sessionState() {
  try {
    const s = await chrome.storage.session.get({ pv_last_active: 0 });
    const cfg = await chrome.storage.local.get({ lock_timeout_min: 10 });
    const mins = Number(cfg.lock_timeout_min) || 0;
    if (!mins) return { ok: true, locked: false, reason: "never" };
    if (!s.pv_last_active) return { ok: true, locked: false, reason: "fresh" };
    const idleMs = Date.now() - Number(s.pv_last_active);
    if (idleMs > mins * 60 * 1000) return { ok: true, locked: true, reason: "inactive", idleMs };
    return { ok: true, locked: false, reason: "active", idleMs };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}

// ---- Clipboard auto-clear (A4) ----
// The popup writes the secret itself (user gesture), then asks the SW to arm
// a one-shot alarm. The alarm survives popup close and service-worker suspend,
// and clears through an offscreen document (Chrome) or a content-script
// fallback (Firefox). The deadline is mirrored in session storage so a SW
// restart mid-window re-arms instead of leaking the secret until reboot.
const CLIP_ALARM = "pv_clip_clear";
const CLIP_DEFAULT_SEC = 30;

function clipSeconds(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(Math.max(Math.round(n), 5), 3600);
}

async function ensureOffscreen() {
  try {
    if (!chrome.offscreen || typeof chrome.offscreen.createDocument !== "function") return false;
    if (chrome.runtime.getContexts) {
      const ctx = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
      if (Array.isArray(ctx) && ctx.length) return true;
    } else if (typeof chrome.offscreen.hasDocument === "function" && await chrome.offscreen.hasDocument()) {
      return true;
    }
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: ["CLIPBOARD"],
      justification: "Clear copied passwords and 2FA codes after the auto-clear timeout.",
    });
    return true;
  } catch (_) {
    return false;
  }
}

async function clearClipboardNow() {
  let cleared = false;
  // Preferred: offscreen document owns a DOM clipboard for the SW lifetime.
  try {
    if (await ensureOffscreen()) {
      const r = await chrome.runtime.sendMessage({ target: "offscreen", type: "PV_CLIP_CLEAR" });
      cleared = !!(r && r.ok);
    }
  } catch (_) {}
  // Fallback: a content script can blank the clipboard while its page is
  // focused. Best-effort — a denied write leaves the secret to expire with the
  // user's next copy, never silently claims success.
  if (!cleared) {
    try {
      const tabs = await chrome.tabs.query({});
      await Promise.all((tabs || []).map((t) => {
        if (!t || t.id == null) return null;
        return Promise.resolve(chrome.tabs.sendMessage(t.id, { type: "PV_CLIP_CLEAR" }, { frameId: 0 }))
          .then(() => { cleared = true; })
          .catch(() => {});
      }));
    } catch (_) {}
  }
  try {
    await chrome.storage.session.remove(["pv_clip_clear_at", "pv_clip_token"]);
  } catch (_) {}
  return { ok: true, cleared };
}

async function armClipboardClear(rawSeconds) {
  const cfg = await chrome.storage.local.get({ clipboard_clear_sec: CLIP_DEFAULT_SEC });
  const seconds = clipSeconds(
    rawSeconds === undefined || rawSeconds === null ? cfg.clipboard_clear_sec : rawSeconds,
  );
  try {
    if (chrome.alarms && typeof chrome.alarms.clear === "function") {
      chrome.alarms.clear(CLIP_ALARM);
    }
  } catch (_) {}
  if (!seconds) {
    try { await chrome.storage.session.remove(["pv_clip_clear_at", "pv_clip_token"]); } catch (_) {}
    return { ok: true, armed: false, seconds: 0 };
  }
  const at = Date.now() + seconds * 1000;
  try {
    await chrome.storage.session.set({ pv_clip_clear_at: at });
  } catch (_) {}
  try {
    if (chrome.alarms && typeof chrome.alarms.create === "function") {
      chrome.alarms.create(CLIP_ALARM, { when: at });
      return { ok: true, armed: true, seconds, at };
    }
  } catch (_) {}
  // No alarms API: the popup's own timer is the only fallback.
  return { ok: true, armed: false, seconds };
}

// A SW restart does not lose the deadline: re-arm a future one, clear a past
// one immediately (the secret has already outlived its window).
async function rearmClipboardClear() {
  try {
    const s = await chrome.storage.session.get({ pv_clip_clear_at: 0 });
    const at = Number(s.pv_clip_clear_at) || 0;
    if (!at) return;
    if (at <= Date.now()) {
      await clearClipboardNow();
      return;
    }
    if (chrome.alarms && typeof chrome.alarms.create === "function") {
      chrome.alarms.create(CLIP_ALARM, { when: at });
    }
  } catch (_) {}
}
rearmClipboardClear();

// E5: a lock/timeout verdict discovered by ANY caller (popup, another tab,
// native PING) must drop every content-script gate cache immediately — a warm
// 30 s cache in a background tab must not keep authorizing page actions after
// the vault locked. Content treats this as "re-probe on next action".
function broadcastGateLocked() {
  try {
    if (!chrome.tabs || typeof chrome.tabs.sendMessage !== "function") return;
    const send = (tabs) => {
      for (const t of tabs || []) {
        if (!t || t.id == null) continue;
        try {
          Promise.resolve(chrome.tabs.sendMessage(t.id, { type: "PV_GATE_LOCKED" })).catch(() => {});
        } catch (_) {}
      }
    };
    let handled = false;
    const ret = chrome.tabs.query({}, (tabs) => { handled = true; send(tabs); });
    if (ret && typeof ret.then === "function") {
      ret.then((tabs) => { if (!handled) send(tabs); }).catch(() => {});
    }
  } catch (_) {}
}

// Proactive idle lock. Until now the timeout was evaluated lazily, on the
// next message: a popup left open kept looking unlocked until it polled, and
// background tabs kept a warm gate cache. An alarm ticks once a minute and
// pushes PV_GATE_LOCKED the moment the deadline passes, so "locked" is a fact
// the UI is told, not a verdict it has to ask for.
const IDLE_ALARM = "pv_idle_check";
function armIdleAlarm() {
  try {
    if (!chrome.alarms || typeof chrome.alarms.create !== "function") return;
    chrome.alarms.create(IDLE_ALARM, { periodInMinutes: 1 });
  } catch (_) {}
}
async function idleAlarmTick() {
  const st = await sessionState();
  if (!st || st.ok !== true || st.locked !== true) return;
  try {
    await chrome.storage.session.set({ pv_locked_at: Date.now() });
  } catch (_) {}
  broadcastGateLocked();
}
if (chrome.alarms && chrome.alarms.onAlarm && chrome.alarms.onAlarm.addListener) {
  chrome.alarms.onAlarm.addListener((a) => {
    if (!a) return;
    if (a.name === CLIP_ALARM) {
      clearClipboardNow();
      return;
    }
    if (a.name !== IDLE_ALARM) return;
    idleAlarmTick();
  });
}

// Content scripts + popup talk to us here; we only proxy to the vault.
// After mutating calls (save/fill) the toolbar count may change, so the
// originating tab's badge refreshes on the next tick.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Offscreen clipboard document answers on its own channel; the router must
  // not race it with an "unknown message" reply.
  if (msg && msg.target === "offscreen") return false;
  (async () => {
    const retouchBadge = () => {
      try {
        const t = sender && sender.tab;
        if (t && t.id != null && t.url) scheduleBadge(t.id, t.url);
      } catch (_) {}
    };
    // Opaque per-tab scoping for the multi-page carry store (no secrets).
    if (msg.type === "PV_TAB_ID") {
      const t = sender && sender.tab;
      return { ok: !!t && t.id != null, tabId: t && t.id != null ? t.id : null };
    }
    if (msg.type === "PV_QUERY") {
      touchActivity();
      return await hostRequest({ cmd: "query", app: msg.app || msg.url || "" });
    }
    if (msg.type === "PV_LIST") {
      touchActivity();
      return await hostRequest({ cmd: "list" });
    }
    if (msg.type === "PV_FETCH") {
      touchActivity();
      return await hostRequest({ cmd: "fetch", kind: msg.kind || 1, id: msg.id || "" });
    }
    // Passkey discovery (v1, metadata only — no ceremony relay yet).
    if (msg.type === "PV_PASSKEY_LOOKUP") {
      touchActivity();
      return await hostRequest({ cmd: "passkey_lookup", rp: msg.rp || "" });
    }
    // Standalone 2FA Hub codes (fallback when logins carry no secret).
        if (msg.type === "PV_TOTP_LOOKUP") {
          touchActivity();
          return await hostRequest({
            cmd: "totp_lookup",
            app: msg.app || msg.domain || "",
            // Optional exact-id scope. The native side widens MATCHING for the
            // named row only (it still mints the code now and still applies the
            // expiry guard), so a caller that already knows its entry id does
            // not depend on the issuer/domain scorer guessing that row matches.
            ...(msg.id ? { id: String(msg.id) } : {}),
          });
        }
    if (msg.type === "PV_CARDS") {
      return await hostRequest({ cmd: "cards", app: msg.app || msg.url || "", all: msg.all === true });
    }
    if (msg.type === "PV_IDENTITIES") {
      return await hostRequest({ cmd: "identities", app: msg.app || msg.url || "" });
    }
    if (msg.type === "PV_PING") {
      try {
        const r = await hostRequest({ cmd: "ping" });
        if (!r || r.ok === false || r.unlocked === false) broadcastGateLocked();
        return r;
      } catch (e) {
        broadcastGateLocked();
        throw e;
      }
    }
    // Session state for the desktop-synced lock (no PIN anywhere).
    if (msg.type === "PV_ACTIVITY") {
      await touchActivity();
      return { ok: true };
    }
    if (msg.type === "PV_SESSION_STATE") {
      const st = await sessionState();
      if (st && st.ok && st.locked) broadcastGateLocked();
      return st;
    }
    if (msg.type === "PV_UNLOCKED_TOUCH") {
      // Popup Retry confirmed desktop presence — restart the idle clock.
      await touchActivity();
      return { ok: true };
    }
    // A4: clipboard auto-clear. Popup/content already wrote the secret; this
    // only schedules the blank (never receives the secret itself).
    if (msg.type === "PV_CLIP_ARM") {
      return await armClipboardClear(msg.seconds);
    }
    if (msg.type === "PV_CLIP_CLEAR") {
      return await clearClipboardNow();
    }
    // A3: item editor. Popup-only — a content script must never create, edit,
    // or trash a vault row (its sender carries a tab).
    function popupOnly() {
      return !!(sender && sender.tab) ? "item edits are popup-only" : "";
    }
    if (msg.type === "PV_REPROMPT") {
      const denied = popupOnly();
      if (denied) return { ok: false, error: denied };
      touchActivity();
      return await hostRequest({ cmd: "verify_master", password: String(msg.password || "") });
    }
    if (msg.type === "PV_ITEM_CREATE" || msg.type === "PV_ITEM_UPDATE" || msg.type === "PV_ITEM_DELETE") {
      const denied = popupOnly();
      if (denied) return { ok: false, error: denied };
      const cmd = msg.type === "PV_ITEM_CREATE"
        ? "create_login"
        : msg.type === "PV_ITEM_UPDATE" ? "update_login" : "delete_login";
      const payload = {
        cmd,
        id: String(msg.id || ""),
        title: String(msg.title || ""),
        username: String(msg.username || ""),
        password: String(msg.password || ""),
        totp: String(msg.totp || ""),
        folder: String(msg.folder || ""),
        url: String(msg.url || ""),
        urls: Array.isArray(msg.urls) ? msg.urls.filter((u) => typeof u === "string").slice(0, 10) : [],
        reprompt: msg.reprompt === true,
      };
      if (msg.reprompt_token) payload.reprompt_token = String(msg.reprompt_token);
      // Update is partial: only send fields the editor actually has.
      if (msg.type === "PV_ITEM_UPDATE") {
        for (const k of ["title", "username", "password", "totp", "folder", "url", "urls", "reprompt"]) {
          if (!(k in msg)) delete payload[k];
        }
      }
      if (msg.type === "PV_ITEM_DELETE") {
        for (const k of ["title", "username", "password", "totp", "folder", "url", "urls", "reprompt"]) delete payload[k];
      }
      const r = await hostRequest(payload);
      if (r && r.ok) { touchActivity(); retouchBadge(); }
      return r;
    }
    // Quick-unlock PIN hash — sealed in the desktop app (DPAPI), managed in
    // its Settings. The extension NEVER sets/stores a PIN, only verifies.
    if (msg.type === "PV_EXT_PIN") {
      return await hostRequest({ cmd: "ext_pin_hash" });
    }
    // Hybrid favicon harvest (engine layer 2): fetch the page's icon with
    // extension host permissions (page-CORS-proof), cap 64KB, push bytes to
    // the desktop disk cache. One push per base-domain per SW lifetime;
    // the host re-validates everything (decode + traversal + size).
    if (msg.type === "PV_FAVICON_HARVEST") {
      try {
        const rawHost = String(msg.domain || "").toLowerCase();
        const base = rawHost ? pvRegistrable(rawHost) : "";
        if (!base || faviconPushed.has(base)) return { ok: true, cached: true };
        const url = String(msg.iconUrl || "");
        if (!/^https?:\/\//i.test(url)) return { ok: false, error: "bad icon url" };
        // Rollback rule: mark pushed ONLY after a host-confirmed store — a
        // transient fetch/bridge failure retries next page load instead of
        // blackholing the domain for the whole SW lifetime.
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), 10000);
        let buf;
        try {
          const resp = await fetch(url, { signal: ctl.signal, credentials: "omit" });
          if (!resp.ok) return { ok: false, error: "icon fetch " + resp.status };
          buf = await resp.arrayBuffer();
        } finally {
          clearTimeout(timer);
        }
        if (!buf || buf.byteLength === 0 || buf.byteLength > 64 * 1024) {
          return { ok: false, error: "icon size rejected" };
        }
        const bytes = new Uint8Array(buf);
        let bin = "";
        for (let i = 0; i < bytes.length; i += 8192) {
          bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
        }
        const stored = await hostRequest({
          cmd: "cache_favicon",
          domain: base,
          data: btoa(bin),
        });
        if (stored && stored.ok) faviconPushed.add(base);
        return stored;
      } catch (e) {
        return { ok: false, error: String((e && e.message) || e) };
      }
    }
    // Sender check: a page must not save under another site's URL. P6 uses
    // the SENDER FRAME's URL (not the tab URL) so a login/card inside a
    // cross-origin frame is filed under the frame's origin.
    function saveSenderOk(msgUrl) {
      try {
        const tabUrl = sender && sender.tab && sender.tab.url;
        const frameUrl = sender && sender.url;
        const srcUrl = (frameUrl && /^https?:/i.test(frameUrl)) ? frameUrl : tabUrl;
        if (srcUrl && /^https?:/i.test(srcUrl) && msgUrl) {
          const srcBase = pvRegistrable(new URL(srcUrl).hostname);
          const msgBase = pvRegistrable(new URL(String(msgUrl).includes("://") ? msgUrl : "https://" + msgUrl).hostname);
          if (srcBase && msgBase && srcBase !== msgBase) return false;
        }
      } catch (_) {}
      return true;
    }
    if (msg.type === "PV_SAVE_LOGIN") {
      if (!saveSenderOk(msg.url)) {
        return { ok: false, error: "save url does not match sender frame" };
      }
      if (await neverSaveHit(msg.url)) {
        return { ok: false, error: "never save for this site" };
      }
      const r = await hostRequest({ cmd: "save_login", username: msg.username || "", password: msg.password || "", url: msg.url || "", title: msg.title || "", totp: msg.totp || "" });
      if (r && r.ok) { touchActivity(); retouchBadge(); }
      return r;
    }
    // Smart-autofill: save a card typed into a checkout. Cards are global,
    // but the sender check still blocks a hostile frame from filing one under
    // another site's URL (used only for the audit log/notes).
    if (msg.type === "PV_SAVE_CARD") {
      if (!msg.url) return { ok: false, error: "url required" };
      if (!saveSenderOk(msg.url)) {
        return { ok: false, error: "save url does not match sender frame" };
      }
      const r = await hostRequest({
        cmd: "save_card",
        number: msg.number || "",
        cardholder: msg.cardholder || "",
        exp_month: msg.exp_month || "",
        exp_year: msg.exp_year || "",
        cvv: msg.cvv || "",
        url: msg.url || "",
        title: msg.title || "",
      });
      if (r && r.ok) { touchActivity(); retouchBadge(); }
      return r;
    }
    // Smart-autofill: save an identity typed into a profile/address form.
    // Identities are global (like cards), but the sender check still blocks a
    // hostile frame from filing one under another site's URL (audit only).
    if (msg.type === "PV_SAVE_IDENTITY") {
      if (!msg.url) return { ok: false, error: "url required" };
      if (!saveSenderOk(msg.url)) {
        return { ok: false, error: "save url does not match sender frame" };
      }
      const r = await hostRequest({
        cmd: "save_identity",
        full_name: msg.full_name || "",
        email: msg.email || "",
        phone: msg.phone || "",
        address: msg.address || "",
        url: msg.url || "",
        title: msg.title || "",
      });
      if (r && r.ok) { touchActivity(); retouchBadge(); }
      return r;
    }
    // Phase 3 ceremony relay: content-script approval (popup button) opens
    // a Hello-gated UV token FIRST, then the full sign/attest call. Sender
    // check: the ceremony origin must match the sender tab host exactly —
    // a malicious page must never borrow another tab's ceremony.
    function ceremonySenderOk() {
      try {
        const tabUrl = sender && sender.tab && sender.tab.url;
        const tabHost = tabUrl ? new URL(tabUrl).hostname.toLowerCase() : "";
        const orgHost = msg.origin ? new URL(String(msg.origin)).hostname.toLowerCase() : "";
        if (!tabHost || !orgHost || tabHost !== orgHost) {
          return "origin does not match sender tab";
        }
      } catch (_) {
        return "sender check failed";
      }
      return "";
    }
    if (msg.type === "PV_ASSERT_SIGN" || msg.type === "PV_ATTEST_SIGN") {
      const senderErr = ceremonySenderOk();
      if (senderErr) return { ok: false, error: senderErr };
      const rp = String(msg.rpId || "").toLowerCase();
      const uv = await hostRequest({ cmd: "request_uv", rp_id: rp });
      if (!(uv && uv.ok && uv.uv_token)) {
        return { ok: false, error: (uv && uv.error) || "hello approval required" };
      }
      touchActivity();
      if (msg.type === "PV_ASSERT_SIGN") {
        return await hostRequest({ cmd: "assert_full", rp_id: rp,
          origin: String(msg.origin || ""), challenge: String(msg.challengeB64 || ""),
          credential_id: String(msg.credentialId || ""), uv_token: uv.uv_token });
      }
      return await hostRequest({ cmd: "attest", rp_id: rp,
        origin: String(msg.origin || ""), challenge: String(msg.challengeB64 || ""),
        user: msg.user || {}, uv_token: uv.uv_token });
    }
    if (msg.type === "PV_FILLED") {
      touchActivity();
      const r = await hostRequest({ cmd: "filled", id: msg.id || "" });
      retouchBadge();
      return r;
    }
    if (msg.type === "PV_STATS") {
      return await hostRequest({ cmd: "stats" });
    }
    // The user's own "this is the working one" verdict, for logins and
    // standalone 2FA accounts alike. `on` is coerced so a sloppy caller can
    // never send an undefined into the native bool and have it default to
    // "mark it" — un-marking is the rarer, deliberate action.
    if (msg.type === "PV_VERIFY") {
      touchActivity();
      const r = await hostRequest({
        cmd: "verify",
        id: String(msg.id || ""),
        on: msg.on === undefined ? true : !!msg.on,
      });
      retouchBadge();
      return r;
    }
    return { ok: false, error: "unknown message type" };
  })()
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String((e && e.message) || e) }));
  return true; // async response
});

// ---- Smart-autofill: context menus + keyboard shortcut dispatcher ----
const PV_MENU_ROOT = "pv_root";

// P6: the login form may live in a cross-origin iframe. Probe every frame and
// route the action to the frame that owns a visible password/text field.
// Pick priority lives in domain.js (shared with the popup).
const PV_FRAME_PROBE = () => {
  const vis = (el) => {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 12 || r.height < 8) return false;
    const st = getComputedStyle(el);
    return st.visibility !== "hidden" && st.display !== "none" && Number(st.opacity) > 0.05;
  };
  const pass = Array.from(document.querySelectorAll('input[type="password"]')).some(vis);
  const text = Array.from(document.querySelectorAll(
    'input[type="text"],input[type="email"],input[type="tel"],input:not([type])')).some(vis);
  return { pass, text, focused: document.hasFocus(), top: window.top === window };
};

async function pvTargetFrame(tabId) {
  try {
    if (!chrome.scripting || typeof chrome.scripting.executeScript !== "function") return null;
    const probes = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: PV_FRAME_PROBE,
    });
    return PVDomain.pickActionFrame(probes);
  } catch (_) {
    return null; // restricted page / no host permission — top frame fallback
  }
}

async function pvSendToActionFrame(tabId, msg) {
  const frameId = await pvTargetFrame(tabId);
  // frameId 0 is explicit: never fan out to every iframe, where a hidden
  // third-party widget could answer (or fill) first.
  await chrome.tabs.sendMessage(tabId, msg, { frameId: frameId == null ? 0 : frameId });
}

async function refreshContextMenus() {
  try {
    await chrome.contextMenus.removeAll();
    const s = await chrome.storage.local.get({ show_context_menu: true });
    if (s.show_context_menu === false) return;
    chrome.contextMenus.create({ id: PV_MENU_ROOT, title: "PhantomVault", contexts: ["editable"] });
    const items = [
      ["pv_fill_login", "⚡ Auto-fill Login"],
      ["pv_fill_card", "💳 Auto-fill Card"],
      ["pv_fill_identity", "🪪 Auto-fill Identity"],
      ["pv_copy_password", "📋 Copy Password"],
      ["pv_copy_totp", "📋 Copy 2FA Code"],
      ["pv_generate_password", "🎲 Generate Password Here"],
    ];
    for (const [id, title] of items) {
      chrome.contextMenus.create({ id, parentId: PV_MENU_ROOT, title, contexts: ["editable"] });
    }
  } catch (_) { /* menus are best-effort */ }
}

chrome.runtime.onInstalled.addListener(() => { armIdleAlarm(); refreshContextMenus(); });
chrome.runtime.onStartup.addListener(() => { armIdleAlarm(); refreshContextMenus(); });
armIdleAlarm();
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.show_context_menu) refreshContextMenus();
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || tab.id == null) return;
  try {
    // P6: the click already knows its frame (info.frameId); use it instead of
    // guessing. Probe only when the browser did not supply one.
    const frameId = (info && info.frameId != null)
      ? info.frameId
      : await pvTargetFrame(tab.id);
    await chrome.tabs.sendMessage(tab.id, { type: "PV_MENU", menu: info.menuItemId },
      { frameId: frameId == null ? 0 : frameId });
  } catch (_) { /* no content script on this page */ }
});

chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "autofill_active_tab") return;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id == null) return;
    await pvSendToActionFrame(tab.id, { type: "PV_HOTKEY_FILL" });
  } catch (_) { /* unsupported page */ }
});

// ---- Toolbar badge: STRICT domain match count per tab ----
// The host matches usernames too ("@gmail.com" would inflate every page),
// so the badge re-filters to website domains only — same rule as popup.
// E1/E2: implementations live in domain.js (single source).
function pvRegistrable(host) {
  return PVDomain.registrable(host);
}
// "Never save for this site": the user's save prompt choice, enforced here
// too (defense in depth — a content script must not be able to file a login
// the user explicitly refused). Values are registrable domains, so a decision
// on accounts.example.com also covers login.example.com.
async function neverSaveHit(rawUrl) {
  try {
    const host = new URL(String(rawUrl).includes("://") ? String(rawUrl) : "https://" + rawUrl).hostname;
    const base = pvRegistrable(host);
    if (!base) return false;
    const s = await chrome.storage.local.get({ never_save_domains: [] });
    const list = Array.isArray(s.never_save_domains) ? s.never_save_domains : [];
    return list.includes(base);
  } catch (_) {
    return false;
  }
}
const PV_EQUIV = PVDomain.EQUIV_CLUSTERS;
function pvMemberHit(member, domain) {
  return PVDomain.memberHit(member, domain);
}
function pvEntryMatchesPage(e, pageHost) {
  const urls = (e && e.urls) || [];
  if (!urls.length) {
    // No stored URL: title text only (never username/email).
    const t = String((e && e.title) || "").toLowerCase();
    const base = pvRegistrable(pageHost);
    return !!base && t.includes(base);
  }
  return urls.some((raw) => {
    let d = "";
    try {
      d = new URL(raw.includes("://") ? raw : "https://" + raw).hostname.toLowerCase();
    } catch (_) { return false; }
    if (!d || !pageHost) return false;
    if (pvRegistrable(d) === pvRegistrable(pageHost)) return true;
    return PV_EQUIV.some((c) =>
      c.some((m) => pvMemberHit(m, d)) && c.some((m) => pvMemberHit(m, pageHost)));
  });
}

async function refreshBadge(tabId, url) {
  const setTitle = (t) => chrome.action.setTitle({ title: t, tabId }).catch(() => {});
  try {
    if (!url || !/^https?:\/\//i.test(url)) {
      await chrome.action.setBadgeText({ text: "", tabId });
      await setTitle("PhantomVault");
      return;
    }
    const base = pvRegistrable(new URL(url).hostname);
    if (!base) {
      await chrome.action.setBadgeText({ text: "", tabId });
      await setTitle("PhantomVault");
      return;
    }
    const res = await hostRequest({ cmd: "query", app: base });
    const entries = res && res.ok && Array.isArray(res.entries) ? res.entries : [];
    const pageHost = new URL(url).hostname.toLowerCase();
    const n = entries.filter((e) => pvEntryMatchesPage(e, pageHost)).length;
    await chrome.action.setBadgeBackgroundColor({ color: "#38bdf8", tabId });
    await chrome.action.setBadgeText({ text: n > 0 ? (n > 9 ? "9+" : String(n)) : "", tabId });
    await setTitle(n > 0 ? `${n} matching logins for this site` : "No matches — open popup to save");
  } catch (_) {
    try {
      await chrome.action.setBadgeText({ text: "?", tabId });
      await setTitle("Vault locked or unreachable — open popup");
    } catch (_) {}
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab && tab.url) scheduleBadge(tabId, tab.url);
});
chrome.tabs.onActivated.addListener(async (info) => {
  try {
    const tab = await chrome.tabs.get(info.tabId);
    if (tab && tab.url) scheduleBadge(info.tabId, tab.url);
  } catch (_) {}
});

// Debounced badge refresh: rapid tab switches queue ONE native-host spawn
// per tab (500ms trailing), not a process storm.
const badgeTimers = new Map();
function scheduleBadge(tabId, url) {
  if (badgeTimers.has(tabId)) clearTimeout(badgeTimers.get(tabId));
  badgeTimers.set(tabId, setTimeout(() => {
    badgeTimers.delete(tabId);
    refreshBadge(tabId, url);
  }, 500));
}
