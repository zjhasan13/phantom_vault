// PhantomVault native bridge client (MV3 service worker).
// Host name MUST match the registry manifest installed by the desktop app:
//   HKCU\...\NativeMessagingHosts\com.phantomvault.host
// Persistent port: one host process serves the whole burst (one Argon2id,
// then ~5ms frames) until the 60s host TTL, browser disconnect, or SW
// suspend. Falls back to one-shot connectNative per request if the shared
// port dies. NOTE: the host serves its spawn-time vault snapshot — desktop
// mutations land on the bridge after the TTL window (documented, not a bug).
const HOST_PORT = "com.phantomvault.host";

// Base-domains already pushed to the desktop favicon cache this SW
// lifetime (harvest is idempotent server-side; this just saves fetches).
const faviconPushed = new Set();

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

// Content scripts + popup talk to us here; we only proxy to the vault.
// After mutating calls (save/fill) the toolbar count may change, so the
// originating tab's badge refreshes on the next tick.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const retouchBadge = () => {
      try {
        const t = sender && sender.tab;
        if (t && t.id != null && t.url) scheduleBadge(t.id, t.url);
      } catch (_) {}
    };
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
      return await hostRequest({ cmd: "cards", app: msg.app || msg.url || "" });
    }
    if (msg.type === "PV_IDENTITIES") {
      return await hostRequest({ cmd: "identities", app: msg.app || msg.url || "" });
    }
    if (msg.type === "PV_PING") {
      return await hostRequest({ cmd: "ping" });
    }
    // Session state for the desktop-synced lock (no PIN anywhere).
    if (msg.type === "PV_ACTIVITY") {
      await touchActivity();
      return { ok: true };
    }
    if (msg.type === "PV_SESSION_STATE") {
      return await sessionState();
    }
    if (msg.type === "PV_UNLOCKED_TOUCH") {
      // Popup Retry confirmed desktop presence — restart the idle clock.
      await touchActivity();
      return { ok: true };
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
    if (msg.type === "PV_SAVE_LOGIN") {
      // Sender check (MISSING-HIGH): a malicious page must not save under
      // another site's URL (github.com) to poison that credential via the
      // host's domain match. Refuse when sender.tab.url disagrees.
      try {
        const tabUrl = sender && sender.tab && sender.tab.url;
        if (tabUrl && /^https?:/i.test(tabUrl) && msg.url) {
          const tabBase = pvRegistrable(new URL(tabUrl).hostname);
          const msgBase = pvRegistrable(new URL(String(msg.url).includes("://") ? msg.url : "https://" + msg.url).hostname);
          if (tabBase && msgBase && tabBase !== msgBase) {
            return { ok: false, error: "save url does not match sender tab" };
          }
        }
      } catch (_) {}
      const r = await hostRequest({ cmd: "save_login", username: msg.username || "", password: msg.password || "", url: msg.url || "", title: msg.title || "", totp: msg.totp || "" });
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

chrome.runtime.onInstalled.addListener(refreshContextMenus);
chrome.runtime.onStartup.addListener(refreshContextMenus);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.show_context_menu) refreshContextMenus();
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || tab.id == null) return;
  try {
    await chrome.tabs.sendMessage(tab.id, { type: "PV_MENU", menu: info.menuItemId });
  } catch (_) { /* no content script on this page */ }
});

chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "autofill_active_tab") return;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id == null) return;
    await chrome.tabs.sendMessage(tab.id, { type: "PV_HOTKEY_FILL" });
  } catch (_) { /* unsupported page */ }
});

// ---- Toolbar badge: STRICT domain match count per tab ----
// The host matches usernames too ("@gmail.com" would inflate every page),
// so the badge re-filters to website domains only — same rule as popup.
function pvRegistrable(host) {
  const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  return parts.slice(-2).join(".");
}
const PV_EQUIV = [
  ["proton.me", "protonmail.com", "protonvpn.com", "protondrive.com"],
  ["google.com", "youtube.com", "gmail.com", "googlemail.com", "gstatic.com", "google.co.*"],
  ["facebook.com", "messenger.com", "instagram.com", "threads.net"],
  ["microsoft.com", "live.com", "office.com", "login.microsoftonline.com", "xbox.com", "outlook.com", "hotmail.com", "onedrive.com"],
  ["apple.com", "icloud.com"],
  ["amazon.com", "primevideo.com", "audible.com", "amazon.co.*"],
  ["sony.com", "playstation.com", "playstationnetwork.com"],
  ["yahoo.com", "aol.com"],
];
function pvMemberHit(member, domain) {
  if (member.endsWith(".*")) {
    const p = member.slice(0, -2);
    return domain === p || domain.startsWith(p + ".");
  }
  return domain === member || domain.endsWith("." + member) || member.endsWith("." + domain);
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
