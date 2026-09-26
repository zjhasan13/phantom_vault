// PhantomVault native bridge client (MV3 service worker).
// Host name MUST match the registry manifest installed by the desktop app:
//   HKCU\...\NativeMessagingHosts\com.phantomvault.host
// Each query opens its own host process (fresh Hello-cached unlock, vault
// decrypted per request, process exits after) — no long-lived bridge.
const HOST_PORT = "com.phantomvault.host";

function hostRequest(payload, timeoutMs = 10000) {
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

// Content scripts + popup talk to us here; we only proxy to the vault.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === "PV_QUERY") {
      return await hostRequest({ cmd: "query", app: msg.app || msg.url || "" });
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
    if (msg.type === "PV_SAVE_LOGIN") {
      return await hostRequest({ cmd: "save_login", username: msg.username || "", password: msg.password || "", url: msg.url || "", title: msg.title || "", totp: msg.totp || "" });
    }
    if (msg.type === "PV_FILLED") {
      return await hostRequest({ cmd: "filled", id: msg.id || "" });
    }
    if (msg.type === "PV_STATS") {
      return await hostRequest({ cmd: "stats" });
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

// ---- Toolbar badge: matching-login count per tab ----
function pvRegistrable(host) {
  const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  return parts.slice(-2).join(".");
}

async function refreshBadge(tabId, url) {
  try {
    if (!url || !/^https?:\/\//i.test(url)) {
      await chrome.action.setBadgeText({ text: "", tabId });
      return;
    }
    const base = pvRegistrable(new URL(url).hostname);
    if (!base) {
      await chrome.action.setBadgeText({ text: "", tabId });
      return;
    }
    const res = await hostRequest({ cmd: "query", app: base });
    const n = res && res.ok && Array.isArray(res.entries) ? res.entries.length : 0;
    await chrome.action.setBadgeBackgroundColor({ color: "#38bdf8", tabId });
    await chrome.action.setBadgeText({ text: n > 0 ? String(Math.min(n, 99)) : "", tabId });
  } catch (_) {
    try { await chrome.action.setBadgeText({ text: "", tabId }); } catch (_) {}
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab && tab.url) refreshBadge(tabId, tab.url);
});
chrome.tabs.onActivated.addListener(async (info) => {
  try {
    const tab = await chrome.tabs.get(info.tabId);
    if (tab && tab.url) refreshBadge(info.tabId, tab.url);
  } catch (_) {}
});
