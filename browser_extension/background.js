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
    if (msg.type === "PV_PING") {
      return await hostRequest({ cmd: "ping" });
    }
    return { ok: false, error: "unknown message type" };
  })()
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String((e && e.message) || e) }));
  return true; // async response
}
