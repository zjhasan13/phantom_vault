// A4: offscreen document with a DOM clipboard. The service worker holds no
// clipboard API, so the auto-clear alarm asks this document to blank the
// clipboard after the configured timeout. No secret ever reaches this file:
// only a SHA-256 hash of it. The current clipboard is read and hashed first —
// a mismatch (the user copied something else) is a no-op.
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.target !== "offscreen" || msg.type !== "PV_CLIP_CLEAR") return false;
  (async () => {
    try {
      const want = String(msg.hash || "").toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(want)) {
        sendResponse({ ok: false, skipped: true, error: "no hash" });
        return;
      }
      const current = await navigator.clipboard.readText();
      if (!current) {
        sendResponse({ ok: true, alreadyEmpty: true });
        return;
      }
      if (await sha256Hex(current) !== want) {
        sendResponse({ ok: false, skipped: true, error: "clipboard changed" });
        return;
      }
      await navigator.clipboard.writeText("");
      sendResponse({ ok: true });
    } catch (e) {
      sendResponse({ ok: false, error: String((e && e.message) || e) });
    }
  })();
  return true;
});
