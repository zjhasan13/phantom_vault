// A4: offscreen document with a DOM clipboard. The service worker holds no
// clipboard API, so the auto-clear alarm asks this document to blank the
// clipboard after the configured timeout. No secret ever reaches this file:
// it only writes an empty string.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.target !== "offscreen" || msg.type !== "PV_CLIP_CLEAR") return false;
  (async () => {
    try {
      await navigator.clipboard.writeText("");
      sendResponse({ ok: true });
    } catch (e) {
      sendResponse({ ok: false, error: String((e && e.message) || e) });
    }
  })();
  return true;
});
