/* PhantomVault page-world hook (runs in MAIN world, not the isolated
 * content-script world — only here can it observe the page's own React /
 * fetch / XHR login POSTs). Sends DATA-FREE tripwire pings; the content
 * script re-reads credentials from the DOM itself, so a hostile page can
 * at worst trigger a save prompt, never inject values. */
(() => {
  "use strict";
  if (window.__pvHook) return;
  window.__pvHook = true;

  function ping() {
    try {
      window.postMessage({ source: "__pv_hook", type: "PV_SPA_LOGIN" }, "*");
    } catch (_) {}
  }

  function bodyLooksLikeLogin(body) {
    if (!body) return false;
    let s = "";
    try {
      if (typeof body === "string") {
        s = body;
      } else if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        s = body.toString();
      } else if (typeof FormData !== "undefined" && body instanceof FormData) {
        const parts = [];
        body.forEach((_, k) => parts.push(k));
        s = parts.join("&");
      } else {
        return false; // Blob / ArrayBuffer / FormData-values: never sniff bytes
      }
    } catch (_) {
      return false;
    }
    const t = String(s).toLowerCase();
    return t.includes("password") || t.includes("passwd") || t.includes("pwd");
  }

  // fetch() hook (React Query / axios-fetch / Next.js actions).
  try {
    const origFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      try {
        const method = ((init && init.method) || "GET").toUpperCase();
        if (method !== "GET" && method !== "HEAD" && bodyLooksLikeLogin(init && init.body)) {
          ping();
        }
      } catch (_) {}
      return origFetch(input, init);
    };
  } catch (_) {}

  // XHR hook (legacy jQuery / axios-xhr stacks).
  try {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      try {
        this.__pvMethod = method;
      } catch (_) {}
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function (body) {
      try {
        const m = String(this.__pvMethod || "POST").toUpperCase();
        if (m !== "GET" && m !== "HEAD" && bodyLooksLikeLogin(body)) {
          ping();
        }
      } catch (_) {}
      return origSend.apply(this, arguments);
    };
  } catch (_) {}
})();
