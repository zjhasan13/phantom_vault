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

  // WebAuthn relay (Phase 3): HOLD get/create briefly so an EXPLICIT user
  // approval (extension popup button) can fulfill the ceremony from the
  // vault. No approval in time → original behavior (page promise untouched).
  // Fulfilled credentials are plain objects (no PublicKeyCredential
  // constructor exists) — RPs read the response fields, which are exact.
  const PV_PENDING = new Map();
  let pvReqSeq = 0;
  const PV_HOLD_MS = 90000;
  function pvHold(kind, pk, origin, origFn, options) {
    let reqId = "";
    try {
      reqId = "pv" + (++pvReqSeq) + Date.now().toString(36);
      window.postMessage(
        { source: "__pv_hook", type: kind === "create" ? "PV_WEBAUTHN_CREATE" : "PV_WEBAUTHN_GET",
          reqId, rpId: String((pk && (pk.rpId || (pk.rp && pk.rp.id))) || ""),
          publicKey: pk, origin: String(origin || "") }, "*");
    } catch (_) {
      return origFn(options);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        PV_PENDING.delete(reqId);
        try { resolve(origFn(options)); } catch (e) { reject(e); }
      }, PV_HOLD_MS);
      PV_PENDING.set(reqId, { resolve, reject, timer, fallback: () => origFn(options) });
    });
  }
  try {
    if (window.PublicKeyCredential && navigator.credentials) {
      if (navigator.credentials.get) {
        const origGet = navigator.credentials.get.bind(navigator.credentials);
        navigator.credentials.get = function (options) {
          try {
            const pk = options && options.publicKey;
            if (!pk) return origGet(options);
            return pvHold("get", pk, location.origin, origGet, options);
          } catch (_) { return origGet(options); }
        };
      }
      if (navigator.credentials.create) {
        const origCreate = navigator.credentials.create.bind(navigator.credentials);
        navigator.credentials.create = function (options) {
          try {
            const pk = options && options.publicKey;
            if (!pk) return origCreate(options);
            return pvHold("create", pk, location.origin, origCreate, options);
          } catch (_) { return origCreate(options); }
        };
      }
    }
  } catch (_) {}
  window.addEventListener("message", (e) => {
    try {
      if (e.source !== window) return;
      const d = e.data || {};
      if (d.source !== "__pv_relay" || d.type !== "PV_WEBAUTHN_FULFILL") return;
      const p = PV_PENDING.get(d.reqId);
      if (!p) return;
      PV_PENDING.delete(d.reqId);
      clearTimeout(p.timer);
      p.resolve(d.credential);
    } catch (_) {}
  });
})();
