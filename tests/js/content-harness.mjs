// jsdom harness for content.js (Tier 0 capture engine).
// Loads the REAL content.js inside a jsdom window with a stubbed `chrome`,
// so the credential-capture paths (form submit, signup, multi-page carry)
// are exercised end-to-end — no browser, `node --test` only.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM, VirtualConsole } from "jsdom";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DOMAIN = fs.readFileSync(
  path.join(ROOT, "..", "..", "browser_extension", "domain.js"), "utf8");
const CONTENT = fs.readFileSync(
  path.join(ROOT, "..", "..", "browser_extension", "content.js"), "utf8");

// host -> closed shadow root, populated by the attachShadow spy in loadContent.
const shadowRoots = new WeakMap();
// element -> { eventType -> [listener] }, filled by the addEventListener spy.
const listenerMap = new WeakMap();

/// Test-only handle on a closed shadow root (falls back to the host itself when
/// an element has no shadow tree, e.g. the card/identity toasts).
export function shadowOf(host) {
  return host ? (shadowRoots.get(host) || host) : null;
}

function makeChrome(store) {
  const listeners = { onMessage: [], changed: [] };
  const sendMessage = async (msg) => {
    if (!msg || !msg.type) return { ok: false, error: "no type" };
    if (msg.type === "PV_QUERY" || msg.type === "PV_LIST") {
      return { ok: true, entries: store.entries };
    }
    if (msg.type === "PV_EXT_PIN_STATUS") return { ok: true, set: true };
  if (msg.type === "PV_EXT_PIN_VERIFY") return { ok: true, valid: true };
    if (msg.type === "PV_SESSION_STATE") {
      return { ok: true, locked: !!store.sessionLocked, reason: store.sessionLocked ? "inactive" : "active" };
    }
    if (msg.type === "PV_PING") {
      store.pings += 1;
      return { ok: true, unlocked: true };
    }
    if (msg.type === "PV_CARDS") {
      return { ok: true, entries: store.cards };
    }
    if (msg.type === "PV_IDENTITIES") {
      return { ok: true, entries: store.identities || [] };
    }
    // 2FA picker path: the content engine asks the host for per-site TOTP
    // candidates and opens its picker only when more than one matches.
    if (msg.type === "PV_TOTP_LOOKUP") {
      const all = store.totp || [];
      const id = msg.id ? String(msg.id) : "";
      return { ok: true, candidates: id ? all.filter((c) => String(c.id) === id) : all };
    }
    if (msg.type === "PV_BREACH") return { ok: true, breach: store.breach ?? null, reuse: store.reuse ?? 0 };
    if (msg.type === "PV_SAVE_LOGIN") {
      store.saves.push(msg);
      return { ok: true, updated: false };
    }
    if (msg.type === "PV_SAVE_CARD") {
      store.cardSaves.push(msg);
      return { ok: true, updated: false };
    }
    return { ok: true };
  };
  return {
    __store: store,
    __listeners: listeners,
    runtime: {
      sendMessage,
      getURL: (p) => "chrome-extension://test/" + p,
      onMessage: { addListener: (fn) => listeners.onMessage.push(fn) },
      lastError: undefined,
    },
    storage: {
      local: {
        // Seed `store.local` to model settings persisted by an earlier run.
        get: async (d) => ({ ...d, ...(store.local || {}) }),
        set: async (o) => { store.local = { ...(store.local || {}), ...o }; },
        remove: async (k) => { if (store.local) delete store.local[k]; },
      },
      session: {
        get: async (d) => {
          const out = { ...d };
          for (const k of Object.keys(d)) {
            if (k in store.session) out[k] = store.session[k];
          }
          return out;
        },
        set: async (o) => { Object.assign(store.session, o); },
        remove: async (k) => { delete store.session[k]; },
        setAccessLevel: () => {},
      },
      onChanged: { addListener: (fn) => listeners.changed.push(fn) },
    },
    tabs: { query: async () => [], sendMessage: async () => ({ ok: true }) },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
  };
}

export function loadContent(html, url = "https://example.com/login", entries = [], cards = [], identities = [], totp = [], local = {}) {
  // content.js schedules 30 s toast timers; when a test closes its window those
  // fire against a torn-down document. Swallow only jsdom's teardown reports —
  // real assertion failures still surface normally.
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", () => {});
  const dom = new JSDOM(html, {
    url, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole,
  });
  const { window } = dom;
  // The save prompt keeps its inputs in a closed shadow root, which the page
  // (and `host.shadowRoot`) cannot reach by design. The harness still needs a
  // handle, so capture every root the extension creates. The spy stays in the
  // test harness — content.js never publishes the root itself.
  const attachShadow = window.Element.prototype.attachShadow;
  if (typeof attachShadow === "function") {
    window.Element.prototype.attachShadow = function (init) {
      const root = attachShadow.call(this, init);
      shadowRoots.set(this, root);
      return root;
    };
  }
  // jsdom has no layout: every element reports 0×0, which fails isVisible().
  // Force non-zero dimensions on the prototypes so field detection behaves as
  // it would on a real page.
  for (const C of [window.HTMLElement, window.HTMLInputElement]) {
    for (const dim of ["offsetWidth", "offsetHeight", "clientWidth", "clientHeight"]) {
      try {
        Object.defineProperty(C.prototype, dim, { get() { return 10; }, configurable: true });
      } catch (_) {}
    }
  }
  const store = { entries, cards, identities, totp, breach: null, reuse: 0, session: {}, pings: 0, sessionLocked: false, saves: [], cardSaves: [], local: { ...local } };
  window.chrome = makeChrome(store);
  // jsdom has no async clipboard; the generate/copy paths call writeText and
  // would otherwise throw after filling the field.
  try {
    Object.defineProperty(window.navigator, "clipboard", {
      value: { writeText: async () => {} }, configurable: true,
    });
  } catch (_) {}
  // jsdom has no innerText. content.js reads it for OTP hint/context text, so
  // map it to textContent; without this the hint paths see empty strings and
  // the classification under test would be untestable here.
  try {
    Object.defineProperty(window.HTMLElement.prototype, "innerText", {
      get() { return this.textContent; },
      set(v) { this.textContent = v; },
      configurable: true,
    });
  } catch (_) {}
  // Manifest order: domain.js before content.js (same isolated world).
  // Record listeners so fireTrusted() can play the browser for user-path
  // tests (a script-dispatched event can never carry isTrusted).
  const origAdd = window.EventTarget.prototype.addEventListener;
  const origRemove = window.EventTarget.prototype.removeEventListener;
  window.EventTarget.prototype.addEventListener = function (type, fn, opts) {
    if (fn) {
      let m = listenerMap.get(this);
      if (!m) { m = {}; listenerMap.set(this, m); }
      (m[type] = m[type] || []).push(fn);
    }
    return origAdd.call(this, type, fn, opts);
  };
  window.EventTarget.prototype.removeEventListener = function (type, fn, opts) {
    const m = listenerMap.get(this);
    if (m && m[type]) m[type] = m[type].filter((f) => f !== fn);
    return origRemove.call(this, type, fn, opts);
  };
  window.eval(DOMAIN);
  window.eval(CONTENT);
  return { dom, window, store };
}

export function submit(window, form) {
  form.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
}

export function runtimeMessage(window, msg) {
  const listeners = window.chrome.__listeners.onMessage;
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      resolve(v);
    };
    for (const fn of listeners) fn(msg, {}, finish);
    setTimeout(() => finish(undefined), 1000);
  });
}

export async function flush(ms = 25) {
  await new Promise((r) => setTimeout(r, ms));
}


// jsdom marks every script-dispatched event `isTrusted: false` and the
// property is non-configurable, so an event cannot be faked into a gesture.
// These tests still need to exercise the USER path; `fireTrusted` calls the
// listener the browser would call, with an event shaped like a real one.

/// Call the handler registered for `type` on `el` as if a real user fired it.
/// Only for positive-path tests; the security tests dispatch a real synthetic
/// event (isTrusted false) and assert nothing happens.
export function fireTrusted(el, type = "click", extra = {}) {
  const byType = listenerMap.get(el) || {};
  const fns = (byType[type] || []).slice();
  const results = [];
  for (const fn of fns) {
    const ev = {
      type, isTrusted: true, target: el, currentTarget: el,
      defaultPrevented: false, button: 0, detail: 1, key: "",
      preventDefault() { this.defaultPrevented = true; },
      stopPropagation() {}, stopImmediatePropagation() {},
      ...extra,
    };
    results.push(fn.call(el, ev));
  }
  return Promise.all(results);
}
