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

function makeChrome(store) {
  const listeners = { onMessage: [], changed: [] };
  const sendMessage = async (msg) => {
    if (!msg || !msg.type) return { ok: false, error: "no type" };
    if (msg.type === "PV_QUERY" || msg.type === "PV_LIST") {
      return { ok: true, entries: store.entries };
    }
    if (msg.type === "PV_EXT_PIN") return { ok: true, hash: "a".repeat(64) };
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
      local: { get: async (d) => ({ ...d }), set: async () => {}, remove: async () => {} },
      session: {
        get: async (d) => ({ ...d }),
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

export function loadContent(html, url = "https://example.com/login", entries = [], cards = []) {
  // content.js schedules 30 s toast timers; when a test closes its window those
  // fire against a torn-down document. Swallow only jsdom's teardown reports —
  // real assertion failures still surface normally.
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", () => {});
  const dom = new JSDOM(html, {
    url, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole,
  });
  const { window } = dom;
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
  const store = { entries, cards, session: {}, pings: 0, sessionLocked: false, saves: [], cardSaves: [] };
  window.chrome = makeChrome(store);
  // Manifest order: domain.js before content.js (same isolated world).
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
