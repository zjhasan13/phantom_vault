#!/usr/bin/env node
// Batch-0 JS harness, step 1: background service-worker router tests.
//
// Why this file exists: 4100+ lines of extension JS ship with zero tests,
// so every JS fix lands blind. This harness loads the REAL background.js
// in a `vm` context with a stubbed `chrome` object and drives its message
// router directly — no browser, no network, `node --test` only.
//
// Scope (v1): message dispatch + session/activity behavior. DOM-heavy
// content.js/popup.js need jsdom-style scaffolding — a marked follow-up,
// NOT this file.
//
// Usage: `node --test tests/js/background.test.mjs` from the repo root.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const EXT = path.join(ROOT, "..", "..", "browser_extension");
const BG = fs.readFileSync(path.join(EXT, "background.js"), "utf8");

// --- minimal chrome stub -------------------------------------------------
// Records what the router asked for; tests answer native-host frames by
// hand. Anything unimplemented throws LOUDLY (silent no-ops hide bugs).
function makeChrome() {
  const listeners = { onMessage: [], onInstalled: [], onStartup: [], onActivated: [], onUpdated: [], onClicked: [], onCommand: [], onChanged: [], onAlarm: [] };
  const state = {
    sessionStore: {},
    localStore: { lock_timeout_min: 10 },
    postedNative: [],
    ports: [],
    accessLevel: null,
    tabList: [],
    sentToTabs: [],
    alarms: [],
    alarmsCleared: [],
    runtimeMessages: [],
    offscreenDocs: [],
    offscreenPresent: false,
  };
  const port = () => {
    const handlers = { message: [], disconnect: [] };
    const p = {
      handlers,
      disconnected: false,
      postMessage(payload) {
        state.postedNative.push(payload);
      },
      disconnect() {
        p.disconnected = true;
      },
      onMessage: { addListener: (fn) => handlers.message.push(fn) },
      onDisconnect: { addListener: (fn) => handlers.disconnect.push(fn) },
    };
    state.ports.push(p);
    return p;
  };
  const chrome = {
    __state: state,
    __listeners: listeners,
    runtime: {
      connectNative: () => port(),
      lastError: undefined,
      sendMessage: async (msg) => {
        state.runtimeMessages.push(msg);
        return { ok: true };
      },
      getContexts: async () => (state.offscreenPresent ? [{ contextType: "OFFSCREEN_DOCUMENT" }] : []),
      onMessage: { addListener: (fn) => listeners.onMessage.push(fn) },
      onInstalled: { addListener: (fn) => listeners.onInstalled.push(fn) },
      onStartup: { addListener: (fn) => listeners.onStartup.push(fn) },
    },
    storage: {
      session: {
        get: async (defaults) => ({ ...defaults, ...state.sessionStore }),
        set: async (obj) => {
          Object.assign(state.sessionStore, obj);
        },
        remove: async (k) => {
          for (const key of Array.isArray(k) ? k : [k]) delete state.sessionStore[key];
        },
        setAccessLevel: (opts) => {
          state.accessLevel = opts;
        },
      },
      local: {
        get: async (defaults) => ({ ...defaults, ...state.localStore }),
        set: async (obj) => {
          Object.assign(state.localStore, obj);
        },
      },
      onChanged: { addListener: (fn) => listeners.onChanged.push(fn) },
    },
    tabs: {
      query: async () => state.tabList,
      sendMessage: async (id, msg, opts) => {
        state.sentToTabs.push({ id, msg, opts });
        return { ok: true };
      },
      get: async () => ({ id: 1, url: "https://example.com/" }),
      onActivated: { addListener: (fn) => listeners.onActivated.push(fn) },
      onUpdated: { addListener: (fn) => listeners.onUpdated.push(fn) },
    },
    action: {
      setBadgeText: async () => {},
      setBadgeBackgroundColor: async () => {},
    },
    contextMenus: {
      create: () => {},
      removeAll: async () => {},
      onClicked: { addListener: (fn) => listeners.onClicked.push(fn) },
    },
    commands: { onCommand: { addListener: (fn) => listeners.onCommand.push(fn) } },
    alarms: {
      create: (name, info) => {
        state.alarms.push({ name, info });
      },
      clear: (name) => {
        state.alarmsCleared.push(name);
      },
      onAlarm: { addListener: (fn) => listeners.onAlarm.push(fn) },
    },
    offscreen: {
      createDocument: async (opts) => {
        state.offscreenDocs.push(opts);
        state.offscreenPresent = true;
      },
    },
  };
  return chrome;
}

function loadBackground(chrome) {
  const sandbox = {
    chrome,
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    AbortController,
    TextEncoder,
    TextDecoder,
    URL,
    Buffer,
    btoa: (bin) => Buffer.from(bin, "binary").toString("base64"),
    // Overridable per test: sandbox.__fetch implementation.
    fetch: (...args) => sandbox.__fetch(...args),
  };
  sandbox.__fetch = () => {
    throw new Error("fetch stub not installed for this test");
  };
  // background.js starts with importScripts("domain.js") (MV3 classic SW).
  sandbox.importScripts = (...files) => {
    for (const f of files) {
      const src = fs.readFileSync(path.join(EXT, f), "utf8");
      vm.runInContext(src, sandbox, { filename: f });
    }
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(BG, sandbox, { filename: "background.js" });
  assert.equal(chrome.__listeners.onMessage.length, 1, "router must register exactly one onMessage listener");
  return { onMessage: chrome.__listeners.onMessage[0], sandbox };
}

// Sends a message through the router like the popup/content would.
function sendMessage(listener, chrome, msg, sender = {}) {
  return new Promise((resolve) => {
    const maybeAsync = listener(msg, sender, (resp) => resolve(resp));
    // Async listener without sendResponse call yet: fall through to resolve.
    if (maybeAsync === false) resolve(undefined);
  });
}

export { makeChrome, loadBackground, sendMessage };
