#!/usr/bin/env node
// background.js router tests (harness v1). Run: `node --test tests/js/`
import test from "node:test";
import assert from "node:assert/strict";
import { makeChrome, loadBackground, sendMessage } from "./harness.mjs";

function fresh() {
  const chrome = makeChrome();
  const { onMessage, sandbox } = loadBackground(chrome);
  return { chrome, onMessage, sandbox };
}

test("unknown message type fails closed with an error (never empty)", async () => {
  const { chrome, onMessage } = fresh();
  const r = await sendMessage(onMessage, chrome, { type: "PV_NOPE" });
  assert.equal(r.ok, false);
  assert.match(r.error || "", /unknown/i);
});

test("PV_ACTIVITY touches session and answers ok", async () => {
  const { chrome, onMessage } = fresh();
  const before = Date.now();
  const r = await sendMessage(onMessage, chrome, { type: "PV_ACTIVITY" });
  assert.equal(r.ok, true);
  assert.ok(chrome.__state.sessionStore.pv_last_active >= before);
});

test("PV_SESSION_STATE reports active with idleMs, locked past timeout", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.sessionStore.pv_last_active = Date.now();
  chrome.__state.localStore.lock_timeout_min = 10;
  let r = await sendMessage(onMessage, chrome, { type: "PV_SESSION_STATE" });
  assert.equal(r.ok, true);
  assert.equal(r.locked, false);
  assert.ok(typeof r.idleMs === "number");
  // 11 minutes idle > 10-minute timeout ⇒ locked.
  chrome.__state.sessionStore.pv_last_active = Date.now() - 11 * 60 * 1000;
  r = await sendMessage(onMessage, chrome, { type: "PV_SESSION_STATE" });
  assert.equal(r.locked, true);
  assert.equal(r.reason, "inactive");
});

test("timeout 0 (Never) never locks", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.sessionStore.pv_last_active = Date.now() - 60 * 60 * 1000;
  chrome.__state.localStore.lock_timeout_min = 0;
  const r = await sendMessage(onMessage, chrome, { type: "PV_SESSION_STATE" });
  assert.equal(r.locked, false);
});

test("PV_EXT_PIN proxies ext_pin_hash to the native host", async () => {
  const { chrome, onMessage } = fresh();
  const pending = sendMessage(onMessage, chrome, { type: "PV_EXT_PIN" });
  // One host spawn per query; answer it like the desktop would.
  assert.equal(chrome.__state.postedNative.length, 1);
  assert.equal(chrome.__state.postedNative[0].cmd, "ext_pin_hash");
  const port = chrome.__state.ports[0];
  port.handlers.message.forEach((fn) => fn({ ok: true, hash: "a".repeat(64) }));
  const r = await pending;
  assert.equal(r.ok, true);
  assert.equal(r.hash, "a".repeat(64));
});

// The router suspends at the first await (fetch), so postedNative only
// fills after microtasks drain — flush before asserting on spawns.
async function flushTicks(n = 5) {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
}

// SSRF/size shape: the harvester fetches page-declared URLs, so the fetch
// + size gates are the trust boundary (the host re-validates after).
function tinyIcon() {
  // Minimal valid PNG bytes (signature + IHDR + IEND); content is never
  // decoded here — only measured.
  return new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3, 4]);
}

test("PV_FAVICON_HARVEST rejects non-http URLs without fetching", async () => {
  const { chrome, onMessage, sandbox } = fresh();
  let fetched = 0;
  sandbox.__fetch = async () => {
    fetched++;
    throw new Error("must not fetch");
  };
  const r = await sendMessage(onMessage, chrome, {
    type: "PV_FAVICON_HARVEST",
    domain: "example.com",
    iconUrl: "ftp://example.com/icon.png",
  });
  assert.equal(r.ok, false);
  assert.equal(fetched, 0);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("PV_FAVICON_HARVEST rejects oversize payloads before the host", async () => {
  const { chrome, onMessage, sandbox } = fresh();
  sandbox.__fetch = async () => ({
    ok: true,
    arrayBuffer: async () => new ArrayBuffer(64 * 1024 + 1),
  });
  const r = await sendMessage(onMessage, chrome, {
    type: "PV_FAVICON_HARVEST",
    domain: "example.com",
    iconUrl: "https://example.com/icon.png",
  });
  assert.equal(r.ok, false);
  assert.match(r.error || "", /size/i);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("PV_FAVICON_HARVEST stores once, then serves cached without refetch", async () => {
  const { chrome, onMessage, sandbox } = fresh();
  let fetched = 0;
  sandbox.__fetch = async () => {
    fetched++;
    return { ok: true, arrayBuffer: async () => tinyIcon().buffer };
  };
  const msg = {
    type: "PV_FAVICON_HARVEST",
    domain: "example.com",
    iconUrl: "https://example.com/icon.png",
  };
  const pending = sendMessage(onMessage, chrome, msg);
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  assert.equal(chrome.__state.postedNative[0].cmd, "cache_favicon");
  assert.equal(chrome.__state.postedNative[0].domain, "example.com");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, domain: "example.com" }));
  const r = await pending;
  assert.equal(r.ok, true);
  // Second harvest of the same base domain: no refetch, no host spawn.
  const r2 = await sendMessage(onMessage, chrome, msg);
  assert.equal(r2.ok, true);
  assert.equal(r2.cached, true);
  assert.equal(fetched, 1);
  assert.equal(chrome.__state.postedNative.length, 1);
});

test("persistent port: sequential queries share one host process", async () => {
  const { chrome, onMessage } = fresh();
  const p1 = sendMessage(onMessage, chrome, { type: "PV_EXT_PIN" });
  await flushTicks();
  assert.equal(chrome.__state.ports.length, 1);
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, hash: "h" }));
  const r1 = await p1;
  assert.equal(r1.ok, true);
  // Second query must reuse the same port — no new host spawn.
  const p2 = sendMessage(onMessage, chrome, { type: "PV_PING" });
  await flushTicks();
  assert.equal(chrome.__state.ports.length, 1);
  assert.equal(chrome.__state.ports[0].disconnected, false);
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r2 = await p2;
  assert.equal(r2.ok, true);
});

test("port disconnect fails pending and reconnects on next query", async () => {
  const { chrome, onMessage } = fresh();
  const p1 = sendMessage(onMessage, chrome, { type: "PV_EXT_PIN" });
  await flushTicks();
  assert.equal(chrome.__state.ports.length, 1);
  // Host dies mid-request: pending fails closed, port dropped. (The
  // router converts the rejection into { ok:false } via sendResponse.)
  chrome.__state.ports[0].handlers.disconnect.forEach((fn) => fn());
  const r1 = await p1;
  assert.equal(r1.ok, false);
  assert.match(r1.error || "", /disconnected|host/i);
  // Next query spawns a FRESH port (lazy reconnect).
  const p2 = sendMessage(onMessage, chrome, { type: "PV_PING" });
  await flushTicks();
  assert.equal(chrome.__state.ports.length, 2);
  chrome.__state.ports[1].handlers.message.forEach((fn) => fn({ ok: true }));
  const r2 = await p2;
  assert.equal(r2.ok, true);
});

test("PV_ASSERT relay removed: fails closed, never reaches the host", async () => {
  // Merge repair: the other line removed the ceremony relay (no content.js /
  // popup.js sender remains). The router must fail closed with zero host
  // spawn — NOT silently drop or partially relay.
  const { chrome, onMessage } = fresh();
  const r = await sendMessage(onMessage, chrome, {
    type: "PV_ASSERT",
    rpId: "github.com",
    challenge: "abc",
    clientDataHash: "a".repeat(44),
    credentialId: "cred1",
  });
  assert.equal(r.ok, false);
  assert.match(r.error || "", /unknown/i);
  assert.equal(chrome.__state.ports.length, 0);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("PV_FAVICON_HARVEST failure leaves no pushed marker (retries later)", async () => {
  const { chrome, onMessage, sandbox } = fresh();
  sandbox.__fetch = async () => {
    throw new Error("net down");
  };
  const msg = {
    type: "PV_FAVICON_HARVEST",
    domain: "retry-test.com",
    iconUrl: "https://retry-test.com/icon.png",
  };
  const r1 = await sendMessage(onMessage, chrome, msg);
  assert.equal(r1.ok, false);
  // Marker absent ⇒ a later page load retries the fetch instead of
  // blackholing the domain for the SW lifetime.
  let fetched = 0;
  sandbox.__fetch = async () => {
    fetched++;
    return { ok: true, arrayBuffer: async () => tinyIcon().buffer };
  };
  const pending = sendMessage(onMessage, chrome, msg);
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r2 = await pending;
  assert.equal(r2.ok, true);
  assert.equal(fetched, 1);
});

test("PV_ASSERT_SIGN: sender mismatch fails closed, zero host spawn", async () => {
  const { chrome, onMessage } = fresh();
  const r = await sendMessage(onMessage, chrome,
    { type: "PV_ASSERT_SIGN", rpId: "github.com", origin: "https://evil.com/",
      challengeB64: "abc", credentialId: "" },
    { tab: { url: "https://github.com/login" } });
  assert.equal(r.ok, false);
  assert.match(r.error || "", /sender tab/i);
  assert.equal(chrome.__state.ports.length, 0);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("PV_ASSERT_SIGN: hello uv first, then assert_full with the token", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { tab: { url: "https://github.com/login" } };
  const p = sendMessage(onMessage, chrome,
    { type: "PV_ASSERT_SIGN", rpId: "github.com", origin: "https://github.com/login",
      challengeB64: "abc", credentialId: "" }, sender);
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  assert.equal(chrome.__state.postedNative[0].cmd, "request_uv");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, uv_token: "tok123" }));
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 2);
  assert.equal(chrome.__state.postedNative[1].cmd, "assert_full");
  assert.equal(chrome.__state.postedNative[1].uv_token, "tok123");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, signature: "sig" }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("PV_ASSERT_SIGN: hello denial stops before assert_full", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { tab: { url: "https://github.com/login" } };
  const p = sendMessage(onMessage, chrome,
    { type: "PV_ASSERT_SIGN", rpId: "github.com", origin: "https://github.com/login",
      challengeB64: "abc", credentialId: "" }, sender);
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: false, error: "canceled" }));
  const r = await p;
  assert.equal(r.ok, false);
  assert.equal(chrome.__state.postedNative.length, 1);
});

test("PV_ATTEST_SIGN: proxies attest with uv token", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { tab: { url: "https://github.com/" } };
  const p = sendMessage(onMessage, chrome,
    { type: "PV_ATTEST_SIGN", rpId: "github.com", origin: "https://github.com/",
      challengeB64: "abc", user: { name: "octo" } }, sender);
  await flushTicks();
  assert.equal(chrome.__state.postedNative[0].cmd, "request_uv");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, uv_token: "tok9" }));
  await flushTicks();
  assert.equal(chrome.__state.postedNative[1].cmd, "attest");
  assert.equal(chrome.__state.postedNative[1].uv_token, "tok9");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r = await p;
  assert.equal(r.ok, true);
});

// ---- Tier 0 extension capture: background-side contract ----

test("K2: SW grants content-script access to chrome.storage.session on load", async () => {
  // Without this, content.js cannot read the multi-page carry (`pvCaptureCarry`)
  // or `pvPending` — chrome.storage.session defaults to trusted contexts only.
  const { chrome } = fresh();
  assert.equal(
    chrome.__state.accessLevel && chrome.__state.accessLevel.accessLevel,
    "TRUSTED_AND_UNTRUSTED_CONTEXTS");
});

test("PV_SAVE_LOGIN: proxies save_login for a matching sender tab", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { tab: { url: "https://example.com/login" } };
  const p = sendMessage(onMessage, chrome,
    { type: "PV_SAVE_LOGIN", username: "u", password: "p",
      url: "https://example.com/login", title: "Example" }, sender);
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  assert.equal(chrome.__state.postedNative[0].cmd, "save_login");
  assert.equal(chrome.__state.postedNative[0].username, "u");
  assert.equal(chrome.__state.postedNative[0].password, "p");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("PV_SAVE_LOGIN: cross-site sender URL is refused, zero host spawn", async () => {
  // A page must never save a credential under another site's URL (poisons that
  // domain's match). Guard lives in the router, so it holds for every capture
  // trigger (form submit, SPA ping, multi-page carry).
  const { chrome, onMessage } = fresh();
  const sender = { tab: { url: "https://example.com/login" } };
  const r = await sendMessage(onMessage, chrome,
    { type: "PV_SAVE_LOGIN", username: "u", password: "p",
      url: "https://github.com/login", title: "GitHub" }, sender);
  assert.equal(r.ok, false);
  assert.match(r.error || "", /does not match/i);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("E5: a locked session broadcasts PV_GATE_LOCKED to every tab", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.tabList = [{ id: 7 }, { id: 8 }];
  chrome.__state.sessionStore.pv_last_active = Date.now() - 11 * 60 * 1000;
  chrome.__state.localStore.lock_timeout_min = 10;
  const r = await sendMessage(onMessage, chrome, { type: "PV_SESSION_STATE" });
  assert.equal(r.locked, true);
  await flushTicks();
  const hits = chrome.__state.sentToTabs.filter((x) => x.msg && x.msg.type === "PV_GATE_LOCKED");
  assert.deepEqual(hits.map((x) => x.id).sort(), [7, 8]);
});
test("P6: PV_SAVE_LOGIN validates the sender FRAME, not the top tab", async () => {
  // Embedded login: top page shop.example.net, form in auth.example.com.
  // The credential belongs to the frame that submitted it.
  const { chrome, onMessage } = fresh();
  const sender = { url: "https://auth.example.com/login", tab: { url: "https://shop.example.net/checkout" } };
  const p = sendMessage(onMessage, chrome, {
    type: "PV_SAVE_LOGIN", username: "u", password: "p",
    url: "https://auth.example.com/login", title: "Auth",
  }, sender);
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  assert.equal(chrome.__state.postedNative[0].cmd, "save_login");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("P6: a frame may not save under a third site even when the tab matches", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { url: "https://evil.example.net/frame", tab: { url: "https://github.com/" } };
  const r = await sendMessage(onMessage, chrome, {
    type: "PV_SAVE_LOGIN", username: "u", password: "p",
    url: "https://github.com/login", title: "GitHub",
  }, sender);
  assert.equal(r.ok, false);
  assert.match(r.error || "", /does not match/i);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("PV_SAVE_CARD: proxies save_card after the sender-frame check", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { url: "https://shop.example/checkout", tab: { url: "https://shop.example/cart" } };
  const p = sendMessage(onMessage, chrome, {
    type: "PV_SAVE_CARD", number: "4111111111111111", cardholder: "Ada",
    exp_month: "12", exp_year: "30", cvv: "123",
    url: "https://shop.example/checkout", title: "Shop",
  }, sender);
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  const sent = chrome.__state.postedNative[0];
  assert.equal(sent.cmd, "save_card");
  assert.equal(sent.number, "4111111111111111");
  assert.equal(sent.exp_month, "12");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, updated: false }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("PV_SAVE_CARD: cross-site sender URL is refused, zero host spawn", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { tab: { url: "https://shop.example/checkout" } };
  const r = await sendMessage(onMessage, chrome, {
    type: "PV_SAVE_CARD", number: "4111111111111111", exp_month: "12", exp_year: "30",
    url: "https://evil.example/checkout",
  }, sender);
  assert.equal(r.ok, false);
  assert.match(r.error || "", /does not match/i);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("PV_CARDS: forwards the checkout `all` flag", async () => {
  const { chrome, onMessage } = fresh();
  const p = sendMessage(onMessage, chrome, { type: "PV_CARDS", app: "shop.example", all: true });
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  assert.equal(chrome.__state.postedNative[0].cmd, "cards");
  assert.equal(chrome.__state.postedNative[0].all, true);
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, entries: [] }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("P6: hotkey routes to the frame with the embedded login form", async () => {
  const { chrome } = fresh();
  chrome.__state.tabList = [{ id: 7, url: "https://shop.example.net/" }];
  chrome.scripting = {
    executeScript: async () => [
      { frameId: 0, result: { pass: false, text: true, focused: false, top: true } },
      { frameId: 4, result: { pass: true, text: true, focused: true, top: false } },
    ],
  };
  await chrome.__listeners.onCommand[0]("autofill_active_tab");
  const hit = chrome.__state.sentToTabs.filter((x) => x.msg && x.msg.type === "PV_HOTKEY_FILL");
  assert.equal(hit.length, 1);
  assert.equal(hit[0].opts.frameId, 4);
});

test("P6: hotkey falls back to the top frame on restricted pages", async () => {
  const { chrome } = fresh();
  chrome.__state.tabList = [{ id: 8, url: "https://shop.example.net/" }];
  chrome.scripting = { executeScript: async () => { throw new Error("no access"); } };
  await chrome.__listeners.onCommand[0]("autofill_active_tab");
  const hit = chrome.__state.sentToTabs.filter((x) => x.msg && x.msg.type === "PV_HOTKEY_FILL");
  assert.equal(hit.length, 1);
  assert.equal(hit[0].opts.frameId, 0);
});