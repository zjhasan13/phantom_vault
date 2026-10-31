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
  // 11 minutes idle > 10-minute timeout â‡’ locked.
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

test("A14: PV_EXT_PIN_STATUS/VERIFY never carry the PIN verifier", async () => {
  const { chrome, onMessage } = fresh();
  const pending = sendMessage(onMessage, chrome, { type: "PV_EXT_PIN_STATUS" });
  await flushTicks();
  assert.equal(chrome.__state.postedNative[0].cmd, "ext_pin_status");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, set: true }));
  assert.equal((await pending).set, true);

  const verify = sendMessage(onMessage, chrome, { type: "PV_EXT_PIN_VERIFY", pin: "1234" });
  await flushTicks();
  const sent = chrome.__state.postedNative[1];
  assert.equal(sent.cmd, "ext_pin_verify");
  assert.equal(sent.pin, "1234");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, valid: true }));
  const r = await verify;
  assert.equal(r.ok, true);
  assert.equal(r.valid, true);
});

// The router suspends at the first await (fetch), so postedNative only
// fills after microtasks drain â€” flush before asserting on spawns.
async function flushTicks(n = 5) {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
}

// SSRF/size shape: the harvester fetches page-declared URLs, so the fetch
// + size gates are the trust boundary (the host re-validates after).
function tinyIcon() {
  // Minimal valid PNG bytes (signature + IHDR + IEND); content is never
  // decoded here â€” only measured.
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
  const p1 = sendMessage(onMessage, chrome, { type: "PV_EXT_PIN_STATUS" });
  await flushTicks();
  assert.equal(chrome.__state.ports.length, 1);
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, set: true }));
  const r1 = await p1;
  assert.equal(r1.ok, true);
  // Second query must reuse the same port â€” no new host spawn.
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
  const p1 = sendMessage(onMessage, chrome, { type: "PV_EXT_PIN_STATUS" });
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
  // spawn â€” NOT silently drop or partially relay.
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
  // Marker absent â‡’ a later page load retries the fetch instead of
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
  // or `pvPending` â€” chrome.storage.session defaults to trusted contexts only.
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

test("PV_SAVE_IDENTITY: proxies save_identity after the sender-frame check", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { url: "https://shop.example/checkout", tab: { url: "https://shop.example/cart" } };
  const p = sendMessage(onMessage, chrome, {
    type: "PV_SAVE_IDENTITY", full_name: "Ada Lovelace", email: "ada@example.com",
    phone: "+1 555 0100", address: "1 Analytic Way",
    url: "https://shop.example/checkout", title: "Shop",
  }, sender);
  await flushTicks();
  assert.equal(chrome.__state.postedNative.length, 1);
  const sent = chrome.__state.postedNative[0];
  assert.equal(sent.cmd, "save_identity");
  assert.equal(sent.full_name, "Ada Lovelace");
  assert.equal(sent.email, "ada@example.com");
  assert.equal(sent.address, "1 Analytic Way");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, updated: false }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("PV_SAVE_IDENTITY: cross-site sender URL is refused, zero host spawn", async () => {
  const { chrome, onMessage } = fresh();
  const sender = { tab: { url: "https://shop.example/checkout" } };
  const r = await sendMessage(onMessage, chrome, {
    type: "PV_SAVE_IDENTITY", full_name: "Ada", email: "ada@example.com",
    url: "https://evil.example/checkout",
  }, sender);
  assert.equal(r.ok, false);
  assert.match(r.error || "", /does not match/i);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("PV_SAVE_IDENTITY: a missing url is refused", async () => {
  const { chrome, onMessage } = fresh();
  const r = await sendMessage(onMessage, chrome, {
    type: "PV_SAVE_IDENTITY", full_name: "Ada", email: "ada@example.com",
  }, { tab: { url: "https://shop.example/" } });
  assert.equal(r.ok, false);
  assert.match(r.error || "", /url required/i);
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
// ---- Proactive idle lock (chrome.alarms) ---------------------------------
// The timeout used to be evaluated only on the next message, so an open popup
// kept claiming "unlocked" for up to 15s and background tabs kept a warm gate
// cache. The alarm closes that window by TELLING every tab it locked.

test("idle alarm is armed once at load with a 1-minute period", () => {
  const { chrome } = fresh();
  const armed = chrome.__state.alarms.filter((a) => a.name === "pv_idle_check");
  assert.equal(armed.length, 1);
  assert.equal(armed[0].info.periodInMinutes, 1);
});

test("idle alarm broadcasts PV_GATE_LOCKED to every tab past the timeout", async () => {
  const { chrome } = fresh();
  chrome.__state.tabList = [
    { id: 1, url: "https://a.example/" },
    { id: 2, url: "https://b.example/" },
  ];
  chrome.__state.localStore.lock_timeout_min = 10;
  chrome.__state.sessionStore.pv_last_active = Date.now() - 11 * 60 * 1000;
  chrome.__listeners.onAlarm[0]({ name: "pv_idle_check" });
  await flushTicks();
  const locked = chrome.__state.sentToTabs.filter((x) => x.msg && x.msg.type === "PV_GATE_LOCKED");
  assert.deepEqual(locked.map((x) => x.id).sort(), [1, 2]);
  assert.ok(chrome.__state.sessionStore.pv_locked_at > 0);
});

test("idle alarm stays silent while the session is still fresh", async () => {
  const { chrome } = fresh();
  chrome.__state.tabList = [{ id: 1, url: "https://a.example/" }];
  chrome.__state.localStore.lock_timeout_min = 10;
  chrome.__state.sessionStore.pv_last_active = Date.now();
  chrome.__listeners.onAlarm[0]({ name: "pv_idle_check" });
  await flushTicks();
  const locked = chrome.__state.sentToTabs.filter((x) => x.msg && x.msg.type === "PV_GATE_LOCKED");
  assert.equal(locked.length, 0);
});

test("idle alarm respects lock_timeout_min 0 (Never)", async () => {
  const { chrome } = fresh();
  chrome.__state.tabList = [{ id: 1, url: "https://a.example/" }];
  chrome.__state.localStore.lock_timeout_min = 0;
  chrome.__state.sessionStore.pv_last_active = Date.now() - 60 * 60 * 1000;
  chrome.__listeners.onAlarm[0]({ name: "pv_idle_check" });
  await flushTicks();
  const locked = chrome.__state.sentToTabs.filter((x) => x.msg && x.msg.type === "PV_GATE_LOCKED");
  assert.equal(locked.length, 0);
});

test("idle alarm ignores unrelated alarm names", async () => {
  const { chrome } = fresh();
  chrome.__state.tabList = [{ id: 1, url: "https://a.example/" }];
  chrome.__state.sessionStore.pv_last_active = Date.now() - 60 * 60 * 1000;
  chrome.__listeners.onAlarm[0]({ name: "something_else" });
  await flushTicks();
  assert.equal(chrome.__state.sentToTabs.length, 0);
});

// ---- "Never save for this site" -----------------------------------------
// Content side hides the prompt; this is the defense-in-depth half, so a
// hostile/skewed content script cannot file a login the user refused.

test("PV_SAVE_LOGIN is refused for a domain in never_save_domains", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.localStore.never_save_domains = ["example.com"];
  const r = await sendMessage(
    onMessage,
    chrome,
    { type: "PV_SAVE_LOGIN", username: "u", password: "p", url: "https://login.example.com/in", title: "Example" },
    { tab: { url: "https://login.example.com/in" }, url: "https://login.example.com/in" },
  );
  assert.equal(r.ok, false);
  assert.match(r.error || "", /never save/i);
  assert.equal(chrome.__state.ports.length, 0);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("PV_SAVE_LOGIN still reaches the host for unlisted domains", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.localStore.never_save_domains = ["other.com"];
  const p = sendMessage(
    onMessage,
    chrome,
    { type: "PV_SAVE_LOGIN", username: "u", password: "p", url: "https://example.com/login", title: "Example" },
    { tab: { url: "https://example.com/login" }, url: "https://example.com/login" },
  );
  await flushTicks();
  assert.equal(chrome.__state.postedNative[0].cmd, "save_login");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("never_save_domains tolerates a corrupted (non-array) value", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.localStore.never_save_domains = "not-an-array";
  const p = sendMessage(
    onMessage,
    chrome,
    { type: "PV_SAVE_LOGIN", username: "u", password: "p", url: "https://example.com/login", title: "Example" },
    { tab: { url: "https://example.com/login" }, url: "https://example.com/login" },
  );
  await flushTicks();
  assert.equal(chrome.__state.postedNative[0].cmd, "save_login");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r = await p;
  assert.equal(r.ok, true);
});
// ---- A3: item editor (popup) + reprompt ----

test("A3: popup creates a login through create_login", async () => {
  const { chrome, onMessage } = fresh();
  const p = sendMessage(onMessage, chrome, {
    type: "PV_ITEM_CREATE", title: "GitHub", username: "octo", password: "s3cret",
    url: "https://github.com/login", folder: "Work", reprompt: false,
  });
  await flushTicks();
  const sent = chrome.__state.postedNative[0];
  assert.equal(sent.cmd, "create_login");
  assert.equal(sent.username, "octo");
  assert.equal(sent.folder, "Work");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, id: "ext1" }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("A3: a content script cannot mutate vault items", async () => {
  const { chrome, onMessage } = fresh();
  const r = await sendMessage(onMessage, chrome,
    { type: "PV_ITEM_DELETE", id: "c1" },
    { tab: { id: 4, url: "https://evil.example/" } });
  assert.equal(r.ok, false);
  assert.match(r.error || "", /popup-only/i);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("A3: update forwards the partial edit and reprompt token", async () => {
  const { chrome, onMessage } = fresh();
  const p = sendMessage(onMessage, chrome, {
    type: "PV_ITEM_UPDATE", id: "c1", folder: "Finance", reprompt: true,
    reprompt_token: "rp-1",
  });
  await flushTicks();
  const sent = chrome.__state.postedNative[0];
  assert.equal(sent.cmd, "update_login");
  assert.equal(sent.id, "c1");
  assert.equal(sent.folder, "Finance");
  assert.equal(sent.reprompt, true);
  assert.equal(sent.reprompt_token, "rp-1");
  assert.ok(!("username" in sent), "absent fields stay absent");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("A3: delete proxies delete_login with the token", async () => {
  const { chrome, onMessage } = fresh();
  const p = sendMessage(onMessage, chrome,
    { type: "PV_ITEM_DELETE", id: "c9", reprompt_token: "rp-9" });
  await flushTicks();
  const sent = chrome.__state.postedNative[0];
  assert.equal(sent.cmd, "delete_login");
  assert.equal(sent.id, "c9");
  assert.equal(sent.reprompt_token, "rp-9");
  assert.ok(!("password" in sent));
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true }));
  const r = await p;
  assert.equal(r.ok, true);
});

test("A3: PV_REPROMPT proxies verify_master and never stores the password", async () => {
  const { chrome, onMessage } = fresh();
  const p = sendMessage(onMessage, chrome, { type: "PV_REPROMPT", password: "master-pw" });
  await flushTicks();
  assert.equal(chrome.__state.postedNative[0].cmd, "verify_master");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: true, token: "rp" }));
  const r = await p;
  assert.equal(r.ok, true);
  assert.equal(r.token, "rp");
  assert.ok(!("master-pw" in chrome.__state.sessionStore));
});

test("A3: PV_REPROMPT is refused from a page", async () => {
  const { chrome, onMessage } = fresh();
  const r = await sendMessage(onMessage, chrome,
    { type: "PV_REPROMPT", password: "x" },
    { tab: { id: 2, url: "https://evil.example/" } });
  assert.equal(r.ok, false);
  assert.equal(chrome.__state.postedNative.length, 0);
});

// ---- A4: clipboard auto-clear ----

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

test("A4: PV_CLIP_ARM stores the hash and schedules one alarm", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.localStore.clipboard_clear_sec = 45;
  const before = Date.now();
  const r = await sendMessage(onMessage, chrome, { type: "PV_CLIP_ARM", hash: HASH_A });
  assert.equal(r.ok, true);
  assert.equal(r.seconds, 45);
  const armed = chrome.__state.alarms.filter((a) => a.name === "pv_clip_clear");
  assert.equal(armed.length, 1);
  assert.ok(armed[0].info.when >= before + 45000 - 50);
  assert.ok(chrome.__state.sessionStore.pv_clip_clear_at >= before + 45000);
  assert.equal(chrome.__state.sessionStore.pv_clip_hash, HASH_A);
  assert.ok(chrome.__state.alarmsCleared.includes("pv_clip_clear"));
});

test("A4: PV_CLIP_ARM without a hash refuses to arm a blind clear", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.localStore.clipboard_clear_sec = 45;
  const r = await sendMessage(onMessage, chrome, { type: "PV_CLIP_ARM" });
  assert.equal(r.armed, false);
  assert.equal(
    chrome.__state.alarms.filter((a) => a.name === "pv_clip_clear").length, 0);
  assert.equal(chrome.__state.sessionStore.pv_clip_hash, undefined);
});

test("A4: PV_CLIP_ARM clamps short values and honours an explicit override", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.localStore.clipboard_clear_sec = 30;
  let r = await sendMessage(onMessage, chrome, { type: "PV_CLIP_ARM", seconds: 1, hash: HASH_A });
  assert.equal(r.seconds, 5, "minimum 5s");
  r = await sendMessage(onMessage, chrome, { type: "PV_CLIP_ARM", seconds: 99999, hash: HASH_A });
  assert.equal(r.seconds, 3600, "maximum 1h");
});

test("A4: timeout 0 disarms and clears the stored deadline", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.localStore.clipboard_clear_sec = 0;
  chrome.__state.sessionStore.pv_clip_clear_at = Date.now() + 30000;
  chrome.__state.sessionStore.pv_clip_hash = HASH_A;
  const r = await sendMessage(onMessage, chrome, { type: "PV_CLIP_ARM", hash: HASH_A });
  assert.equal(r.armed, false);
  assert.equal(chrome.__state.sessionStore.pv_clip_clear_at, undefined);
  assert.equal(chrome.__state.sessionStore.pv_clip_hash, undefined);
});

test("A4: the alarm clears through the offscreen document and drops the marker", async () => {
  const { chrome } = fresh();
  chrome.__state.sessionStore.pv_clip_clear_at = Date.now() + 30000;
  chrome.__state.sessionStore.pv_clip_hash = HASH_A;
  chrome.__listeners.onAlarm[0]({ name: "pv_clip_clear" });
  await flushTicks();
  assert.equal(chrome.__state.offscreenDocs.length, 1);
  assert.equal(chrome.__state.offscreenDocs[0].reasons[0], "CLIPBOARD");
  const clear = chrome.__state.runtimeMessages.filter(
    (m) => m && m.target === "offscreen" && m.type === "PV_CLIP_CLEAR");
  assert.equal(clear.length, 1);
  assert.equal(clear[0].hash, HASH_A, "clear is hash-guarded");
  assert.equal(chrome.__state.sessionStore.pv_clip_clear_at, undefined);
  assert.equal(chrome.__state.sessionStore.pv_clip_hash, undefined);
});

test("A4: a stale alarm without a hash never blanks the clipboard", async () => {
  const { chrome } = fresh();
  chrome.__state.sessionStore.pv_clip_clear_at = Date.now() + 30000;
  chrome.__listeners.onAlarm[0]({ name: "pv_clip_clear" });
  await flushTicks();
  assert.equal(chrome.__state.offscreenDocs.length, 0);
  assert.equal(chrome.__state.sentToTabs.length, 0);
});

test("A4: without offscreen support the alarm falls back to content scripts", async () => {
  const { chrome } = fresh();
  delete chrome.offscreen;
  chrome.__state.tabList = [{ id: 7 }, { id: 8 }];
  chrome.__state.sessionStore.pv_clip_clear_at = Date.now() + 30000;
  chrome.__state.sessionStore.pv_clip_hash = HASH_B;
  chrome.__listeners.onAlarm[0]({ name: "pv_clip_clear" });
  await flushTicks();
  const hits = chrome.__state.sentToTabs.filter((x) => x.msg && x.msg.type === "PV_CLIP_CLEAR");
  assert.deepEqual(hits.map((x) => x.id).sort(), [7, 8]);
  assert.ok(hits.every((x) => x.opts && x.opts.frameId === 0));
  assert.ok(hits.every((x) => x.msg.hash === HASH_B));
});

test("A4: re-arming with a new secret replaces the old hash", async () => {
  const { chrome, onMessage } = fresh();
  chrome.__state.localStore.clipboard_clear_sec = 30;
  await sendMessage(onMessage, chrome, { type: "PV_CLIP_ARM", hash: HASH_A });
  await sendMessage(onMessage, chrome, { type: "PV_CLIP_ARM", hash: HASH_B });
  assert.equal(chrome.__state.sessionStore.pv_clip_hash, HASH_B);
});

test("A4: PV_COPY_SECRET proxies copy_secret to the native host", async () => {
  const { chrome, onMessage } = fresh();
  const p = sendMessage(onMessage, chrome,
    { type: "PV_COPY_SECRET", text: "s3cret", seconds: 45 });
  await flushTicks();
  const sent = chrome.__state.postedNative[0];
  assert.equal(sent.cmd, "copy_secret");
  assert.equal(sent.text, "s3cret");
  assert.equal(sent.ttl_secs, 45);
  chrome.__state.ports[0].handlers.message.forEach((fn) =>
    fn({ ok: true, native: true, ttl_secs: 45 }));
  const r = await p;
  assert.equal(r.ok, true);
  assert.equal(r.native, true);
  assert.equal(chrome.__state.alarms.filter((a) => a.name === "pv_clip_clear").length, 0,
    "native host owns the timer");
});

test("A4: a page cannot use PV_COPY_SECRET as a clipboard service", async () => {
  const { chrome, onMessage } = fresh();
  const r = await sendMessage(onMessage, chrome,
    { type: "PV_COPY_SECRET", text: "x" },
    { tab: { id: 3, url: "https://evil.example/" } });
  assert.equal(r.ok, false);
  assert.equal(chrome.__state.postedNative.length, 0);
});

test("A4: unrelated alarms stay silent for the clipboard path", async () => {
  const { chrome } = fresh();
  chrome.__listeners.onAlarm[0]({ name: "pv_idle_check" });
  await flushTicks();
  assert.equal(chrome.__state.offscreenDocs.length, 0);
  assert.equal(chrome.__state.runtimeMessages.length, 0);
});

// --- A11: Hello-gated offline cache -------------------------------------
const OFFLINE_ENTRIES = [
  { id: "1", title: "GitHub", username: "u", password: "p", urls: ["https://github.com"] },
  { id: "2", title: "Other", username: "x", password: "y", urls: ["https://other.test"] },
];
function cacheFrame() {
  return {
    ok: true, cached: true, created_at: 42, ttl_secs: 900,
    entries: OFFLINE_ENTRIES,
  };
}

test("A11b: cache status is prompt-free and reports both methods", async () => {
  const { chrome, onMessage } = fresh();
  const p = sendMessage(onMessage, chrome, { type: "PV_CACHE_STATUS" });
  await flushTicks();
  assert.equal(chrome.__state.postedNative[0].cmd, "cache_status");
  chrome.__state.ports[0].handlers.message.forEach((fn) =>
    fn({ ok: true, enabled: true, pin_set: true, pin_allowed: true, cached: false }));
  const r = await p;
  assert.equal(r.ok, true);
  assert.equal(r.enabled, true);
  assert.equal(r.pin_set, true);
  assert.equal(r.pin_allowed, true);
  assert.equal(r.cached, false);
});

test("A11b: PIN unlock uses cache_get method=pin, then queries serve cached rows", async () => {
  const { chrome, onMessage } = fresh();
  const unlock = sendMessage(onMessage, chrome, { type: "PV_CACHE_PIN", pin: "1234" });
  await flushTicks();
  const sent = chrome.__state.postedNative[0];
  assert.equal(sent.cmd, "cache_get");
  assert.equal(sent.method, "pin");
  assert.equal(sent.pin, "1234");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn(cacheFrame()));
  assert.equal((await unlock).ok, true);

  const q = sendMessage(onMessage, chrome, { type: "PV_QUERY", app: "github.com" });
  await flushTicks();
  assert.equal(chrome.__state.postedNative[1].cmd, "query");
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: false, error: "closed" }));
  const r = await q;
  assert.equal(r.ok, true);
  assert.equal(r.cached, true);
  assert.equal(r.entries.length, 1);
  assert.equal(r.entries[0].password, "p");
  assert.equal(r.cache_synced_at, 42);
});

test("A11b: a warm snapshot serves queries without a second gate prompt", async () => {
  const { chrome, onMessage } = fresh();
  const first = sendMessage(onMessage, chrome, { type: "PV_CACHE_HELLO" });
  await flushTicks();
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn(cacheFrame()));
  await first;

  const again = sendMessage(onMessage, chrome, { type: "PV_QUERY", app: "github.com" });
  await flushTicks();
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: false, error: "closed" }));
  const r = await again;
  assert.equal(r.cached, true);
  assert.equal(
    chrome.__state.postedNative.filter((x) => x.cmd === "cache_get").length,
    1,
    "TTL snapshot is reused, not re-prompted",
  );
});

test("A11b: a lock verdict clears the decrypted snapshot", async () => {
  const { chrome, onMessage } = fresh();
  const warm = sendMessage(onMessage, chrome, { type: "PV_CACHE_HELLO" });
  await flushTicks();
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn(cacheFrame()));
  await warm;

  chrome.__state.sessionStore.pv_last_active = Date.now() - 11 * 60 * 1000;
  chrome.__state.localStore.lock_timeout_min = 10;
  const st = await sendMessage(onMessage, chrome, { type: "PV_SESSION_STATE" });
  assert.equal(st.locked, true);

  const status = sendMessage(onMessage, chrome, { type: "PV_CACHE_STATUS" });
  await flushTicks();
  assert.equal(chrome.__state.postedNative.filter((x) => x.cmd === "cache_status").length, 1);
  chrome.__state.ports[0].handlers.message.forEach((fn) =>
    fn({ ok: true, enabled: true, pin_set: true, cached: false }));
  assert.equal((await status).cached, false, "lock dropped the warm snapshot");
});

test("A11b: an empty query never dumps the cache", async () => {
  const { chrome, onMessage } = fresh();
  const warm = sendMessage(onMessage, chrome, { type: "PV_CACHE_HELLO" });
  await flushTicks();
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn(cacheFrame()));
  await warm;

  const p = sendMessage(onMessage, chrome, { type: "PV_QUERY", app: "" });
  await flushTicks();
  chrome.__state.ports[0].handlers.message.forEach((fn) => fn({ ok: false, error: "closed" }));
  const r = await p;
  assert.equal(r.ok, false);
  assert.equal(r.entries, undefined);
});
