#!/usr/bin/env node
// background.js router tests (harness v1). Run: `node --test tests/js/`
import test from "node:test";
import assert from "node:assert/strict";
import { makeChrome, loadBackground, sendMessage } from "./harness.mjs";

function fresh() {
  const chrome = makeChrome();
  const onMessage = loadBackground(chrome);
  return { chrome, onMessage };
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
