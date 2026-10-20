// content.js capture-engine tests (Tier 0). Run: `node --test tests/js/`
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadContent, submit, flush, runtimeMessage } from "./content-harness.mjs";

const saver = (window) => window.document.getElementById("__pv_saver");

// Each jsdom window must be closed or its 30 s toast-dismiss timers keep the
// test process alive long after the assertions pass.
function env(t, ...args) {
  const { dom, window, store } = loadContent(...args);
  t.after(() => dom.window.close());
  return { window, store };
}

test("login form (username+password) offers a save banner", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw123">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  const banner = saver(window);
  assert.ok(banner, "save banner should appear for a new login");
  assert.match(banner.textContent, /Save to PhantomVault/);
});

test("G1: signup form with only new-password still offers save (was skipped)", async (t) => {
  // The old selector `input[type=password]:not([autocomplete=new-password])`
  // matched nothing here, so registration submits were never captured.
  const { window } = env(t, `<form>
    <input type="email" name="email" value="new@user.com">
    <input type="password" autocomplete="new-password" name="password" value="S3cret!">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.ok(saver(window), "signup must offer save");
});

test("G3: confirm-password mismatch does not offer", async (t) => {
  const { window } = env(t, `<form>
    <input type="email" name="email" value="new@user.com">
    <input type="password" autocomplete="new-password" name="password" value="aaa111">
    <input type="password" autocomplete="new-password" name="confirm" value="bbb222">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.equal(saver(window), null);
});

test("K1: page-1 email submit carries the username (no password yet)", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="email" name="email" value="step1@user.com">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  const c = store.session.pvCaptureCarry;
  assert.ok(c, "carry must be written");
  assert.equal(c.username, "step1@user.com");
  assert.equal(c.password, undefined, "password must never be carried (P1-b)");
});

test("known credential is silent (no banner)", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="bob">
    <input type="password" name="password" value="pw">
  </form>`, "https://example.com/login", [{ username: "bob", password: "pw", urls: ["example.com"] }]);
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.equal(saver(window), null);
});

test("search box is never treated as a credential form", async (t) => {
  const { window, store } = env(t, `<form role="search">
    <input type="search" name="q" value="hello world">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.equal(saver(window), null);
  assert.equal(store.session.pvCaptureCarry, undefined);
});

test("E4: all frames load the script, cross-origin frames stay inert", () => {
  const read = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
  for (const mf of ["manifest.json", "manifest.firefox.json"]) {
    const m = JSON.parse(read("../../browser_extension/" + mf));
    assert.equal(m.content_scripts[0].all_frames, true, mf + " must opt into subframes");
    assert.deepEqual(m.content_scripts[0].js, ["domain.js", "content.js"]);
  }
  const src = read("../../browser_extension/content.js");
  const guard = src.indexOf("window.top !== window");
  assert.ok(guard > 0, "same-origin frame guard must exist");
  assert.ok(guard < src.indexOf("const DEFAULTS"), "frame guard must run before capture setup");
});

test("E5: desktop gate is bounded by TTL and dropped on focus", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw">
  </form>`);
  const realNow = window.Date.now.bind(window.Date);
  let now = realNow();
  window.Date.now = () => now;
  t.after(() => { window.Date.now = realNow; });
  const fill = () => runtimeMessage(window, { type: "PV_HOTKEY_FILL" });

  await fill();
  assert.equal(store.pings, 1, "first action probes the desktop");
  await fill();
  assert.equal(store.pings, 1, "second action reuses the warm cache");

  now += 31 * 1000;
  await fill();
  assert.equal(store.pings, 2, "cache must expire after 30 s");

  window.dispatchEvent(new window.Event("focus"));
  now += 1;
  await fill();
  assert.equal(store.pings, 3, "returning to the tab forces re-verification");
});

test("E5: PV_GATE_LOCKED drops a warm desktop-gate cache", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw">
  </form>`);
  const fill = () => runtimeMessage(window, { type: "PV_HOTKEY_FILL" });
  await fill();
  assert.equal(store.pings, 1);
  await fill();
  assert.equal(store.pings, 1, "warm cache avoids a second probe");
  await runtimeMessage(window, { type: "PV_GATE_LOCKED" });
  await fill();
  assert.equal(store.pings, 2, "a lock broadcast forces the next action to re-probe");
});

test("P0: URL-less items never autofill on the web", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="keep">
    <input type="password" name="password" value="keep">
  </form>`, "https://discord-login.com/login",
    [{ id: "desk1", title: "Discord", username: "alice", password: "hunter2" }]);
  await runtimeMessage(window, { type: "PV_HOTKEY_FILL" });
  await flush();
  assert.equal(window.document.querySelector('input[name="username"]').value, "keep",
    "unbound item must not touch the username field");
  assert.equal(window.document.querySelector('input[name="password"]').value, "keep",
    "unbound item must not touch the password field");
});

test("P0: URL-bound item still autofills (control)", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="">
    <input type="password" name="password" value="">
  </form>`, "https://discord.com/login",
    [{ id: "web1", title: "Discord", username: "alice", password: "hunter2", urls: ["discord.com"] }]);
  await runtimeMessage(window, { type: "PV_HOTKEY_FILL" });
  await flush();
  assert.equal(window.document.querySelector('input[name="username"]').value, "alice");
  assert.equal(window.document.querySelector('input[name="password"]').value, "hunter2");
});

test("E6: document scans run through one debounced observer", () => {
  const src = readFileSync(new URL("../../browser_extension/content.js", import.meta.url), "utf8");
  assert.equal((src.match(/new MutationObserver\(pvScheduleScan\)/g) || []).length, 1);
  assert.ok(!/new MutationObserver\(scan\)/.test(src), "no undebounced scan observer");
  assert.ok(!/new MutationObserver\(scanForms\)/.test(src), "no undebounced scanForms observer");
  assert.match(src, /pvScanTimer = setTimeout\(\(\) => \{[\s\S]{0,120}scan\(\);[\s\S]{0,80}scanForms\(\);[\s\S]{0,40}\}, 120\)/);
});
