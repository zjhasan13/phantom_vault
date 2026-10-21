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

test("card form submit offers to save the card", async (t) => {
  const { window, store } = env(t, `<form>
    <input autocomplete="cc-number" name="cardnumber" value="4111 1111 1111 1111">
    <input autocomplete="cc-name" name="cardholder" value="Ada L">
    <input autocomplete="cc-exp" name="exp" value="12/30">
    <input autocomplete="cc-csc" name="cvv" value="123">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  const banner = saver(window);
  assert.ok(banner, "card save banner should appear");
  assert.match(banner.textContent, /Save card/i);
  const save = [...banner.querySelectorAll("button")].find((b) => /Save/.test(b.textContent));
  save.click();
  await flush();
  assert.equal(store.cardSaves.length, 1);
  assert.equal(store.cardSaves[0].number, "4111111111111111");
  assert.equal(store.cardSaves[0].exp_month, "12");
  assert.equal(store.cardSaves[0].exp_year, "30");
  assert.equal(store.cardSaves[0].cvv, "123");
});

test("split expiry selects are normalized before save", async (t) => {
  const { window, store } = env(t, `<form>
    <input name="cardnumber" value="4111111111111111">
    <select autocomplete="cc-exp-month" name="expmonth"><option value="12">12</option></select>
    <select autocomplete="cc-exp-year" name="expyear"><option value="2030">2030</option></select>
    <input name="cvv" value="123">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  const banner = saver(window);
  assert.ok(banner);
  [...banner.querySelectorAll("button")].find((b) => /Save/.test(b.textContent)).click();
  await flush();
  assert.equal(store.cardSaves[0].exp_month, "12");
  assert.equal(store.cardSaves[0].exp_year, "30");
});

test("card[...] names and YYYY-MM expiry save correctly", async (t) => {
  const { window, store } = env(t, `<form>
    <input name="card[number]" value="4111111111111111">
    <input name="card[name]" value="ADA LOVELACE">
    <input name="card[exp]" value="2030-12">
    <input name="card[cvc]" value="123">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  const banner = saver(window);
  assert.ok(banner);
  [...banner.querySelectorAll("button")].find((b) => /Save/.test(b.textContent)).click();
  await flush();
  assert.equal(store.cardSaves[0].exp_month, "12");
  assert.equal(store.cardSaves[0].exp_year, "30");
  assert.equal(store.cardSaves[0].cardholder, "ADA LOVELACE");
});

test("invalid (Luhn) card number never offers a save", async (t) => {
  const { window } = env(t, `<form>
    <input autocomplete="cc-number" value="4111111111111112">
    <input autocomplete="cc-exp" value="12/30">
    <input autocomplete="cc-csc" value="123">
  </form>`);
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.equal(saver(window), null);
});

test("already-saved card is silent on submit", async (t) => {
  const { window } = env(t, `<form>
    <input autocomplete="cc-number" value="4111111111111111">
    <input autocomplete="cc-exp" value="12/30">
    <input autocomplete="cc-csc" value="123">
  </form>`, "https://example.com/checkout", [],
    [{ id: "c1", number: "4111111111111111", exp_month: "12", exp_year: "30", cvv: "123" }]);
  await flush(); // let the boot card-list warm resolve
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.equal(saver(window), null);
});

test("form-less login gets ONE shield (on the password), not one per field", (t) => {
  const { window } = env(t, `<div class="login">
    <div><input type="text" name="user"></div>
    <div><input type="password" name="pass"></div>
  </div>
  <div><input type="text" name="nickname"></div>
  <div><input type="email" name="newsletter"></div>`);
  const badged = (n) =>
    !!window.document.querySelector(`input[name="${n}"]`).dataset.pvBadged;
  assert.equal(badged("pass"), true, "password carries the single shield");
  assert.equal(badged("user"), false, "username shares the password's shield");
  assert.equal(badged("nickname"), false, "unrelated page text boxes stay badge-free");
});

test("form login gets one shield and no stray badges", (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="user">
    <input type="password" name="pass">
  </form>
  <div><input type="text" name="nickname"></div>`);
  const badged = (n) =>
    !!window.document.querySelector(`input[name="${n}"]`).dataset.pvBadged;
  assert.equal(badged("pass"), true);
  assert.equal(badged("user"), false, "one shield per login form");
  assert.equal(badged("nickname"), false, "a password elsewhere must not badge stray inputs");
});

test("matched username-only step still gets its single shield", async (t) => {
  const { window } = env(t, `<div class="login"><input type="email" name="email"></div>`,
    "https://example.com/login",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush();
  assert.ok(window.document.querySelector('input[name="email"]').dataset.pvBadged,
    "multi-step email/username pages must stay clickable");
});

test("a revealed password replaces the standalone email shield", async (t) => {
  const { window } = env(t, `<form action="/login"><input type="email" name="email"></form>`,
    "https://example.com/start",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush();
  const email = window.document.querySelector('input[name="email"]');
  const form = window.document.querySelector("form");
  assert.ok(email.dataset.pvBadged);
  const pw = window.document.createElement("input");
  pw.type = "password"; pw.name = "password";
  form.appendChild(pw);
  await new Promise((r) => setTimeout(r, 250));
  assert.equal(email.dataset.pvBadged, undefined, "username shield folds into the form shield");
  assert.ok(pw.dataset.pvBadged);
  assert.equal(window.document.querySelectorAll('button[title="Fill with PhantomVault"]').length, 1,
    "rescan must not leave two shields on one form");
});

test("signup form gets a single dice, never an email shield", async (t) => {
  const { window } = env(t, `<form>
    <input type="email" name="email">
    <input type="password" autocomplete="new-password" name="new_password">
    <input type="password" autocomplete="new-password" name="confirm_password">
  </form>`, "https://example.com/signup",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush();
  const icons = [...window.document.querySelectorAll("button")]
    .filter((b) => /PhantomVault/.test(b.title));
  assert.equal(icons.length, 1, "one icon per credential context");
  assert.match(icons[0].title, /Generate/);
  assert.equal(window.document.querySelector('input[name="email"]').dataset.pvBadged, undefined);
});

test("change-password form has ONE shield with fill + generate actions", async (t) => {
  const { window } = env(t, `<form>
    <input type="password" name="current_password" value="old">
    <input type="password" autocomplete="new-password" name="new_password">
    <input type="password" autocomplete="new-password" name="confirm_password">
  </form>`, "https://example.com/account/password",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush();
  const icons = [...window.document.querySelectorAll("button")]
    .filter((b) => /PhantomVault/.test(b.title));
  assert.equal(icons.length, 1, "no second dice on the same form");
  icons[0].click();
  await flush(80);
  const gen = [...window.document.querySelectorAll("button")]
    .find((b) => /Generate strong password/.test(b.textContent));
  assert.ok(gen, "shield menu exposes generation for the new field");
  gen.dispatchEvent(new window.MouseEvent("mousedown", { bubbles: true, cancelable: true }));
  await flush(40);
  const v = (n) => window.document.querySelector(`input[name="${n}"]`).value;
  assert.equal(v("current_password"), "old", "current password is never overwritten");
  assert.ok(v("new_password").length >= 16);
  assert.equal(v("new_password"), v("confirm_password"));
});

test("checkout and login on one page keep one icon per context", async (t) => {
  const { window } = env(t, `<form class="login">
      <input type="email" name="email"><input type="password" name="password">
    </form>
    <form class="checkout">
      <input type="email" name="billing_email">
      <input autocomplete="cc-number" value="4111111111111111">
      <input autocomplete="cc-exp" value="12/30">
      <input autocomplete="cc-csc" value="123">
    </form>`, "https://example.com/checkout",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush(60);
  assert.ok(window.document.querySelector('input[name="password"]').dataset.pvBadged);
  assert.equal(window.document.querySelector('input[name="billing_email"]').dataset.pvBadged, undefined,
    "billing email belongs to the card context, not a login");
  const icons = [...window.document.querySelectorAll("button")]
    .filter((b) => /PhantomVault/.test(b.title));
  assert.equal(icons.length, 2, "login shield + card shield");
});

test("removing a field removes its stale shield", async (t) => {
  const { window } = env(t, `<form><input type="password" name="password"></form>`,
    "https://example.com/login",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush();
  const pw = window.document.querySelector('input[name="password"]');
  assert.ok(pw.dataset.pvBadged);
  pw.remove();
  await new Promise((r) => setTimeout(r, 250));
  assert.equal([...window.document.querySelectorAll("button")]
    .filter((b) => /PhantomVault/.test(b.title)).length, 0);
});

test("matched newsletter email is never badged", async (t) => {
  const { window } = env(t, `<form class="newsletter"><input type="email" name="email"></form>`,
    "https://example.com/newsletter",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush();
  assert.equal(window.document.querySelector('input[name="email"]').dataset.pvBadged, undefined);
});

test("email-only login step is badged from its action/path", async (t) => {
  const { window } = env(t, `<form action="/login"><input type="email" name="email"></form>`,
    "https://example.com/start",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush();
  assert.ok(window.document.querySelector('input[name="email"]').dataset.pvBadged);
});

test("E4/P6: all frames load the engine, domain decisions use the frame origin", () => {
  const read = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
  for (const mf of ["manifest.json", "manifest.firefox.json"]) {
    const m = JSON.parse(read("../../browser_extension/" + mf));
    assert.equal(m.content_scripts[0].all_frames, true, mf + " must opt into subframes");
    assert.deepEqual(m.content_scripts[0].js, ["domain.js", "content.js"]);
  }
  const src = read("../../browser_extension/content.js");
  // P6: cross-origin frames are no longer inert — an embedded login widget is
  // filled by the frame that owns it, using its own origin for every match.
  assert.ok(!/if \(window\.top !== window\)/.test(src),
    "no early return for cross-origin frames");
  assert.ok(!src.includes("window.top.location"),
    "must never read the top document's location");
  assert.ok(src.includes("function pageBase() { return registrable(location.hostname); }"),
    "frame-local origin is the matching source");
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

test("P1: save stores canonical URL + site brand (og:site_name)", async (t) => {
  const { window, store } = env(t, `<head>
    <meta property="og:site_name" content="Example">
    <title>Sign in - Example</title>
  </head><form>
    <input type="text" name="username" value="bob">
    <input type="password" name="password" value="pw">
  </form>`, "https://example.com/login?token=secret#frag");
  submit(window, window.document.querySelector("form"));
  await flush();
  saver(window).querySelector("button").click();
  await flush();
  assert.equal(store.saves.length, 1, "one bridge save");
  assert.equal(store.saves[0].url, "https://example.com/login",
    "query + fragment stripped, path kept");
  assert.equal(store.saves[0].title, "Example", "brand meta wins over title");
});

test("P1: title suffix heuristic + root URL normalization", async (t) => {
  const { window, store } = env(t, `<head>
    <title>Sign in – Example</title>
  </head><form>
    <input type="text" name="username" value="bob">
    <input type="password" name="password" value="pw">
  </form>`, "https://example.org/?next=%2F#top");
  submit(window, window.document.querySelector("form"));
  await flush();
  saver(window).querySelector("button").click();
  await flush();
  assert.equal(store.saves[0].url, "https://example.org");
  assert.equal(store.saves[0].title, "Example",
    "generic 'Sign in' segment skipped, brand kept");
});

test("P3: PV_FILL_ENTRY fills through the content engine", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="">
    <input type="password" name="password" value="">
  </form>`, "https://example.com/login",
    [{ id: "e1", title: "Example", username: "alice", password: "hunter2", urls: ["example.com"] }]);
  const res = await runtimeMessage(window, { type: "PV_FILL_ENTRY", id: "e1" });
  await flush();
  assert.ok(res && res.ok, "content accepted the fill");
  assert.equal(res.filled, 2, "username + password counted");
  assert.equal(window.document.querySelector('input[name="username"]').value, "alice");
  assert.equal(window.document.querySelector('input[name="password"]').value, "hunter2");
});

test("P3: PV_FILL_ENTRY refuses ids the page domain cannot claim", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="keep">
    <input type="password" name="password" value="keep">
  </form>`, "https://discord-login.com/login",
    [{ id: "desk1", title: "Discord", username: "alice", password: "hunter2" }]);
  const res = await runtimeMessage(window, { type: "PV_FILL_ENTRY", id: "desk1" });
  await flush();
  assert.equal(res.ok, false);
  assert.equal(res.error, "not for this site");
  assert.equal(window.document.querySelector('input[name="password"]').value, "keep");
});

test("E6: document scans run through one debounced observer", () => {
  const src = readFileSync(new URL("../../browser_extension/content.js", import.meta.url), "utf8");
  assert.equal((src.match(/new MutationObserver\(pvScheduleScan\)/g) || []).length, 1);
  assert.ok(!/new MutationObserver\(scan\)/.test(src), "no undebounced scan observer");
  assert.ok(!/new MutationObserver\(scanForms\)/.test(src), "no undebounced scanForms observer");
  assert.match(src, /pvScanTimer = setTimeout\(\(\) => \{[\s\S]{0,120}scan\(\);[\s\S]{0,80}scanForms\(\);[\s\S]{0,40}\}, 120\)/);
});
