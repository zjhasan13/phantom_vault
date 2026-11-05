// content.js capture-engine tests (Tier 0). Run: `node --test tests/js/`
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadContent, submit, flush, runtimeMessage, shadowOf } from "./content-harness.mjs";

const saver = (window) => window.document.getElementById("__pv_saver");
// A9: the login prompts keep their fields and buttons in a closed shadow root,
// so tests reach them through the harness spy rather than the page tree.
// Card/identity prompts have no shadow tree; shadowOf() falls back to the host.
const saverRoot = (window) => shadowOf(saver(window));
const saverButton = (window, re) =>
  [...saverRoot(window).querySelectorAll("button")].find((b) => re.test(b.textContent));

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
  assert.match(saverRoot(window).textContent, /Save this login/);
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

test("carry-priority: previous step's email sorts first in the login dropdown", async (t) => {
  const { window } = env(t, `<form id="step1">
    <input type="email" name="email" value="alice@example.com">
  </form>
  <form id="step2">
    <input type="password" name="password" value="">
  </form>`, "https://example.com/login", [
    { id: "c2", title: "Example", username: "zed@example.com", password: "p2",
      urls: ["example.com"], verified: true, last_filled: Math.floor(Date.now() / 1000) },
    { id: "c1", title: "Example", username: "alice@example.com", password: "p1",
      urls: ["example.com"], verified: false, last_filled: 0 },
  ]);
  // Page 1 submits the email → the username is carried (no password yet).
  submit(window, window.document.getElementById("step1"));
  await flush();
  // Page 2 focuses the password field → the dropdown opens.
  const pw = window.document.querySelector('#step2 input[type="password"]');
  pw.dispatchEvent(new window.Event("focusin", { bubbles: true }));
  await flush(80);
  const rows = [...window.document.querySelectorAll("button[data-pv-index]")];
  assert.ok(rows.length >= 2, "dropdown should list both accounts");
  assert.match(rows[0].textContent, /alice@example\.com/,
    "carried email must be first even though the other account is verified");
  assert.match(rows[0].textContent, /this step/);
  assert.match(rows[1].textContent, /zed@example\.com/);
});

test("recency beats the sticky verified flag when the page shows no account", async (t) => {
  const { window } = env(t, `<form>
    <input type="password" name="password" value="">
  </form>`, "https://example.com/login", [
    { id: "old", title: "Example", username: "old@example.com", password: "p1",
      urls: ["example.com"], verified: true, last_filled: 1600000000 },
    { id: "fresh", title: "Example", username: "fresh@example.com", password: "p2",
      urls: ["example.com"], verified: false, last_filled: Math.floor(Date.now() / 1000) },
  ]);
  const pw = window.document.querySelector('input[type="password"]');
  pw.dispatchEvent(new window.Event("focusin", { bubbles: true }));
  await flush(80);
  const rows = [...window.document.querySelectorAll("button[data-pv-index]")];
  assert.ok(rows.length >= 2, "both accounts must stay listed");
  assert.match(rows[0].textContent, /fresh@example\.com/,
    "the most recently filled account wins over a stale verified one");
  assert.match(rows[1].textContent, /old@example\.com/);
});

test("page hint ranks the displayed account first (Google-style password step)", async (t) => {
  const { window } = env(t, `<div data-identifier="right@example.com"></div>
  <form>
    <input type="password" name="password" value="">
  </form>`, "https://example.com/login", [
    { id: "wrong", title: "Example", username: "wrong@example.com", password: "p1",
      urls: ["example.com"], verified: true, last_filled: Math.floor(Date.now() / 1000) },
    { id: "right", title: "Example", username: "right@example.com", password: "p2",
      urls: ["example.com"], verified: false, last_filled: 0 },
  ]);
  const pw = window.document.querySelector('input[type="password"]');
  pw.dispatchEvent(new window.Event("focusin", { bubbles: true }));
  await flush(80);
  const rows = [...window.document.querySelectorAll("button[data-pv-index]")];
  assert.ok(rows.length >= 2, "hint must order rows, never drop them");
  assert.match(rows[0].textContent, /right@example\.com/,
    "the account the page displays must be first");
});

test("save prompt keeps a pending capture for the next page", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw123">
  </form>`, "https://example.com/login");
  submit(window, window.document.querySelector("form"));
  await flush();
  const pending = store.session["pvSavePending:example.com"];
  assert.ok(pending, "pending capture must be stored in session memory");
  assert.equal(pending.username, "alice");
  assert.equal(pending.password, "pw123");
});

test("pending capture re-opens the save prompt after a reload", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="password" name="password" value="">
  </form>`, "https://example.com/home");
  // Simulate the POST landing on a new document: the previous document's
  // capture is still in session storage.
  store.session["pvSavePending:example.com"] = {
    username: "alice", password: "pw123", at: Date.now(), shows: 1,
  };
  await flush(1500);
  assert.ok(saver(window), "the prompt must come back on the next page");
});

test("Not Now clears the pending capture (no prompt on the next page)", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="password" name="password" value="">
  </form>`, "https://example.com/home");
  store.session["pvSavePending:example.com"] = {
    username: "alice", password: "pw123", at: Date.now(), shows: 1,
  };
  await flush(1500);
  const notNow = saverButton(window, /Not Now/);
  assert.ok(notNow, "restored prompt must offer Not Now");
  notNow.click();
  await flush(50);
  assert.equal(store.session["pvSavePending:example.com"], undefined,
    "explicit dismiss must clear the pending capture");
});

test("Continue as: one matching account on a password-only step fills in one click", async (t) => {
  const { window } = env(t, `<div data-identifier="alice@example.com"></div>
    <form><input type="password" name="password" value=""></form>`,
    "https://example.com/signin", [
      { id: "c1", title: "Example", username: "alice@example.com", password: "pw1", urls: ["example.com"] },
      { id: "c2", title: "Example", username: "bob@example.com", password: "pw2", urls: ["example.com"] },
    ]);
  await flush(600);
  const el = window.document.getElementById("__pv_continue");
  assert.ok(el, "the continue-as chip must appear");
  assert.match(el.textContent, /alice@example\.com/);
  const fill = [...el.querySelectorAll("button")].find((b) => /Fill/i.test(b.textContent));
  fill.click();
  await flush(60);
  assert.equal(window.document.querySelector('input[name="password"]').value, "pw1");
});

test("Continue as: dismissed chip stays hidden for the site", async (t) => {
  const { window } = env(t, `<div data-identifier="alice@example.com"></div>
    <form><input type="password" name="password" value=""></form>`,
    "https://example.com/signin", [
      { id: "c1", title: "Example", username: "alice@example.com", password: "pw1", urls: ["example.com"] },
    ]);
  await flush(600);
  const el = window.document.getElementById("__pv_continue");
  assert.ok(el, "chip appears first");
  el.querySelector(".x").click();
  await flush(400);
  assert.equal(window.document.getElementById("__pv_continue"), null);
});

test("Continue as: never on a page that already has a username field", async (t) => {
  const { window } = env(t, `<div data-identifier="alice@example.com"></div>
    <form>
      <input type="email" name="email" autocomplete="username" value="alice@example.com">
      <input type="password" name="password" value="">
    </form>`,
    "https://example.com/signin", [
      { id: "c1", title: "Example", username: "alice@example.com", password: "pw1", urls: ["example.com"] },
    ]);
  await flush(600);
  assert.equal(window.document.getElementById("__pv_continue"), null,
    "the normal dropdown covers user+pass forms");
});

test("save prompt sends the folder and can be dismissed with x", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw123">
  </form>`, "https://example.com/login");
  submit(window, window.document.querySelector("form"));
  await flush();
  const root = saverRoot(window);
  const sel = root.querySelector("select");
  assert.ok(sel, "folder picker must render");
  const saveBtn = [...root.querySelectorAll("button")].find((b) => /^Save$/.test(b.textContent.trim()));
  assert.ok(saveBtn, "save button present");
  saveBtn.click();
  await flush(80);
  assert.ok(store.saves.length, "save message sent");
  assert.equal(store.saves[0].folder, "General");

  // A second submit shows the prompt again; the header x must clear the
  // pending capture without saving.
  submit(window, window.document.querySelector("form"));
  await flush(120);
  const box2 = saver(window);
  assert.ok(box2, "prompt re-opened");
  const x = saverRoot(window).querySelector('button[aria-label="Dismiss save prompt"]');
  assert.ok(x, "close button present");
  x.click();
  await flush(50);
  assert.equal(store.session["pvSavePending:example.com"], undefined);
});

test("save prompt lets the user edit the title and URL", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw123">
  </form>`, "https://example.com/login");
  submit(window, window.document.querySelector("form"));
  await flush();
  const root = saverRoot(window);
  const ins = [...root.querySelectorAll("input")];
  assert.ok(ins.length >= 4, "title/username/password/url fields");
  ins[0].value = "My Example";
  ins[3].value = "https://example.com/account";
  const saveBtn = [...root.querySelectorAll("button")].find((b) => /^Save$/.test(b.textContent.trim()));
  saveBtn.click();
  await flush(80);
  assert.equal(store.saves[0].title, "My Example");
  assert.equal(store.saves[0].url, "https://example.com/account");
});

test("identity fill covers company, city, state, zip and country", async (t) => {
  const { window } = env(t, `<form>
    <input autocomplete="name" name="name">
    <input autocomplete="organization" name="company">
    <input autocomplete="email" name="email">
    <input autocomplete="tel" name="phone">
    <input autocomplete="street-address" name="street">
    <input autocomplete="address-level2" name="city">
    <input autocomplete="address-level1" name="state">
    <input autocomplete="postal-code" name="zip">
    <select autocomplete="country-name" name="country">
      <option>United States</option><option>United Kingdom</option>
    </select>
  </form>`, "https://shop.example/checkout", [], [], [
    { id: "i1", title: "Home", full_name: "Ada Lovelace", email: "ada@example.com",
      phone: "123", address: "1 Analytical Way", company: "Analytical Engines",
      city: "London", state: "Greater London", zip: "N1", country: "United Kingdom" },
  ]);
  const street = window.document.querySelector('input[name="street"]');
  street.dispatchEvent(new window.Event("focusin", { bubbles: true }));
  await flush(80);
  const row = window.document.querySelector("button[data-pv-index]");
  assert.ok(row, "the identity row must reach the dropdown");
  row.dispatchEvent(new window.MouseEvent("mousedown", { bubbles: true, cancelable: true }));
  await flush(60);
  const val = (n) => window.document.querySelector(`[name="${n}"]`).value;
  assert.equal(val("company"), "Analytical Engines");
  assert.equal(val("city"), "London");
  assert.equal(val("state"), "Greater London");
  assert.equal(val("zip"), "N1");
  assert.equal(val("country"), "United Kingdom", "country select matched by label");
  assert.equal(val("name"), "Ada Lovelace");
});

test("identity capture keeps the structured address parts", async (t) => {
  const { window } = env(t, `<form>
    <input autocomplete="name" name="name" value="Ada Lovelace">
    <input autocomplete="organization" name="company" value="Analytical Engines">
    <input autocomplete="email" name="email" value="ada@example.com">
    <input autocomplete="street-address" name="street" value="1 Analytical Way">
    <input autocomplete="address-level2" name="city" value="London">
    <input autocomplete="postal-code" name="zip" value="N1">
    <select autocomplete="country-name" name="country">
      <option>United States</option><option selected>United Kingdom</option>
    </select>
  </form>`, "https://shop.example/checkout");
  submit(window, window.document.querySelector("form"));
  await flush(150);
  const saver = window.document.getElementById("__pv_saver");
  assert.ok(saver, "an identity save prompt must appear");
  assert.match(saverRoot(window).textContent, /Ada Lovelace|identity/i);
});

test("identity suggestions reach the dropdown (url-less rows survive)", async (t) => {
  const { window } = env(t, `<form>
    <input autocomplete="street-address" name="address1" value="">
  </form>`, "https://example.com/checkout", [], [], [
    { id: "exti1", title: "Home", full_name: "Ada Lovelace",
      email: "ada@example.com", phone: "+1 555 0100", address: "1 Analytical Way" },
  ]);
  const addr = window.document.querySelector('input[autocomplete="street-address"]');
  addr.dispatchEvent(new window.Event("focusin", { bubbles: true }));
  await flush(80);
  const rows = [...window.document.querySelectorAll("button[data-pv-index]")];
  assert.ok(rows.some((r) => /Ada Lovelace/.test(r.textContent)),
    "identity row must appear even though identities store no URL");
});

test("SPA identifier-only step carries the username (no submit event)", async (t) => {
  const { window, store } = env(t, `<form id="f">
    <input type="email" name="identifier" value="ghost@example.com">
  </form>`, "https://accounts.example.com/login");
  window.dispatchEvent(new window.MessageEvent("message", {
    data: { source: "__pv_hook", type: "PV_SPA_IDENT" }, source: window,
  }));
  await flush(80);
  const c = store.session.pvCaptureCarry;
  assert.ok(c, "carry must be written from a pure-XHR identifier step");
  assert.equal(c.username, "ghost@example.com");
  assert.equal(c.password, undefined, "password must never be carried (P1-b)");
});

test("hotkey fill ranks the carried account above a verified one", async (t) => {
  const { window } = env(t, `<form id="step1">
    <input type="email" name="email" value="alice@example.com">
  </form>
  <form id="step2"><input type="password" name="password" value=""></form>`,
  "https://example.com/login", [
    { id: "c2", username: "zed@example.com", password: "p2",
      urls: ["example.com"], verified: true, last_filled: 1700000000 },
    { id: "c1", username: "alice@example.com", password: "p1", urls: ["example.com"] },
  ]);
  submit(window, window.document.getElementById("step1"));
  await flush();
  await runtimeMessage(window, { type: "PV_HOTKEY_FILL" });
  await flush(60);
  assert.equal(window.document.querySelector('#step2 input[type="password"]').value, "p1",
    "hotkey must use the same ranking as the dropdown, not vault order");
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
  assert.match(saverRoot(window).textContent, /Save this card/i);
  const save = saverButton(window, /Save/);
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
  saverButton(window, /Save/).click();
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
  saverButton(window, /Save/).click();
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

test("newsletter / contact email boxes never get a shield, even on a matched site", async (t) => {
  const { window } = env(t, `<div class="footer">
    <input type="email" name="newsletter" placeholder="Your email">
    <input type="email" name="email" autocomplete="email" placeholder="Email address">
    <input type="text" name="contact" placeholder="Contact">
  </div>`,
    "https://example.com/",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush(120);
  const badged = (n) =>
    !!window.document.querySelector(`input[name="${n}"]`).dataset.pvBadged;
  assert.equal(badged("newsletter"), false);
  assert.equal(badged("email"), false,
    "autocomplete=email alone is not proof of a login form");
  assert.equal(badged("contact"), false);
});

test("identity fields (tel/address) are never login usernames", async (t) => {
  const { window } = env(t, `<form>
    <input type="tel" name="phone" autocomplete="tel">
    <input type="text" name="street" autocomplete="street-address">
  </form>`,
    "https://example.com/signin",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush(120);
  const badged = (n) =>
    !!window.document.querySelector(`input[name="${n}"]`).dataset.pvBadged;
  assert.equal(badged("phone"), false);
  assert.equal(badged("street"), false);
});

test("explicit autocomplete=username still earns the shield on a challenge URL", async (t) => {
  const { window } = env(t, `<form>
    <input type="email" name="identifier" autocomplete="username">
  </form>`,
    "https://accounts.google.com/v3/signin/challenge/pwd",
    [{ id: "e1", username: "a", password: "p", urls: ["google.com"] }]);
  await flush(120);
  assert.ok(window.document.querySelector('input[name="identifier"]').dataset.pvBadged,
    "developer-declared username fields must stay clickable");
});

test("a newsletter heading beats the URL signal", async (t) => {
  const { window } = env(t, `<section>
    <h2>Subscribe to our newsletter</h2>
    <form><input type="email" name="email" placeholder="Email address"></form>
  </section>`,
    "https://example.com/account",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush(120);
  assert.equal(window.document.querySelector('input[name="email"]').dataset.pvBadged, undefined,
    "a newsletter heading must veto the login badge");
});

test("a sign-in heading qualifies a lone email box without an auth URL", async (t) => {
  const { window } = env(t, `<section>
    <h1>Sign in to Example</h1>
    <form><input type="email" name="email" placeholder="Email address"></form>
  </section>`,
    "https://example.com/session",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush(120);
  assert.ok(window.document.querySelector('input[name="email"]').dataset.pvBadged,
    "the closest heading is a login signal");
});

test("signup fields are not login usernames", async (t) => {
  const { window } = env(t, `<h1>Create your account</h1>
  <form action="/register">
    <input type="email" name="email" autocomplete="username">
    <input type="password" name="password" autocomplete="new-password">
  </form>`,
    "https://example.com/register",
    [{ id: "e1", username: "a", password: "p", urls: ["example.com"] }]);
  await flush(120);
  assert.equal(window.document.querySelector('input[name="email"]').dataset.pvBadged, undefined,
    "autocomplete=username loses when the page is creating a credential");
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
  saverButton(window, /Save/).click();
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
  saverButton(window, /Save/).click();
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

test("E6/A12: every scan observer is debounced (document + open shadow roots)", () => {
  const src = readFileSync(new URL("../../browser_extension/content.js", import.meta.url), "utf8");
  // One document observer, plus one per discovered open shadow root — all must
  // call the SAME debounced scheduler (never scan()/scanForms() directly).
  assert.ok((src.match(/new MutationObserver\(pvScheduleScan\)/g) || []).length >= 1);
  assert.match(src, /new MutationObserver\(pvScheduleScan\)\.observe\(document\.documentElement/);
  assert.match(src, /const observeDeep = \(\) => \{[\s\S]{0,700}new MutationObserver\(pvScheduleScan\)\.observe\(root/);
  assert.ok(!/new MutationObserver\(scan\)/.test(src), "no undebounced scan observer");
  assert.ok(!/new MutationObserver\(scanForms\)/.test(src), "no undebounced scanForms observer");
  assert.match(src, /pvScanTimer = setTimeout\(\(\) => \{[\s\S]{0,120}scan\(\);[\s\S]{0,80}scanForms\(\);[\s\S]{0,40}\}, 120\)/);
});

// ---- 2FA picker qualification (Bitwarden parity) -------------------------
// The picker must be evidence-driven, never inferred. Regression: on GitHub's
// "New repository" page the surrounding copy contains the word "code", and the
// old classifier read that as an OTP ceremony and covered the page with the
// TOTP account menu.
const TOTP_TWO = [
  { id: "t1", account: "zjhasan13", issuer: "GitHub", code: "379321", has_totp: true, totp: "1" },
  { id: "t2", account: "zjhasan33", issuer: "GitHub", code: "163997", has_totp: true, totp: "1" },
];
const REPO_FORM = `<form action="/repositories" method="post">
  <label for="repository_name">Repository name</label>
  <input type="text" id="repository_name" name="repository[name]" autocomplete="off" maxlength="100">
  <p>Choose which files not to track. Code owners can be added later.</p>
  <label for="repository_description">Description</label>
  <input type="text" id="repository_description" name="repository[description]" autocomplete="off">
  <button type="submit">Create repository</button>
</form>`;

test("2FA picker stays closed on a generic text field (GitHub new-repo copy mentions 'code')", async (t) => {
  const { window } = env(t, REPO_FORM, "https://github.com/new", [], [], [], TOTP_TWO);
  await flush(120); // boot sweep + mutation observer
  assert.equal(window.document.getElementById("__pv_otp_picker"), null);
});

test("2FA picker stays closed when a generic text field is focused", async (t) => {
  const { window } = env(t, REPO_FORM, "https://github.com/new", [], [], [], TOTP_TWO);
  const box = window.document.getElementById("repository_name");
  box.focus();
  await flush(150);
  assert.equal(window.document.activeElement, box);
  assert.equal(window.document.getElementById("__pv_otp_picker"), null);
});

test("passive sweep never opens the picker without focus or a pinned account", async (t) => {
  const { window } = env(t, `<form>
    <p>Enter the 6-digit code from your authenticator app.</p>
    <input type="text" id="otp" name="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6">
  </form>`, "https://github.com/sessions/two-factor", [], [], [], TOTP_TWO);
  await flush(150);
  assert.equal(window.document.getElementById("__pv_otp_picker"), null);
});

test("focused real 2FA box still opens the account picker (control)", async (t) => {
  const { window } = env(t, `<form>
    <p>Enter the 6-digit code from your authenticator app.</p>
    <input type="text" id="otp" name="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6">
  </form>`, "https://github.com/sessions/two-factor", [], [], [], TOTP_TWO);
  window.document.getElementById("otp").focus();
  await flush(150);
  assert.ok(window.document.getElementById("__pv_otp_picker"), "explicit focus must still open the picker");
});

// ---- "Never save for this site" (content side) ---------------------------
// Bitwarden parity for the save prompt: the middle option is "Not Now", the
// permanent opt-out must exist too. Choice is stored per registrable domain,
// so a decision on login.example.com also silences accounts.example.com.

test("save banner offers Never and stores the registrable domain", async (t) => {
  const { window, store } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw123">
  </form>`, "https://login.example.com/signin");
  await flush(); // settings boot get() settles before the first submit
  submit(window, window.document.querySelector("form"));
  await flush();
  const banner = saver(window);
  assert.ok(banner, "banner first");
  const never = saverButton(window, /Never/);
  assert.ok(never, "Never button must exist");
  never.click();
  await flush();
  assert.deepEqual(Array.from(store.local.never_save_domains), ["example.com"]);
  assert.equal(saver(window), null, "banner dismissed");
});

test("after Never, a later submit on the same site stays silent", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw123">
  </form>`, "https://example.com/login");
  await flush();
  submit(window, window.document.querySelector("form"));
  await flush();
  const banner = saver(window);
  saverButton(window, /Never/).click();
  await flush();
  // Second submit (e.g. a failed login retried) must not re-open the prompt.
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.equal(saver(window), null);
});

test("a seeded never_save_domains entry suppresses the prompt on load", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw123">
  </form>`, "https://example.com/login", [], [], [], [], { never_save_domains: ["example.com"] });
  await flush();
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.equal(saver(window), null);
});

test("Never also silences the password-update prompt for that site", async (t) => {
  const { window } = env(t, `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="newpw">
  </form>`, "https://example.com/login",
    [{ id: "e1", username: "alice", password: "oldpw", urls: ["example.com"] }],
    [], [], [], { never_save_domains: ["example.com"] });
  await flush();
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.equal(saver(window), null);
});
// ---- A9: edit before save ------------------------------------------------
// The prompt must show the submitted pair and let it be corrected before a
// single byte reaches the vault. The fields live in a closed shadow root, so a
// page script cannot read a corrected secret out of the page tree.

const loginForm = (u, p) => `<form>
    <input type="text" name="username" value="${u}">
    <input type="password" name="password" value="${p}">
  </form>`;

test("A9: save prompt pre-fills editable fields in a closed shadow root", async (t) => {
  const { window } = env(t, loginForm("alice", "pw123"));
  submit(window, window.document.querySelector("form"));
  await flush();
  const host = saver(window);
  assert.ok(host, "save prompt first");
  assert.equal(host.shadowRoot, null, "root must be closed to page scripts");
  assert.equal(host.querySelector("input"), null, "no input leaks into light DOM");
  const root = saverRoot(window);
  const user = root.querySelector('[data-pv-field="username"]');
  const pass = root.querySelector('input[type="password"]');
  assert.equal(user.value, "alice");
  assert.equal(pass.value, "pw123");
  assert.equal(pass.autocomplete, "off");
  assert.equal(pass.spellcheck, false);
});

test("A9: corrected fields are what gets saved", async (t) => {
  const { window, store } = env(t, loginForm("alice", "wrongpw"));
  submit(window, window.document.querySelector("form"));
  await flush();
  const root = saverRoot(window);
  root.querySelector('[data-pv-field="username"]').value = "alice@corp.example";
  root.querySelector('input[type="password"]').value = "RightPass!1";
  saverButton(window, /Save/).click();
  await flush();
  assert.equal(store.saves.length, 1);
  assert.equal(store.saves[0].username, "alice@corp.example");
  assert.equal(store.saves[0].password, "RightPass!1");
  assert.equal(saver(window), null, "prompt closes after a successful save");
});

test("A9: blank fields block the save instead of writing garbage", async (t) => {
  const { window, store } = env(t, loginForm("alice", "pw123"));
  submit(window, window.document.querySelector("form"));
  await flush();
  const root = saverRoot(window);
  root.querySelector('[data-pv-field="username"]').value = "   ";
  root.querySelector('input[type="password"]').value = "";
  saverButton(window, /Save/).click();
  await flush();
  assert.equal(store.saves.length, 0, "no host call for an empty pair");
  assert.ok(saver(window), "prompt stays open so the user can fix it");
  assert.match(root.textContent, /username/i);
});

test("A9: editing back to the stored password stops the update", async (t) => {
  const { window, store } = env(t, loginForm("bob", "newpw"), "https://example.com/login",
    [{ id: "e1", username: "bob", password: "oldpw", urls: ["example.com"] }]);
  await flush(); // boot warm fills the credential cache
  submit(window, window.document.querySelector("form"));
  await flush();
  assert.ok(saver(window), "a changed password opens the update prompt");
  const root = saverRoot(window);
  assert.equal(root.querySelector('input[type="password"]').value, "newpw");
  root.querySelector('input[type="password"]').value = "oldpw";
  saverButton(window, /Update/).click();
  await flush();
  assert.equal(store.saves.length, 0, "known pair must not hit the host");
  assert.ok(saver(window), "prompt stays open");
  assert.match(root.textContent, /already saved/i);
});

test("A9: update prompt saves corrected username and password", async (t) => {
  const { window, store } = env(t, loginForm("bob", "newpw"), "https://example.com/login",
    [{ id: "e1", username: "bob", password: "oldpw", urls: ["example.com"] }]);
  await flush();
  submit(window, window.document.querySelector("form"));
  await flush();
  const root = saverRoot(window);
  root.querySelector('[data-pv-field="username"]').value = "bob@example.com";
  root.querySelector('input[type="password"]').value = "EvenNewer1";
  saverButton(window, /Update/).click();
  await flush();
  assert.equal(store.saves.length, 1);
  assert.equal(store.saves[0].username, "bob@example.com");
  assert.equal(store.saves[0].password, "EvenNewer1");
});

test("A9: Escape inside a field keeps the edit, Escape elsewhere dismisses", async (t) => {
  const { window } = env(t, loginForm("alice", "pw123"));
  submit(window, window.document.querySelector("form"));
  await flush();
  const root = saverRoot(window);
  const pass = root.querySelector('input[type="password"]');
  pass.focus();
  pass.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true, composed: true }));
  assert.ok(saver(window), "in-field Escape must not discard the edit");
  const save = saverButton(window, /Save/);
  save.focus();
  save.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true, composed: true }));
  assert.equal(saver(window), null, "Escape outside a field still closes the prompt");
});

// ---- A4: hash-guarded clipboard clear ----

test("A4: content arms the clipboard clear with a hash and verifies it before blanking", () => {
  const C = readFileSync(
    new URL("../../browser_extension/content.js", import.meta.url), "utf8");
  const arm = C.match(/function copyWithAutoclear\(text, ms = 30000\) \{([\s\S]*?)\n  \}/);
  assert.ok(arm, "copyWithAutoclear present");
  assert.match(arm[1], /type: "PV_CLIP_ARM", hash/);
  const clear = C.match(/if \(msg\.type === "PV_CLIP_CLEAR"\) \{([\s\S]*?)\n      \}/);
  assert.ok(clear, "PV_CLIP_CLEAR handler present");
  assert.match(clear[1], /readText\(\)/);
  assert.ok(clear[1].indexOf("readText") < clear[1].indexOf('writeText("")'),
    "read + hash compare must precede the blank");
  assert.match(clear[1], /sha256Hex\(cur\) !== want/);
});

test("A12: a shadow-DOM login gets a badge and offers save on submit", async (t) => {
  const { window } = env(t, `<div id="host"></div>`);
  const host = window.document.getElementById("host");
  const root = host.attachShadow({ mode: "open" });
  root.innerHTML = `<form>
    <input type="text" name="username" value="alice">
    <input type="password" name="password" value="pw123">
  </form>`;
  // Boot scan + the 120 ms debounced observer must discover the new root.
  await flush(320);
  const badges = [...window.document.querySelectorAll('button[data-pv-kind="shield"]')];
  assert.ok(badges.length >= 1, "shadow field gets a badge");
  submit(window, root.querySelector("form"));
  await flush();
  assert.ok(saver(window), "shadow form submit must offer save");
});

test("A12: nested open shadow roots are traversed", async (t) => {
  const { window } = env(t, `<div id="outer"></div>`);
  const outer = window.document.getElementById("outer").attachShadow({ mode: "open" });
  outer.innerHTML = `<div id="inner"></div>`;
  const inner = outer.getElementById("inner").attachShadow({ mode: "open" });
  inner.innerHTML = `<form>
    <input type="text" name="username" value="deep">
    <input type="password" name="password" value="pw">
  </form>`;
  await flush(320);
  const badges = [...window.document.querySelectorAll('button[data-pv-kind="shield"]')];
  assert.ok(badges.length >= 1, "nested shadow input gets a badge");
  submit(window, inner.querySelector("form"));
  await flush();
  assert.ok(saver(window), "nested shadow submit must offer save");
});

test("A12: the scanner stays out of closed shadow roots", async (t) => {
  const { window } = env(t, `<div id="closed"></div>`);
  const host = window.document.getElementById("closed");
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `<input type="password" name="password" value="hidden">`;
  await flush(320);
  assert.equal(
    window.document.querySelectorAll('button[data-pv-kind="shield"]').length,
    0,
    "closed roots are not traversed",
  );
});

test("E5: never-save sites have a Settings list with Remove", () => {
  const html = readFileSync(new URL("../../browser_extension/popup.html", import.meta.url), "utf8");
  const js = readFileSync(new URL("../../browser_extension/popup.js", import.meta.url), "utf8");
  assert.match(html, /id="neverSaveList"/);
  assert.match(js, /function renderNeverSave\(/);
  assert.match(js, /never_save_domains: list/);
  assert.match(js, /btn\.dataset\.domain = d/);
});

test("A4: offscreen never blanks without a matching hash", () => {
  const O = readFileSync(
    new URL("../../browser_extension/offscreen.js", import.meta.url), "utf8");
  assert.match(O, /readText\(\)/);
  assert.ok(O.indexOf("readText()") < O.indexOf('writeText("")'),
    "read + hash compare must precede the blank");
  assert.match(O, /sha256Hex\(current\) !== want/);
  assert.match(O, /0-9a-f\]\{64\}/);
});
