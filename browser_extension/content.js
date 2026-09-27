// PhantomVault Smart Autofill Engine (content script).
// Bitwarden-surpassing automation: zero-click load fill, hands-free TOTP,
// inline login/card/identity suggestions, base-domain matching, plus
// next-gen guards (anti-phishing, clickjacking, blocked domains).
(() => {
  "use strict";
  if (window.__pvEngine) return;
  window.__pvEngine = true;

  const DEFAULTS = {
    show_suggestions: true,
    suggest_cards: true,
    suggest_identities: true,
    autofill_on_load: true,
    auto_inject_totp: true,
    show_context_menu: true,
    match_mode: "base", // base | host | exact
    auto_submit: false,
    blocked_domains: [],
  };
  let settings = { ...DEFAULTS };
  chrome.storage.local.get(DEFAULTS).then((s) => { settings = { ...DEFAULTS, ...s }; });
  chrome.storage.onChanged.addListener((ch, area) => {
    if (area !== "local") return;
    for (const k of Object.keys(DEFAULTS)) {
      if (ch[k]) settings[k] = ch[k].newValue;
    }
  });

  // ---------- domain utils ----------
  function registrable(host) {
    const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    return parts.slice(-2).join("."); // pragmatic; multi-label PSL TLDs are edge cases
  }
  function pageBase() { return registrable(location.hostname); }
  function isBlocked() {
    const base = pageBase();
    return (settings.blocked_domains || []).some((d) => {
      const t = String(d || "").trim().toLowerCase();
      return t && (base === t || base.endsWith("." + t));
    });
  }
  // Anti-phishing: punycode lookalikes never get credentials.
  function phishingRefuse() {
    if (location.hostname.toLowerCase().includes("xn--")) {
      toast("⚠️ Phishing Hazard: punycode domain, autofill refused!");
      return true;
    }
    return false;
  }
  // Entry allow-list by match mode. Entries WITHOUT stored urls pass through
  // (legacy titles) — only entries WITH urls are strictly verified.
  function entryAllowed(entry) {
    const urls = entry.urls || [];
    if (!urls.length) return true;
    const pageHost = location.hostname.toLowerCase();
    const pageHref = location.href.split("#")[0].replace(/\/$/, "");
    for (const raw of urls) {
      let u;
      try { u = new URL(raw.includes("://") ? raw : "https://" + raw); }
      catch (_) { continue; }
      const mode = settings.match_mode || "base";
      if (mode === "exact") {
        if (u.href.split("#")[0].replace(/\/$/, "") === pageHref) return true;
      } else if (mode === "host") {
        if (u.hostname.toLowerCase() === pageHost) return true;
      } else {
        if (registrable(u.hostname) === pageBase()) return true;
      }
    }
    return false;
  }
  function filterEntries(entries) {
    const ok = [];
    let refused = false;
    for (const e of entries || []) {
      if (entryAllowed(e)) ok.push(e);
      else refused = true;
    }
    if (refused && !ok.length) {
      toast("⚠️ Phishing Hazard: Domain mismatch, autofill refused!");
    }
    return ok;
  }

  // ---------- dom utils ----------
  function isVisible(el) {
    if (!el || !el.isConnected) return false;
    if (el.offsetWidth <= 0 || el.offsetHeight <= 0) return false; // honeypot / 1px guard
    const cs = getComputedStyle(el);
    return cs.visibility !== "hidden" && cs.display !== "none" && !el.disabled && !el.readOnly;
  }
  function setNativeValue(el, value) {
    const proto = el.tagName === "TEXTAREA"
      ? window.HTMLTextAreaElement.prototype
      : window.HTMLInputElement.prototype;
    try {
      Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value);
    } catch (_) { el.value = value; }
    for (const t of ["input", "change"]) {
      el.dispatchEvent(new Event(t, { bubbles: true }));
    }
    el.dispatchEvent(new FocusEvent("blur", { bubbles: true }));
  }
  function toast(msg) {
    let t = document.getElementById("__pv_toast");
    if (!t) {
      t = document.createElement("div");
      t.id = "__pv_toast";
      t.style.cssText = "position:fixed;top:14px;left:50%;transform:translateX(-50%);z-index:2147483647;" +
        "background:#3a1730;border:1px solid #fb7185;color:#fb7185;font:700 13px system-ui;" +
        "padding:10px 16px;border-radius:10px;box-shadow:0 8px 30px #000c;";
      document.documentElement.appendChild(t);
    }
    t.textContent = msg;
    t.style.display = "block";
    clearTimeout(t.__pvTimer);
    t.__pvTimer = setTimeout(() => { t.style.display = "none"; }, 4200);
  }
  function copyWithAutoclear(text, ms = 30000) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => {});
      }, ms);
    }).catch(() => {
      // http://, file://, or denied permission: say so, don't fake success.
      toast("⚠️ Copy blocked by the page — click 📋 again or copy manually.");
    });
  }

  function findFields() {
    const q = (s) => [...document.querySelectorAll(s)].filter(isVisible);
    const pass = q('input[type="password"]:not([autocomplete="new-password"])');
    const newPass = q('input[autocomplete="new-password"], input[type="password"][name*="new" i]');
    const users = q('input[type="text"][name*="user" i], input[type="text"][name*="login" i], ' +
      'input[type="email"], input[type="text"][autocomplete*="username" i], input[type="text"][id*="user" i]');
    const otp = q('input[autocomplete="one-time-code"], input[inputmode="numeric"], ' +
      'input[name*="otp" i], input[name*="2fa" i], input[name*="verif" i], input[name*="code" i][maxlength]');
    const cards = q('input[name*="cardnumber" i], input[autocomplete="cc-number"], input[data-stripe="number"]');
    const addr = q('input[autocomplete="street-address"], input[autocomplete="address-line1"], ' +
      'input[name*="address" i], input[autocomplete="tel"], input[name*="phone" i]');
    return { pass, newPass, users, otp, cards, addr };
  }
  function queryHost(type, q, ms = 10000) {
    // Dead-bridge hang guard: every round-trip races a timeout (popup and
    // background already do; content must not dangle promises forever).
    const req = chrome.runtime.sendMessage({ type, app: q }).then((res) => {
      if (!res || !res.ok) throw new Error((res && res.error) || "bridge failed");
      return filterEntries(res.entries);
    });
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("vault bridge timed out")), ms);
    });
    return Promise.race([req, timeout]).finally(() => clearTimeout(timer));
  }

  // ---------- fill primitives ----------
  // Tabnabbing guard: links that open new tabs must not keep an opener handle.
  function neutralizeOpener() {
    for (const a of document.querySelectorAll('a[target="_blank"]')) {
      const rel = (a.getAttribute("rel") || "").toLowerCase();
      if (!rel.includes("noopener")) a.setAttribute("rel", (rel + " noopener noreferrer").trim());
    }
  }
  // Sensitive-credential re-prompt: user-presence modal before injection.
  // (True Hello attestation happens in the desktop app; the host only hands
  // out reprompt-flagged secrets to an extension that confirmed presence.)
  function confirmSensitive(entry) {
    return new Promise((resolve) => {
      const ov = document.createElement("div");
      ov.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:#000a;" +
        "display:flex;align-items:center;justify-content:center;";
      const box = document.createElement("div");
      box.style.cssText = "background:#0d131f;border:1px solid #8b7cf6;border-radius:14px;" +
        "padding:20px 22px;max-width:320px;font:14px system-ui;color:#eef1ff;text-align:center;";
      const h = document.createElement("div");
      h.style.cssText = "font-weight:800;margin-bottom:8px;";
      h.textContent = "🔒 " + (entry.title || "Sensitive credential");
      const p = document.createElement("div");
      p.style.cssText = "color:#8e99c0;font-size:12px;margin-bottom:14px;";
      p.textContent = "This item needs verification before fill. Confirm presence to continue.";
      const row = document.createElement("div");
      row.style.cssText = "display:flex;gap:8px;";
      const ok = document.createElement("button");
      ok.textContent = "✅ Confirm & Fill";
      ok.style.cssText = "flex:1;background:#8b7cf6;color:#fff;border:0;border-radius:8px;padding:9px;font-weight:700;cursor:pointer;";
      const no = document.createElement("button");
      no.textContent = "Cancel";
      no.style.cssText = "flex:1;background:#1a2450;color:#fff;border:1px solid #26315c;border-radius:8px;padding:9px;cursor:pointer;";
      row.append(ok, no);
      box.append(h, p, row);
      ov.append(box);
      document.documentElement.append(ov);
      const done = (v) => { ov.remove(); resolve(v); };
      ok.addEventListener("click", () => done(true));
      no.addEventListener("click", () => done(false));
      ov.addEventListener("keydown", (e) => { if (e.key === "Escape") done(false); });
      ok.focus();
    });
  }
  function pingFilled(id) {
    if (!id) return;
    chrome.runtime.sendMessage({ type: "PV_FILLED", id }).catch(() => {});
  }
  function staleNudge(entry) {
    if (!entry || !entry.last_changed) return;
    const ageDays = (Date.now() / 1000 - entry.last_changed) / 86400;
    if (ageDays > 180) {
      toast("⚠️ Password is over 6 months old. Consider updating it.");
    }
  }
  async function fillLogin(entry, fields) {
    if (entry.reprompt) {
      const ok = await confirmSensitive(entry);
      if (!ok) return;
    }
    neutralizeOpener();
    const f = fields || findFields();
    if (f.users[0] && entry.username) setNativeValue(f.users[0], entry.username);
    if (f.pass[0] && entry.password) {
      setNativeValue(f.pass[0], entry.password);
      // Multi-step chaining: remember entry; password step may render later.
      try { sessionStorage.setItem("__pv_pending", JSON.stringify(entry)); } catch (_) {}
    }
    if (entry.totp) fillTotp(entry.totp, f);
    staleNudge(entry);
    pingFilled(entry.id);
    if (settings.auto_submit) {
      const form = (f.pass[0] || f.users[0] || document.activeElement || {}).form;
      if (form && form.requestSubmit) form.requestSubmit();
    }
  }
  function fillTotp(code, fields) {
    if (!code) return;
    const f = fields || findFields();
    if (f.otp[0]) {
      setNativeValue(f.otp[0], code.replace(/\s/g, ""));
      copyWithAutoclear(code); // fallback: paste-ready, auto-cleared in 30s
      if (settings.auto_submit) {
        const form = f.otp[0].form;
        if (form && form.requestSubmit) form.requestSubmit();
      }
    } else {
      copyWithAutoclear(code);
    }
  }
  function fillCard(entry) {
    const num = document.querySelector('input[autocomplete="cc-number"], input[name*="cardnumber" i]');
    const exp = document.querySelector('input[autocomplete="cc-exp"], input[name*="expir" i]');
    const cvc = document.querySelector('input[autocomplete="cc-csc"], input[name*="cvv" i], input[name*="cvc" i]');
    const holder = document.querySelector('input[autocomplete="cc-name"], input[name*="cardholder" i]');
    if (holder && entry.cardholder) setNativeValue(holder, entry.cardholder);
    if (num && entry.number) setNativeValue(num, entry.number);
    if (exp && (entry.exp_month || entry.exp_year)) {
      setNativeValue(exp, `${entry.exp_month || ""}/${entry.exp_year || ""}`);
    }
    if (cvc && entry.cvv) setNativeValue(cvc, entry.cvv);
    pingFilled(entry.id);
  }
  function fillIdentity(entry) {
    const map = [
      ['input[autocomplete="name"], input[name*="fullname" i], input[name*="full_name" i]', entry.full_name],
      ['input[autocomplete="email"], input[type="email"]', entry.email],
      ['input[autocomplete="tel"], input[name*="phone" i]', entry.phone],
      ['input[autocomplete="street-address"], input[name*="address" i]', entry.address],
    ];
    for (const [sel, val] of map) {
      if (!val) continue;
      const el = [...document.querySelectorAll(sel)].find(isVisible);
      if (el) setNativeValue(el, val);
    }
    pingFilled(entry.id);
  }
  function masked(num) {
    const d = String(num || "").replace(/\D/g, "");
    return d.length > 4 ? "•••• " + d.slice(-4) : "••••";
  }

  // ---------- inline suggestions dropdown ----------
  let dropEl = null;
  function closeDrop() {
    if (dropEl) { dropEl.remove(); dropEl = null; }
    document.removeEventListener("click", outsideDrop, true);
  }
  function outsideDrop(e) {
    if (dropEl && !dropEl.contains(e.target)) closeDrop();
  }
  function showDrop(anchor, rows) {
    closeDrop();
    if (!rows.length || !isVisible(anchor)) return;
    dropEl = document.createElement("div");
    dropEl.style.cssText = "position:absolute;z-index:2147483647;min-width:240px;max-width:320px;" +
      "background:#0d131f;border:1px solid #26315c;border-radius:10px;padding:6px;" +
      "box-shadow:0 12px 40px #000d;font:13px system-ui;color:#eef1ff;";
    for (const r of rows.slice(0, 6)) {
      const b = document.createElement("button");
      b.type = "button";
      b.style.cssText = "display:block;width:100%;text-align:left;background:transparent;border:0;" +
        "color:#eef1ff;padding:8px 10px;border-radius:8px;cursor:pointer;";
      b.innerHTML = "";
      const t = document.createElement("div");
      t.style.fontWeight = "700";
      t.textContent = r.title;
      const s = document.createElement("div");
      s.style.cssText = "color:#8e99c0;font-size:11px;";
      s.textContent = r.sub;
      b.append(t, s);
      b.addEventListener("mouseenter", () => { b.style.background = "#1a2333"; });
      b.addEventListener("mouseleave", () => { b.style.background = "transparent"; });
      b.addEventListener("mousedown", (e) => { e.preventDefault(); e.stopPropagation(); r.onPick(); closeDrop(); });
      dropEl.append(b);
    }
    document.documentElement.appendChild(dropEl);
    const rc = anchor.getBoundingClientRect();
    dropEl.style.left = (rc.left + window.scrollX) + "px";
    dropEl.style.top = (rc.bottom + window.scrollY + 4) + "px";
    document.addEventListener("click", outsideDrop, true);
  }
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrop(); }, true);

  async function suggestFor(anchor) {
    if (!settings.show_suggestions || isBlocked() || phishingRefuse()) return;
    if (!location.host) return;
    const f = findFields();
    // Explicit parens: card-field OR checkout-form context (was `a || b && c`
    // which misclassified address inputs on /checkout as card fields).
    const form = anchor.closest("form");
    const inCheckoutForm = !!form &&
      /check|pay|card/i.test(((form.id || "") + " " + location.pathname));
    const isCard = f.cards.includes(anchor) || inCheckoutForm;
    const isAddr = f.addr.includes(anchor);
    try {
      if (isCard && settings.suggest_cards) {
        const cards = await queryHost("PV_CARDS", pageBase());
        showDrop(anchor, cards.map((c) => ({
          title: "💳 " + (c.title || "Card"),
          sub: `${c.cardholder || ""} ${masked(c.number)}`.trim(),
          onPick: () => fillCard(c),
        })));
      } else if (isAddr && settings.suggest_identities) {
        const ids = await queryHost("PV_IDENTITIES", pageBase());
        showDrop(anchor, ids.map((i) => ({
          title: "🪪 " + (i.title || i.full_name || "Identity"),
          sub: [i.full_name, i.email].filter(Boolean).join(" • "),
          onPick: () => fillIdentity(i),
        })));
      } else {
        const logins = await queryHost("PV_QUERY", pageBase());
        showDrop(anchor, logins.map((e) => ({
          title: "🔑 " + (e.title || "(untitled)"),
          sub: e.username || "",
          onPick: () => fillLogin(e, f),
        })));
      }
    } catch (_) { /* bridge down: stay silent, popup explains */ }
  }
  document.addEventListener("focusin", (e) => {
    const el = e.target;
    if (el instanceof HTMLInputElement && isVisible(el)) suggestFor(el);
  });

  // ---------- badge (legacy quick-fill) + generator dice ----------
  function placeBadge(field) {
    if (field.dataset.pvBadged) return;
    field.dataset.pvBadged = "1";
    const b = document.createElement("button");
    b.type = "button";
    b.title = "Fill with PhantomVault";
    b.textContent = "🛡️";
    b.style.cssText = "position:absolute;z-index:2147483647;width:26px;height:26px;margin-left:-30px;" +
      "border:1px solid #8b7cf6;border-radius:8px;background:#0d131f;cursor:pointer;font-size:14px;";
    b.addEventListener("click", async (ev) => {
      ev.preventDefault(); ev.stopPropagation();
      await hotkeyFill();
    });
    field.insertAdjacentElement("afterend", b);
  }
  function genPassword(len = 20) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_+=";
    const buf = new Uint32Array(len);
    crypto.getRandomValues(buf);
    return [...buf].map((x) => chars[x % chars.length]).join("");
  }
  function placeDice(field) {
    if (field.dataset.pvDice) return;
    field.dataset.pvDice = "1";
    const b = document.createElement("button");
    b.type = "button";
    b.title = "Generate strong password (PhantomVault)";
    b.textContent = "🎲";
    b.style.cssText = "position:absolute;z-index:2147483647;width:26px;height:26px;margin-left:-30px;" +
      "border:1px solid #10b981;border-radius:8px;background:#0d131f;cursor:pointer;font-size:14px;";
    b.addEventListener("click", (ev) => {
      ev.preventDefault(); ev.stopPropagation();
      const pw = genPassword();
      setNativeValue(field, pw);
      const form = field.form;
      if (form) {
        const confirm = [...form.querySelectorAll('input[type="password"]')].find((x) => x !== field && isVisible(x));
        if (confirm) setNativeValue(confirm, pw);
      }
      copyWithAutoclear(pw);
      toast("🎲 Strong password filled + copied — save it in PhantomVault!");
    });
    field.insertAdjacentElement("afterend", b);
  }

  // ---------- zero-click load + multi-step chaining ----------
  async function autofillOnLoad() {
    if (!settings.autofill_on_load || isBlocked() || phishingRefuse()) return;
    if (!location.host) return;
    try {
      const logins = await queryHost("PV_QUERY", pageBase());
      if (logins.length !== 1) {
        // Multi-step: a pending entry from step 1 + password field now visible?
        await chainPendingStep();
        return;
      }
      const f = findFields();
      if ((f.users[0] || f.pass[0]) && (logins[0].username || logins[0].password)) {
        fillLogin(logins[0], f);
      }
    } catch (_) {}
  }
  async function chainPendingStep() {
    let pending;
    try { pending = JSON.parse(sessionStorage.getItem("__pv_pending") || "null"); }
    catch (_) { return; }
    if (!pending) return;
    const f = findFields();
    if (f.pass[0] && pending.password) {
      setNativeValue(f.pass[0], pending.password);
      if (settings.auto_inject_totp && pending.totp) fillTotp(pending.totp, f);
      try { sessionStorage.removeItem("__pv_pending"); } catch (_) {}
    }
  }
  // OTP fields that render late (SPA step 3): inject live TOTP on sight.
  const otpObserver = new MutationObserver(() => {
    if (!settings.auto_inject_totp || isBlocked()) return;
    const f = findFields();
    if (!f.otp.length || f.otp[0].dataset.pvOtpFilled) return;
    let pending = null;
    try { pending = JSON.parse(sessionStorage.getItem("__pv_pending") || "null"); } catch (_) {}
    if (pending && pending.totp) {
      f.otp[0].dataset.pvOtpFilled = "1";
      fillTotp(pending.totp, f);
      try { sessionStorage.removeItem("__pv_pending"); } catch (_) {}
    }
  });

  async function hotkeyFill() {
    if (isBlocked() || phishingRefuse() || !location.host) return;
    const f = findFields();
    try {
      if (f.cards[0] && settings.suggest_cards) {
        const cards = await queryHost("PV_CARDS", pageBase());
        if (cards[0]) { fillCard(cards[0]); return; }
      }
      const logins = await queryHost("PV_QUERY", pageBase());
      if (logins[0]) fillLogin(logins[0], f);
      else toast("🛡️ No matching credential for this site.");
    } catch (e) {
      toast("⚠️ " + (e.message || "bridge failed"));
    }
  }

  function scan() {
    if (isBlocked()) return;
    const { pass, newPass } = findFields();
    pass.forEach(placeBadge);
    newPass.forEach(placeDice);
  }

  // ---------- auto-save: offer to store freshly submitted credentials ----------
  function saverToast(username, password) {
    if (document.getElementById("__pv_saver")) return;
    const box = document.createElement("div");
    box.id = "__pv_saver";
    box.style.cssText = "position:fixed;bottom:16px;right:16px;z-index:2147483647;" +
      "background:#0d131f;border:1px solid #8b7cf6;border-radius:12px;padding:12px 14px;" +
      "font:13px system-ui;color:#eef1ff;box-shadow:0 12px 40px #000d;max-width:300px;";
    const t = document.createElement("div");
    t.style.cssText = "font-weight:700;margin-bottom:8px;";
    t.textContent = "🛡️ Save to PhantomVault?";
    const sub = document.createElement("div");
    sub.style.cssText = "color:#8e99c0;font-size:11px;margin-bottom:10px;";
    sub.textContent = `New login for ${pageBase()} — store it encrypted.`;
    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:8px;";
    const save = document.createElement("button");
    save.textContent = "💾 Save";
    save.style.cssText = "flex:1;background:#8b7cf6;color:#fff;border:0;border-radius:8px;padding:8px;font-weight:700;cursor:pointer;";
    const no = document.createElement("button");
    no.textContent = "✕ Not Now";
    no.style.cssText = "flex:1;background:#1a2450;color:#fff;border:1px solid #26315c;border-radius:8px;padding:8px;cursor:pointer;";
    row.append(save, no);
    box.append(t, sub, row);
    document.documentElement.append(box);
    const dismiss = () => box.remove();
    no.addEventListener("click", dismiss);
    setTimeout(dismiss, 30000);
    save.addEventListener("click", async () => {
      save.textContent = "⏳ Saving…";
      try {
        const res = await chrome.runtime.sendMessage({
          type: "PV_SAVE_LOGIN",
          username, password,
          url: location.href,
          title: document.title ? document.title.split(/[-|–]/)[0].trim().slice(0, 60) : pageBase(),
        });
        if (res && res.ok) {
          toast(res.updated ? "✅ Login updated in PhantomVault." : "✅ Login saved to PhantomVault.");
          dismiss();
        } else {
          save.textContent = "⚠️ " + ((res && res.error) || "failed");
        }
      } catch (_) {
        save.textContent = "⚠️ Bridge unreachable";
      }
    });
  }
  async function watchSubmit(form) {
    if (!form || form.dataset.pvWatched) return;
    form.dataset.pvWatched = "1";
    form.addEventListener("submit", async () => {
      try {
        if (isBlocked() || phishingRefuse() || !location.host) return;
        const user = form.querySelector('input[type="text"], input[type="email"]');
        const pw = form.querySelector('input[type="password"]:not([autocomplete="new-password"])');
        const username = (user && user.value || "").trim();
        const password = (pw && pw.value || "");
        if (!username || !password) return;
        const existing = await queryHost("PV_QUERY", pageBase());
        const known = existing.some((e) =>
          (e.username || "").toLowerCase() === username.toLowerCase() && e.password === password);
        if (!known) saverToast(username, password);
      } catch (_) {}
    });
  }
  function scanForms() {
    for (const f of document.querySelectorAll("form")) watchSubmit(f);
  }

  // ---------- messages from popup / menus / hotkey ----------
  chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
    (async () => {
      if (msg.type === "PV_HOTKEY_FILL") { await hotkeyFill(); return { ok: true }; }
      if (msg.type === "PV_MENU") {
        // Same guards as every other fill path: blocked domains, punycode /
        // spoofed hosts, and host-less pages (file://, about:blank) refuse.
        if (isBlocked() || phishingRefuse() || !location.host) return { ok: false };
        const f = findFields();
        if (msg.menu === "pv_fill_login") {
          const l = await queryHost("PV_QUERY", pageBase());
          if (l[0]) fillLogin(l[0], f);
        } else if (msg.menu === "pv_fill_card") {
          const c = await queryHost("PV_CARDS", pageBase());
          if (c[0]) fillCard(c[0]);
        } else if (msg.menu === "pv_fill_identity") {
          const ids = await queryHost("PV_IDENTITIES", pageBase());
          if (ids[0]) fillIdentity(ids[0]);
        } else if (msg.menu === "pv_copy_password") {
          const l = await queryHost("PV_QUERY", pageBase());
          if (l[0]) copyWithAutoclear(l[0].password);
        } else if (msg.menu === "pv_copy_totp") {
          const l = await queryHost("PV_QUERY", pageBase());
          if (l[0] && l[0].totp) copyWithAutoclear(l[0].totp);
        }
        return { ok: true };
      }
      return { ok: false };
    })().then(sendResponse).catch((e) => sendResponse({ ok: false, error: String(e && e.message || e) }));
    return true;
  });

  scan();
  scanForms();
  new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
  new MutationObserver(scanForms).observe(document.documentElement, { childList: true, subtree: true });
  otpObserver.observe(document.documentElement, { childList: true, subtree: true });
  if (document.readyState === "complete" || document.readyState === "interactive") {
    autofillOnLoad();
  } else {
    window.addEventListener("DOMContentLoaded", autofillOnLoad, { once: true });
  }
})();
