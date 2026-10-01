// Popup: matching credentials with live TOTP, keyboard nav, fill audit,
// 📊 Stats dashboard, ⚙️ settings, and BN/EN i18n.
//
// Hang-proof: every bridge round-trip races a 10s timeout, so the popup can
// NEVER stick on "Loading…".
(async () => {
  const DEFAULTS = {
    show_suggestions: true,
    show_suggestions_on_icon_click_only: false,
    suggest_cards: true,
    suggest_identities: true,
    autofill_on_load: false,
    auto_inject_totp: true,
    copy_totp_auto: true,
    show_context_menu: true,
    match_mode: "base",
    auto_submit: false,
    blocked_domains: [],
    lang: "en",
  };
  const TOGGLES = [
    ["show_suggestions", "suggest_show", "Show autofill suggestions on form fields"],
    ["show_suggestions_on_icon_click_only", "suggest_icon_only", "Show suggestions only when icon is clicked"],
    ["suggest_cards", "suggest_cards", "Display Cards as suggestions on checkout"],
    ["suggest_identities", "suggest_ids", "Display Identities as suggestions on forms"],
    ["autofill_on_load", "autofill_load", "Enable Auto-fill on Page Load"],
    ["auto_inject_totp", "auto_totp", "Hands-free 2FA / TOTP injection"],
    ["copy_totp_auto", "copy_totp", "Copy TOTP automatically"],
    ["show_context_menu", "ctx_menu", "Show context menu options (Right-click)"],
    ["auto_submit", "auto_submit", "Automatically submit form after autofill"],
  ];
  const MATCH_MODES = [["base", "Base domain (recommended)"], ["host", "Host"], ["exact", "Exact URL"]];

  const I18N = {
    en: {
      vault: "🔑 Vault", stats: "📊 Stats", settings: "⚙️ Autofill Settings",
      loading: "Loading…", save: "💾 Save Settings", saved: "✅ Saved — applies to all tabs instantly.",
      match_label: "Default URI Match Detection", blocked_h: "🚫 Blocked Domains",
      blocked_hint: "One per line — no badges, no autofill here.",
      retry: "🔄 Retry", fill: "⚡ Fill", copy: "📋 Copy", copied: "✅ Copied", blocked_cb: "⚠️ Blocked",
      submit_btn: "⚡↩", lock_in: (m) => `🔒 Auto-locks in ${m}m`, lock_soon: "🔒 Locking soon…",
      pass_btn: "📋 Pass", user_btn: "👤 User", eye_show: "👁️", eye_hide: "🙈",
      sync_locked: "🔒 Vault is Locked",
      sync_locked_sub: "Unlock PhantomVault desktop app.",
      sync_inactive: "Session auto-locked for inactivity. Confirm the desktop app is open, then Retry.",
      sync_still_locked: "❌ Still locked — open/unlock the desktop app, then Retry.",
      retry_btn: "🔄 Retry",
      lock_timeout_h: "⏱️ Auto-Lock Timeout",
      lock_timeout_hint: "Lock after inactivity. A locked desktop app always locks instantly.",
      quick_pin_h: "🔐 Quick Unlock",
      quick_pin_sub: "Enter your extension PIN (set in the desktop app).",
      quick_pin_go: "🔓 Unlock",
      quick_pin_wrong: "❌ Invalid PIN. Please try again.",
      copy2fa: "📋 Copy 2FA", no_match: (h) => `No credentials match “${h}”.`,
      empty_title: "No credentials match this domain",
      empty_save: "➕ Save login for this site",
      empty_saved: "✅ Login saved to PhantomVault.",
      empty_need_both: "⚠️ Enter username + password first",
      empty_user_ph: "Username / email",
      empty_pass_ph: "Password",
      suggest_head: (d, n) => `Autofill suggestions (${d}) (${n})`,
      suggest_empty: "No suggestions for this page",
      all_head: (n) => `All items (${n})`,
      this_page: "this page",
      open_site: "🌐 Open a real website tab first, then click the PhantomVault icon.",
      last_filled: (a) => `Last filled: ${a}`,
      never_filled: "Never filled yet",
      just_now: "just now", min_ago: (n) => `${n}m ago`, hour_ago: (n) => `${n}h ago`, day_ago: (n) => `${n}d ago`,
      score: "Security Score", fills: "Total Fills", stale_n: "Stale passwords", reused_n: "Reused groups",
      suggest_show: "Show autofill suggestions on form fields",
      suggest_icon_only: "Show suggestions only when icon is clicked",
      suggest_cards: "Display Cards as suggestions on checkout",
      suggest_ids: "Display Identities as suggestions on forms",
      autofill_load: "Enable Auto-fill on Page Load",
      auto_totp: "Hands-free 2FA / TOTP injection",
      copy_totp: "Copy TOTP automatically",
      ctx_menu: "Show context menu options (Right-click)",
      auto_submit: "Automatically submit form after autofill",
    },
    bn: {
      vault: "🔑 ভল্ট", stats: "📊 পরিসংখ্যান", settings: "⚙️ অটোফিল সেটিংস",
      loading: "লোড হচ্ছে…", save: "💾 সেটিংস সংরক্ষণ", saved: "✅ সংরক্ষিত — সব ট্যাবে প্রযোজ্য।",
      match_label: "ডিফল্ট URI মিল", blocked_h: "🚫 ব্লকড ডোমেইন",
      blocked_hint: "প্রতি লাইনে একটি — এখানে ব্যাজ/অটোফিল বন্ধ।",
      retry: "🔄 পুনরায়", fill: "⚡ পূরণ", copy: "📋 কপি", copied: "✅ কপি হয়েছে", blocked_cb: "⚠️ ব্যর্থ",
      submit_btn: "⚡↩", lock_in: (m) => `🔒 ${m} মি-এ অটো-লক`, lock_soon: "🔒 শীঘ্রই লক হচ্ছে…",
      pass_btn: "📋 পাস", user_btn: "👤 ইউজার", eye_show: "👁️", eye_hide: "🙈",
      sync_locked: "🔒 ভল্ট লকড",
      sync_locked_sub: "PhantomVault ডেস্কটপ অ্যাপ আনলক করো।",
      sync_inactive: "নিষ্ক্রিয়তার জন্য সেশন লক হয়েছে। ডেস্কটপ অ্যাপ খোলা আছে কিনা দেখে Retry চাপো।",
      sync_still_locked: "❌ এখনো লকড — ডেস্কটপ অ্যাপ খুলে/আনলক করে Retry চাপো।",
      retry_btn: "🔄 পুনরায়",
      lock_timeout_h: "⏱️ অটো-লক সময়",
      lock_timeout_hint: "নিষ্ক্রিয়তার পর লক হবে। ডেস্কটপ লক হলে সাথে সাথে লক হবে।",
      quick_pin_h: "🔐 কুইক আনলক",
      quick_pin_sub: "এক্সটেনশন PIN দাও (ডেস্কটপ অ্যাপে সেট করা)।",
      quick_pin_go: "🔓 আনলক",
      quick_pin_wrong: "❌ ভুল PIN। আবার চেষ্টা করো।",
      copy2fa: "📋 2FA কপি", no_match: (h) => `“${h}” এর কোনো তথ্য নেই।`,
      empty_title: "এই ডোমেইনের কোনো তথ্য নেই",
      empty_save: "➕ এই সাইটের লগইন সংরক্ষণ করো",
      empty_saved: "✅ লগইন সংরক্ষিত হয়েছে।",
      empty_need_both: "⚠️ আগে ইউজারনেম + পাসওয়ার্ড দাও",
      empty_user_ph: "ইউজারনেম / ইমেইল",
      empty_pass_ph: "পাসওয়ার্ড",
      suggest_head: (d, n) => `অটোফিল পরামর্শ (${d}) (${n})`,
      suggest_empty: "এই পেজের জন্য পরামর্শ নেই",
      all_head: (n) => `সব আইটেম (${n})`,
      this_page: "এই পেজ",
      open_site: "🌐 আগে আসল ওয়েবসাইট খুলুন, তারপর আইকনে ক্লিক করুন।",
      last_filled: (a) => `শেষ পূরণ: ${a}`,
      never_filled: "এখনো পূরণ হয়নি",
      just_now: "এক্ষুনি", min_ago: (n) => `${n} মি আগে`, hour_ago: (n) => `${n} ঘ আগে`, day_ago: (n) => `${n} দি আগে`,
      score: "নিরাপত্তা স্কোর", fills: "মোট পূরণ", stale_n: "পুরনো পাসওয়ার্ড", reused_n: "পুনর্ব্যবহৃত গ্রুপ",
      suggest_show: "ফর্মে অটোফিল পরামর্শ দেখাও",
      suggest_icon_only: "শুধু আইকনে ক্লিক করলে পরামর্শ দেখাও",
      suggest_cards: "চেকআউটে কার্ড পরামর্শ দেখাও",
      suggest_ids: "ফর্মে পরিচয় পরামর্শ দেখাও",
      autofill_load: "পেজ লোডে অটো-ফিল চালু",
      auto_totp: "হ্যান্ডস-ফ্রি 2FA / TOTP ইনজেকশন",
      copy_totp: "TOTP স্বয়ংক্রিয়ভাবে কপি করো",
      ctx_menu: "রাইট-ক্লিক মেনু দেখাও",
      auto_submit: "অটোফিলের পর ফর্ম সাবমিট করো",
    },
  };
  let lang = "en";
  const t = (k, ...a) => {
    const v = (I18N[lang] && I18N[lang][k]) ?? I18N.en[k];
    return typeof v === "function" ? v(...a) : v;
  };
  function ago(ts) {
    if (!ts) return t("never_filled");
    const s = Date.now() / 1000 - ts;
    if (s < 90) return t("just_now");
    if (s < 3600) return t("min_ago", Math.floor(s / 60));
    if (s < 86400) return t("hour_ago", Math.floor(s / 3600));
    return t("day_ago", Math.floor(s / 86400));
  }

  // ---------- tabs ----------
  const panes = { tabVault: "vaultPane", tabStats: "statsPane", tabSettings: "settingsPane" };
  function selectTab(id) {
    for (const [b, p] of Object.entries(panes)) {
      document.getElementById(b).classList.toggle("active", b === id);
      document.getElementById(p).classList.toggle("hidden", b !== id);
    }
    if (id === "tabStats") ensureUnlocked().then((ok) => { if (ok) loadStats(); });
  }
  for (const b of Object.keys(panes)) {
    document.getElementById(b).addEventListener("click", () => selectTab(b));
  }

  // ---------- language ----------
  const langBtn = document.getElementById("langToggle");
  function applyLang() {
    langBtn.textContent = lang === "en" ? "EN" : "BN";
    document.getElementById("tabVault").textContent = t("vault");
    document.getElementById("tabStats").textContent = t("stats");
    document.getElementById("tabSettings").textContent = t("settings");
    document.getElementById("saveSettings").textContent = t("save");
    for (const [key, , fallback] of TOGGLES) {
      const lab = document.querySelector(`label[data-k="${key}"]`);
      if (lab) lab.textContent = (I18N[lang][TOGGLE_I18N[key]] ?? fallback);
    }
  }
  const TOGGLE_I18N = {
    show_suggestions: "suggest_show", show_suggestions_on_icon_click_only: "suggest_icon_only",
    suggest_cards: "suggest_cards",
    suggest_identities: "suggest_ids", autofill_on_load: "autofill_load",
    auto_inject_totp: "auto_totp", copy_totp_auto: "copy_totp",
    show_context_menu: "ctx_menu", auto_submit: "auto_submit",
  };
  langBtn.addEventListener("click", async () => {
    lang = lang === "en" ? "bn" : "en";
    await chrome.storage.local.set({ lang });
    applyLang();
  });

  // ---------- settings form ----------
  const form = document.getElementById("settingsForm");
  const inputs = {};
  for (const [key, i18nKey, fallback] of TOGGLES) {
    const row = document.createElement("div");
    row.className = "setrow";
    const lab = document.createElement("label");
    lab.dataset.k = key;
    lab.textContent = fallback;
    const cb = document.createElement("input");
    cb.type = "checkbox";
    row.append(lab, cb);
    form.append(row);
    inputs[key] = cb;
  }
  const modeRow = document.createElement("div");
  modeRow.className = "setrow";
  const modeLab = document.createElement("label");
  modeLab.textContent = "Default URI Match Detection";
  modeLab.id = "matchLab";
  const modeSel = document.createElement("select");
  for (const [v, label] of MATCH_MODES) {
    const o = document.createElement("option");
    o.value = v;
    o.textContent = label;
    modeSel.append(o);
  }
  modeRow.append(modeLab, modeSel);
  form.append(modeRow);

  const blockedEl = document.getElementById("blocked");
  chrome.storage.local.get(DEFAULTS).then((s) => {
    const cur = { ...DEFAULTS, ...s };
    lang = cur.lang === "bn" ? "bn" : "en";
    applyLang();
    // Re-translate toggle labels + settings headers now that lang is known.
    for (const [key, i18nKey, fallback] of TOGGLES) {
      const lab = document.querySelector(`label[data-k="${key}"]`);
      if (lab) lab.textContent = t(i18nKey) || fallback;
    }
    document.getElementById("matchLab").textContent = t("match_label");
    document.querySelector("#settingsPane .row .t").textContent = t("blocked_h");
    document.querySelector("#settingsPane .hint").textContent = t("blocked_hint");
    for (const [key] of TOGGLES) inputs[key].checked = cur[key] !== false;
    modeSel.value = cur.match_mode || "base";
    blockedEl.value = (cur.blocked_domains || []).join("\n");
  });
  document.getElementById("saveSettings").addEventListener("click", async () => {
    const out = { lang };
    for (const [key] of TOGGLES) out[key] = inputs[key].checked;
    out.match_mode = modeSel.value;
    out.blocked_domains = blockedEl.value.split("\n").map((d) => d.trim().toLowerCase()).filter(Boolean);
    await chrome.storage.local.set(out);
    const hint = document.getElementById("saveHint");
    hint.textContent = t("saved");
    setTimeout(() => { hint.textContent = ""; }, 2500);
  });

  // ---------- stats ----------
  async function loadStats() {
    const box = document.getElementById("statsBox");
    box.textContent = t("loading");
    let s;
    try {
      s = await chrome.runtime.sendMessage({ type: "PV_STATS" });
    } catch (_) { s = null; }
    if (!s || !s.ok) {
      box.textContent = "🔒 Vault is locked. Please unlock PhantomVault desktop app.";
      return;
    }
    const total = s.logins + s.cards + s.notes + s.identities + s.ssh_keys + s.licenses + s.passkeys;
    const color = s.score >= 80 ? "#10b981" : s.score >= 50 ? "#fbbf24" : "#fb7185";
    box.innerHTML = "";
    const mk = (label, val) => {
      const d = document.createElement("div");
      d.innerHTML = "";
      const b = document.createElement("b");
      b.textContent = String(val);
      d.append(b, document.createTextNode(" " + label));
      return d;
    };
    const grid = document.createElement("div");
    grid.className = "statgrid";
    grid.append(
      mk("Items", total), mk("2FA", s.totp_accounts),
      mk(t("fills"), s.total_fills), mk(t("stale_n"), s.stale),
      mk(t("reused_n"), s.reused_groups), mk("Logins", s.logins),
    );
    const lab = document.createElement("div");
    lab.className = "t";
    lab.textContent = `${t("score")}: ${s.score}/100`;
    const bar = document.createElement("div");
    bar.className = "scorebar";
    const fill = document.createElement("div");
    fill.style.width = `${s.score}%`;
    fill.style.background = color;
    bar.append(fill);
    box.append(lab, bar, grid);
  }

  // ---------- vault pane ----------
  const LOCKED_MSG = "🔒 Vault is locked. Please unlock PhantomVault desktop app.";
  const QUERY_TIMEOUT_MS = 10000;
  let lastFilledMap = {};
  try {
    const st = await chrome.runtime.sendMessage({ type: "PV_STATS" });
    if (st && st.ok && st.last_filled) lastFilledMap = st.last_filled;
  } catch (_) {}

  const suggestList = document.getElementById("suggestList");
  const suggestHead = document.getElementById("suggestHead");
  const neverBtn = document.getElementById("neverBtn");
  const allList = document.getElementById("allList");
  const allHead = document.getElementById("allHead");
  const status = document.getElementById("status");
  const searchBox = document.getElementById("vaultSearch");
  const folderSel = document.getElementById("folderFilter");
  const typeSel = document.getElementById("typeFilter");
  function showLocked(hint) {
    status.textContent = LOCKED_MSG + (hint ? " (" + hint + ")" : "");
    const retry = document.createElement("button");
    retry.textContent = t("retry");
    retry.addEventListener("click", () => window.location.reload());
    status.append(document.createElement("br"), retry);
  }
  function withTimeout(promise, ms, label) {
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label + " timed out")), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
  }

  let host = "";
  let hostBase = "";
  let tabUrl = "";
  try {
    const [tab] = await withTimeout(
      chrome.tabs.query({ active: true, currentWindow: true }),
      QUERY_TIMEOUT_MS, "tab lookup");
    // Bulletproof extraction: missing/blocked urls (chrome://, web store,
    // redacted without permissions) yield "" — suggestions stay empty, but
    // the full vault browser below remains usable.
    try {
      const raw = tab && tab.url ? String(tab.url) : "";
      tabUrl = raw;
      host = raw ? new URL(raw).hostname.toLowerCase() : "";
    } catch (_) { host = ""; }
    hostBase = pageBase(host);
  } catch (_) { showLocked("no active tab"); return; }
  // No host (chrome://, new-tab): suggestions stay empty, but the full
  // vault browser below remains usable.
  const noHost = !host;
  console.log("PV tab host:", host ? `${host} (base: ${hostBase})` : "(none — suggestions off)");

  function pageBase(h) {
    const parts = String(h || "").toLowerCase().split(".").filter(Boolean);
    return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
  }
  // Equivalent-domain clusters (mirrors content.js/host — keep in sync).
  const EQUIV_CLUSTERS = [
    ["proton.me", "protonmail.com", "protonvpn.com", "protondrive.com"],
    ["google.com", "youtube.com", "gmail.com", "googlemail.com", "gstatic.com", "google.co.*"],
    ["facebook.com", "messenger.com", "instagram.com", "threads.net"],
    ["microsoft.com", "live.com", "office.com", "login.microsoftonline.com", "xbox.com", "outlook.com", "hotmail.com", "onedrive.com"],
    ["apple.com", "icloud.com"],
    ["amazon.com", "primevideo.com", "audible.com", "amazon.co.*"],
    ["sony.com", "playstation.com", "playstationnetwork.com"],
    ["yahoo.com", "aol.com"],
  ];
  function memberHit(member, domain) {
    if (member.endsWith(".*")) {
      const p = member.slice(0, -2);
      return domain === p || domain.startsWith(p + ".");
    }
    return domain === member || domain.endsWith("." + member) || member.endsWith("." + domain);
  }
  function domainsEquiv(a, b) {
    const cn = (h) => {
      const full = String(h || "").toLowerCase();
      const parts = full.split(".").filter(Boolean);
      const out = [full];
      for (let i = 1; i < parts.length; i++) {
        if (parts.length - i >= 2) out.push(parts.slice(i).join("."));
      }
      return out;
    };
    const ca = cn(a), cb = cn(b);
    return EQUIV_CLUSTERS.some((cluster) =>
      cluster.some((m) => ca.some((d) => memberHit(m, d))) &&
      cluster.some((m) => cb.some((d) => memberHit(m, d))));
  }
  // Strict WEBSITE-domain extraction: username/email NEVER participate.
  // A "@gmail.com" username must not turn the whole vault into "Google".
  function itemDomains(e) {
    return (e.urls || []).map((raw) => {
      try {
        const u = new URL(raw.includes("://") ? raw : "https://" + raw);
        return u.hostname.toLowerCase();
      } catch (_) { return ""; }
    }).filter(Boolean);
  }
  function domainMatchesPage(d) {
    if (!host) return false;
    if (pageBase(d) === pageBase(host)) return true;
    return domainsEquiv(d, host);
  }
  // Suggestion gate: stored-URL domains decide; url-less legacy entries
  // fall back to TITLE text only (never username/email).
  function suggestMatch(e) {
    const domains = itemDomains(e);
    if (domains.length) return domains.some(domainMatchesPage);
    if (!hostBase) return false;
    const t = (e.title || "").toLowerCase();
    if (t.includes(hostBase)) return true;
    return EQUIV_CLUSTERS.some((cluster) => {
      const pageHit = cluster.some((m) => memberHit(m, host));
      return pageHit && cluster.some((m) => t.includes(m.replace(/\.\*$/, "")));
    });
  }
  function entryAllowed(e) {
    // Fill gate mirrors the suggestion gate (strict domains + clusters).
    // Url-less legacy entries pass through (nothing to verify against).
    const urls = e.urls || [];
    if (!urls.length) return true;
    return urls.some((raw) => {
      try {
        const u = new URL(raw.includes("://") ? raw : "https://" + raw);
        return domainMatchesPage(u.hostname);
      } catch (_) { return false; }
    });
  }
  // Shared injectors: fill returns which fields landed; submit clicks the
  // form's own submit path (requestSubmit → submit → submit-button click).
  async function injectFill(tabId, entry) {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId },
      func: (e) => {
        const set = (el, v) => {
          if (!el) return false;
          Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set.call(el, v);
          el.dispatchEvent(new Event("input", { bubbles: true }));
          return true;
        };
        return {
          u: set(document.querySelector('input[type="text"], input[type="email"]'), e.username || ""),
          p: set(document.querySelector('input[type="password"]'), e.password || ""),
        };
      },
      args: [{ username: entry.username, password: entry.password }],
    });
    return (res && res.result) || { u: false, p: false };
  }
  async function injectSubmit(tabId) {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const pw = document.querySelector('input[type="password"]');
        const form = (pw && pw.form) || document.querySelector("form");
        if (!form) return false;
        try {
          if (typeof form.requestSubmit === "function") form.requestSubmit();
          else form.submit();
          return true;
        } catch (_) {
          const btn = form.querySelector('button[type="submit"], input[type="submit"]');
          if (btn) { btn.click(); return true; }
          return false;
        }
      },
      args: [],
    });
    return !!(res && res.result);
  }
  function fillGuards(entry) {
    // Popup-side guards (content.js can't interpose here): reprompt needs
    // explicit presence; mismatched domains refuse like the page path.
    if (entry.reprompt) {
      if (!window.confirm(`🔒 "${entry.title || "Sensitive credential"}" needs verification before fill. Fill now?`)) return false;
    }
    if (!entryAllowed(entry)) {
      status.textContent = "⚠️ Phishing Hazard: Domain mismatch, autofill refused!";
      return false;
    }
    return true;
  }
  async function doFill(entry) {
    if (!fillGuards(entry)) return;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id == null) return;
    let found = { u: false, p: false };
    try {
      found = await injectFill(tab.id, entry);
    } catch (err) {
      status.textContent = "⚠️ " + ((err && err.message) || "inject failed");
      return;
    }
    if (!found.u && !found.p) {
      status.textContent = "⚠️ No login fields on this page — open the site's sign-in form first.";
      return;
    }
    try { await chrome.runtime.sendMessage({ type: "PV_FILLED", id: entry.id }); } catch (_) {}
    window.close();
  }
  async function doFillSubmit(entry) {
    if (!fillGuards(entry)) return;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id == null) return;
    let found = { u: false, p: false };
    try {
      found = await injectFill(tab.id, entry);
    } catch (err) {
      status.textContent = "⚠️ " + ((err && err.message) || "inject failed");
      return;
    }
    if (!found.u && !found.p) {
      status.textContent = "⚠️ No login fields on this page — open the site's sign-in form first.";
      return;
    }
    let submitted = false;
    try {
      submitted = await injectSubmit(tab.id);
    } catch (err) {
      status.textContent = "⚠️ " + ((err && err.message) || "submit failed");
      return;
    }
    if (!submitted) status.textContent = "⚠️ Filled, but no submittable form found.";
    try { await chrome.runtime.sendMessage({ type: "PV_FILLED", id: entry.id }); } catch (_) {}
    window.close();
  }

  // ---------- two-tier data: domain suggestions + full metadata ----------
  let suggEntries = []; // full login entries (with secrets) for this domain
  let allData = { logins: [], cards: [], identities: [], notes: [] };
  const suggIds = new Set();
  const rows = [];

  // Subdomain prefixes stripped before the initial is read — "www." /
  // "accountscenter." must never donate W or A (Facebook → F, always).
  function stripBrandPrefix(s) {
    return String(s || "")
      .replace(/^(www|m|mobile|accountscenter|accounts|account|login|signin|auth|sso)\b[^a-z0-9]*/i, "");
  }
  function brandLetter(title, username) {
    const m = stripBrandPrefix(String((title || "") + " " + (username || "")).trim()).match(/[A-Za-z0-9]/);
    return (m ? m[0] : "?").toUpperCase();
  }
  // Brand icon: letter + brand color (no more generic "A" everywhere).
  // Checks title/username/urls so "gmail" or "2captcha" resolve correctly.
  const BRANDS = [
    ["google", "G", "#4285F4", "#ffffff"],
    ["gmail", "G", "#4285F4", "#ffffff"],
    ["binance", "B", "#F3BA2F", "#080c14"],
    ["proton", "P", "#6D4AFF", "#ffffff"],
    ["firefox", "F", "#FF7139", "#ffffff"],
    ["github", "G", "#eef1ff", "#24292E"],
    ["2captcha", "2", "#8b7cf6", "#ffffff"],
    ["discord", "D", "#5865F2", "#ffffff"],
    ["steam", "S", "#66C0F4", "#080c14"],
    ["spotify", "S", "#1DB954", "#080c14"],
    ["microsoft", "M", "#00A4EF", "#ffffff"],
    ["outlook", "O", "#00A4EF", "#ffffff"],
    ["apple", "A", "#A2AAAD", "#080c14"],
    ["icloud", "A", "#A2AAAD", "#080c14"],
    ["facebook", "F", "#1877F2", "#ffffff"],
    ["instagram", "I", "#E4405F", "#ffffff"],
    ["amazon", "A", "#FF9900", "#080c14"],
    ["yahoo", "Y", "#6001D2", "#ffffff"],
    ["x", "X", "#eef1ff", "#080c14"],
    ["twitter", "X", "#1DA1F2", "#ffffff"],
  ];
  function brandIcon(entry) {
    const urls = ((entry && entry.urls) || []);
    // Stripped host roots first: "accountscenter.facebook.com" → root
    // "facebook" → F, even when the title is just "Accounts Center".
    const roots = [];
    for (const raw of urls) {
      try {
        const h = new URL(raw.includes("://") ? raw : "https://" + raw).hostname.toLowerCase();
        roots.push(stripBrandPrefix(h).split(".").filter(Boolean)[0] || "");
      } catch (_) {}
    }
    for (const root of roots) {
      if (!root) continue;
      for (const [key, letter, bg, fg] of BRANDS) {
        if (key.length > 1 && root === key) return { letter, bg, fg };
      }
    }
    const hay = (((entry && entry.title) || "") + " " + ((entry && entry.username) || "") + " " + (urls.join(" "))).toLowerCase();
    for (const [key, letter, bg, fg] of BRANDS) {
      if (key.length === 1 ? hay.split(/[^a-z0-9]/).includes(key) : hay.includes(key)) {
        return { letter, bg, fg };
      }
    }
    return { letter: brandLetter(entry && entry.title, entry && entry.username), bg: "#8b7cf6", fg: "#080c14" };
  }
  // eTLD+1-ish base for grouping (page side; host already expanded clusters).
  function regBase(h) {
    const p = String(h || "").toLowerCase().split(".").filter(Boolean);
    return p.length <= 2 ? p.join(".") : p.slice(-2).join(".");
  }

  // ---------- desktop-synced lock (no PIN anywhere) ----------
  // UNLOCKED whenever the desktop vault is reachable. Inactivity auto-lock
  // (lock_timeout_min, background session state) overlays the same screen.
  // Retry re-confirms desktop presence and restarts the idle clock.
  async function desktopReachable() {
    try {
      const pong = await withTimeout(
        chrome.runtime.sendMessage({ type: "PV_PING" }), 5000, "ping");
      return !!(pong && pong.ok && pong.unlocked !== false);
    } catch (_) { return false; }
  }
  // Single choke-point for the lock overlay (CSS-specificity lesson: always
  // set BOTH the class and the inline style, and log every transition).
  function setLockVisible(v, why) {
    const ov = document.getElementById("extLock");
    ov.classList.toggle("hidden", !v);
    ov.style.display = v ? "flex" : "none";
    console.log(`PV lock overlay ${v ? "SHOWN" : "HIDDEN"} (${why || "?"})`);
  }
  function showDesktopLock(sub) {
    document.getElementById("extLockTitle").textContent = t("sync_locked");
    document.getElementById("extLockSub").textContent = sub || t("sync_locked_sub");
    document.getElementById("extPinInput").style.display = "none";
    document.getElementById("extUnlockBtn").style.display = "none";
    const rb = document.getElementById("extRetryBtn");
    rb.style.display = "";
    rb.textContent = t("retry_btn");
    document.getElementById("extLockMsg").textContent = "";
    setLockVisible(true, "desktop-lock");
  }
  async function extPinHash() {
    // Verify-only: hash sealed in the desktop app, managed in its Settings.
    // Empty when unset/unreachable/locked — no PIN enrolled, no PIN asked.
    try {
      const res = await withTimeout(
        chrome.runtime.sendMessage({ type: "PV_EXT_PIN" }), 5000, "ext pin");
      return (res && res.ok && res.hash) || "";
    } catch (_) { return ""; }
  }
  async function sha256hex(s) {
    const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
  }
  function showPinLock() {
    document.getElementById("extLockTitle").textContent = t("quick_pin_h");
    document.getElementById("extLockSub").textContent = t("quick_pin_sub");
    const input = document.getElementById("extPinInput");
    input.style.display = "";
    input.value = "";
    const ub = document.getElementById("extUnlockBtn");
    ub.style.display = "";
    ub.textContent = t("quick_pin_go");
    document.getElementById("extRetryBtn").style.display = "none";
    const msg = document.getElementById("extLockMsg");
    msg.style.color = "";
    msg.textContent = "";
    setLockVisible(true, "quick-pin");
    input.focus();
    // Re-armable verify loop (one-shot handlers brick the popup — never again).
    const arm = () => {
      ub.onclick = async () => {
        try {
          const entered = input.value.trim();
          console.log("PV quick-PIN attempt");
          const hash = await extPinHash();
          const ok = !!hash && (await sha256hex(entered)) === hash;
          if (!ok) console.log("PV quick-PIN mismatch");
          finish(ok);
        } catch (err) { console.log("PV quick-PIN error:", err); finish(false); }
      };
      input.onkeydown = (ev) => { if (ev.key === "Enter") ub.click(); };
    };
    const finish = async (ok) => {
      ub.onclick = null;
      input.onkeydown = null;
      if (ok) {
        try { await chrome.runtime.sendMessage({ type: "PV_UNLOCKED_TOUCH" }); } catch (_) {}
        input.value = "";
        setLockVisible(false, "quick-pin-ok");
        refresh();
        return;
      }
      msg.style.color = "#ff6b6b";
      msg.textContent = t("quick_pin_wrong");
      input.value = "";
      input.focus();
      arm(); // loop: next attempt works
    };
    arm();
  }
  async function ensureUnlocked() {
    console.log("PV popup v5 (quick-pin) boot");
    let inactive = false;
    try {
      const st = await withTimeout(
        chrome.runtime.sendMessage({ type: "PV_SESSION_STATE" }), 3000, "session");
      inactive = !!(st && st.ok && st.locked);
    } catch (e) { console.log("PV session check failed:", (e && e.message) || e); }
    if (!(await desktopReachable())) {
      console.log("PV desktop unreachable — lock shown");
      showDesktopLock();
      return false;
    }
    if (inactive) {
      // Inactivity lock: quick-PIN when enrolled, else desktop presence
      // alone re-opens (a lock without PIN would be pure theater).
      if (await extPinHash()) {
        console.log("PV session inactive — PIN shown");
        showPinLock();
        return false;
      }
      console.log("PV session inactive, no PIN enrolled — reopening on desktop presence");
    }
    try { await chrome.runtime.sendMessage({ type: "PV_UNLOCKED_TOUCH" }); } catch (_) {}
    setLockVisible(false, "open");
    return true;
  }
  // Retry (wired once): re-probe desktop, restart idle clock, load vault.
  document.getElementById("extRetryBtn").addEventListener("click", async () => {
    const msg = document.getElementById("extLockMsg");
    msg.style.color = "";
    msg.textContent = "⏳ …";
    if (await desktopReachable()) {
      // NOTE: no UNLOCKED_TOUCH here — it would clear the inactivity flag
      // before ensureUnlocked reads it, silently skipping the quick-PIN.
      msg.textContent = "";
      const ok = await ensureUnlocked();
      if (ok) refresh();
    } else {
      msg.style.color = "#ff6b6b";
      msg.textContent = t("sync_still_locked");
    }
  });
  // Popup interaction counts as activity (throttled 30s): keeps the idle
  // clock fresh while the user browses/copies inside the popup.
  // (lastActPing/touchActivityPing are declared near clipText above.)
  for (const ev of ["click", "keydown"]) {
    document.addEventListener(ev, () => touchActivityPing(), { passive: true });
  }
  // Auto-lock indicator (footer): live countdown from the background
  // idle clock. Never = hidden; locked = hidden (the lock card covers it).
  const lockHint = document.getElementById("lockHint");
  async function updateLockHint() {
    try {
      const st = await withTimeout(
        chrome.runtime.sendMessage({ type: "PV_SESSION_STATE" }), 3000, "session");
      const cfg = await chrome.storage.local.get({ lock_timeout_min: 10 }).catch(() => ({ lock_timeout_min: 10 }));
      const mins = Number(cfg.lock_timeout_min) || 0;
      if (!mins || !st || !st.ok || st.locked) { lockHint.textContent = ""; return; }
      const idleMs = Number(st.idleMs) || 0;
      const remainMs = mins * 60 * 1000 - idleMs;
      if (remainMs <= 0) { lockHint.textContent = ""; return; }
      const remainMin = Math.ceil(remainMs / 60000);
      lockHint.textContent = remainMin <= 1 ? t("lock_soon") : t("lock_in", remainMin);
    } catch (_) {
      lockHint.textContent = "";
    }
  }
  setInterval(updateLockHint, 15000);
  // Auto-lock timeout pref (minutes; 0 = Never). Read by background
  // session checks on every popup boot / autofill.
  const lockTimeoutSel = document.getElementById("lockTimeout");
  chrome.storage.local.get({ lock_timeout_min: 10 }).then((s) => {
    lockTimeoutSel.value = String(s.lock_timeout_min ?? 10);
  }).catch(() => {});
  lockTimeoutSel.addEventListener("change", async () => {
    await chrome.storage.local.set({ lock_timeout_min: Number(lockTimeoutSel.value) || 0 });
    try { await chrome.runtime.sendMessage({ type: "PV_UNLOCKED_TOUCH" }); } catch (_) {}
    console.log("PV auto-lock timeout set:", lockTimeoutSel.value);
  });

  async function refresh() {
    console.log("PV refresh start");
    status.textContent = t("loading");
    suggEntries = [];
    suggIds.clear();
    allData = { logins: [], cards: [], identities: [], notes: [] };
    try {
      // Fast lock gate: a 3s ping short-circuits the 10s query wait when
      // the desktop vault is locked (bridge errors fall through to the
      // normal path — a dead bridge reports itself below).
      try {
        const pong = await withTimeout(
          chrome.runtime.sendMessage({ type: "PV_PING" }), 3000, "ping");
        if (pong && pong.ok && pong.unlocked === false) { console.log("PV refresh: ping says locked"); showLocked(); return; }
      } catch (e) { console.log("PV refresh: ping failed:", (e && e.message) || e); }
      const [q, l] = await Promise.all([
        host ? withTimeout(chrome.runtime.sendMessage({ type: "PV_QUERY", app: host }), QUERY_TIMEOUT_MS, "vault bridge") : Promise.resolve(null),
        withTimeout(chrome.runtime.sendMessage({ type: "PV_LIST" }), QUERY_TIMEOUT_MS, "vault list"),
      ]);
      if (q && !q.ok) {
        const err = q.error || "";
        console.log("PV refresh: query not ok:", err);
        if (/lock/i.test(err)) { showLocked(); return; }
        if (err) { status.textContent = "⚠️ " + err; return; }
      }
      if (l && !l.ok) {
        const err = l.error || "";
        console.log("PV refresh: list not ok:", err);
        if (/lock/i.test(err)) { showLocked(); return; }
      }
      suggEntries = (q && q.ok && q.entries) || [];
      suggEntries.forEach((e) => suggIds.add(e.id));
      if (l && l.ok) {
        allData.logins = l.logins || [];
        allData.cards = l.cards || [];
        allData.identities = l.identities || [];
        allData.notes = l.notes || [];
      }
      buildFolderOptions();
      render();
      console.log(`PV refresh done: sugg=${suggEntries.length} logins=${allData.logins.length}`);
      updateLockHint();
    } catch (e) { console.log("PV refresh: bridge unreachable:", (e && e.message) || e); showLocked("bridge unreachable"); }
  }

  function buildFolderOptions() {
    const seen = new Set();
    const folders = [];
    const touch = (f) => { const v = (f || "").trim() || "General"; if (!seen.has(v)) { seen.add(v); folders.push(v); } };
    suggEntries.forEach((e) => touch(e.folder));
    ["logins", "cards", "identities", "notes"].forEach((k) => allData[k].forEach((e) => touch(e.folder)));
    folders.sort((a, b) => a.localeCompare(b));
    const cur = folderSel.value;
    folderSel.innerHTML = "";
    const mk = (v, label) => {
      const o = document.createElement("option");
      o.value = v; o.textContent = label;
      folderSel.append(o);
    };
    mk("", "📁 Folder");
    folders.forEach((f) => mk(f, "📁 " + f));
    if ([...folderSel.options].some((o) => o.value === cur)) folderSel.value = cur;
  }

  function currentFilter() {
    return {
      q: searchBox.value.trim().toLowerCase(),
      folder: folderSel.value,
      type: typeSel.value,
    };
  }
  function matchText(e, q) {
    if (!q) return true;
    return ((e.title || "") + " " + (e.username || "") + " " + (e.full_name || "") + " " + (e.email || "")).toLowerCase().includes(q);
  }
  function matchFolder(e, folder) {
    if (!folder) return true;
    return ((e.folder || "").trim() || "General") === folder;
  }

  function sectionHead(el, labelText, isEmpty, emptyHint) {
    el.textContent = "";
    const s = document.createElement("span");
    s.textContent = labelText;
    el.append(s);
    if (isEmpty) {
      const h = document.createElement("div");
      h.style.cssText = "color:#5b6589;font-size:11px;font-weight:400;margin-top:2px;";
      h.textContent = emptyHint;
      el.append(h);
    }
  }

  function render() {
    const f = currentFilter();
    if (neverBtn) neverBtn.classList.toggle("hidden", !hostBase);
    suggestList.innerHTML = "";
    allList.innerHTML = "";
    rows.length = 0;
    // --- Tier 1: STRICT domain suggestions (website URLs only — a
    // "@gmail.com" username never promotes an entry to Google) ---
    const sugg = suggEntries.filter((e) => suggestMatch(e) && matchText(e, f.q) && matchFolder(e, f.folder) && (f.type === "all" || f.type === "1"));
    // Recently-used first (last_filled epoch, missing = 0), then A→Z by
    // username so 20+ same-domain accounts scan effortlessly.
    sugg.sort((a, b) => {
      const ta = lastFilledMap[a.id] || 0, tb = lastFilledMap[b.id] || 0;
      if (tb !== ta) return tb - ta;
      return String(a.username || "").localeCompare(String(b.username || ""), undefined, { sensitivity: "base" });
    });
    sectionHead(suggestHead, t("suggest_head", hostBase || t("this_page"), sugg.length), !sugg.length, t("suggest_empty"));
    sugg.slice(0, 20).forEach((e, i) => suggestList.append(buildLoginRow(e, i)));
    // --- Tier 2: rest of the vault (metadata; secrets fetched on demand) ---
    const rest = [];
    if (f.type === "all" || f.type === "1") {
      allData.logins.forEach((e) => { if (!suggIds.has(e.id)) rest.push({ kind: 1, e }); });
    }
    if (f.type === "all" || f.type === "4") {
      allData.cards.forEach((e) => rest.push({ kind: 4, e }));
    }
    if (f.type === "all" || f.type === "5") {
      allData.identities.forEach((e) => rest.push({ kind: 5, e }));
    }
    if (f.type === "all" || f.type === "3") {
      allData.notes.forEach((e) => rest.push({ kind: 3, e }));
    }
    const restShown = rest.filter(({ e }) => matchText(e, f.q) && matchFolder(e, f.folder));
    const totalAll = allData.logins.length + allData.cards.length + allData.identities.length + allData.notes.length;
    sectionHead(allHead, t("all_head", totalAll), false, "");
    restShown.slice(0, 60).forEach(({ kind, e }) => {
      if (kind === 1) allList.append(buildLoginMetaRow(e));
      else if (kind === 4) allList.append(buildCardRow(e));
      else if (kind === 5) allList.append(buildIdentityRow(e));
      else allList.append(buildNoteRow(e));
    });
    status.textContent = "";
    if (!sugg.length && !restShown.length) {
      if (!f.q) renderEmptyCard();
      else status.textContent = t("no_match", f.q || host);
    }
    focusRow(0);
  }

  // Empty state: illustration + headline + inline save form with the
  // current tab's domain/URL pre-filled (no separate page needed).
  function renderEmptyCard() {
    const card = document.createElement("div");
    card.className = "row emptycard";
    const art = document.createElement("div");
    art.className = "emptyart";
    art.textContent = "🔍";
    const head = document.createElement("div");
    head.className = "t";
    head.textContent = t("empty_title");
    const sub = document.createElement("div");
    sub.className = "u";
    sub.textContent = hostBase || t("this_page");
    card.append(art, head, sub);
    if (host && tabUrl) {
      const userIn = document.createElement("input");
      userIn.className = "pvinput";
      userIn.placeholder = t("empty_user_ph");
      userIn.autocomplete = "off";
      const passIn = document.createElement("input");
      passIn.className = "pvinput";
      passIn.placeholder = t("empty_pass_ph");
      passIn.type = "password";
      passIn.autocomplete = "new-password";
      const save = document.createElement("button");
      save.className = "wide";
      save.textContent = t("empty_save");
      const msg = document.createElement("div");
      msg.className = "hint";
      save.addEventListener("click", async () => {
        const username = userIn.value.trim();
        const password = passIn.value;
        if (!username || !password) { msg.textContent = t("empty_need_both"); return; }
        save.textContent = "⏳";
        try {
          const res = await withTimeout(
            chrome.runtime.sendMessage({
              type: "PV_SAVE_LOGIN",
              username, password,
              url: tabUrl,
              title: hostBase || host,
            }),
            QUERY_TIMEOUT_MS, "save");
          if (res && res.ok) {
            msg.textContent = t("empty_saved");
            userIn.value = "";
            passIn.value = "";
            refresh();
          } else {
            save.textContent = t("empty_save");
            msg.textContent = "⚠️ " + ((res && res.error) || "failed");
          }
        } catch (_) {
          save.textContent = t("empty_save");
          msg.textContent = "⚠️ Bridge unreachable";
        }
      });
      card.append(userIn, passIn, save, msg);
    }
    suggestList.append(card);
  }

  let searchTimer = null;
  searchBox.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(render, 200);
  });
  // ---------- standalone password generator ----------
  // Same CSPRNG core as the page dice (no ambiguous 0O1lI). Output shown
  // in-popup for registration flows; Copy uses the clipboard (auto-clear
  // happens on the page side; here the panel re-masks on close/render).
  const genToggle = document.getElementById("genToggle");
  const genPanel = document.getElementById("genPanel");
  const genOut = document.getElementById("genOut");
  const genLen = document.getElementById("genLen");
  const genSym = document.getElementById("genSym");
  let genSymbols = true;
  function genPassword(len, symbols) {
    const base = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const chars = symbols ? base + "!@#$%^&*-_+=" : base;
    const buf = new Uint32Array(len);
    crypto.getRandomValues(buf);
    return [...buf].map((x) => chars[x % chars.length]).join("");
  }
  function genRefresh() {
    const len = Math.min(64, Math.max(8, Number(genLen.value) || 20));
    genOut.textContent = genPassword(len, genSymbols);
    touchActivityPing();
  }
  chrome.storage.local.get({ gen_len: 20, gen_sym: true }).then((s) => {
    genLen.value = String([12, 16, 20, 32].includes(Number(s.gen_len)) ? s.gen_len : 20);
    genSymbols = s.gen_sym !== false;
    genSym.textContent = genSymbols ? "!@# ✓" : "!@# ✕";
  }).catch(() => {});
  genToggle.addEventListener("click", () => {
    const opening = genPanel.classList.contains("hidden");
    genPanel.classList.toggle("hidden");
    if (opening) genRefresh();
    else genOut.textContent = "••••••••";
  });
  document.getElementById("genNew").addEventListener("click", (ev) => { ev.stopPropagation(); genRefresh(); });
  genLen.addEventListener("change", () => {
    chrome.storage.local.set({ gen_len: Number(genLen.value) || 20 }).catch(() => {});
    genRefresh();
  });
  genSym.addEventListener("click", () => {
    genSymbols = !genSymbols;
    genSym.textContent = genSymbols ? "!@# ✓" : "!@# ✕";
    chrome.storage.local.set({ gen_sym: genSymbols }).catch(() => {});
    genRefresh();
  });
  document.getElementById("genCopy").addEventListener("click", async (ev) => {
    ev.stopPropagation();
    touchActivityPing();
    const btn = ev.currentTarget;
    try {
      await navigator.clipboard.writeText(genOut.textContent || "");
      btn.textContent = "✅";
      setTimeout(() => { btn.textContent = "📋"; }, 1500);
    } catch (_) { btn.textContent = "⚠️"; }
  });
  // Per-site "never suggest": appends this host to blocked_domains (the
  // same list content.js enforces — badges, dropdowns, autofill all stop).
  if (neverBtn) {
    neverBtn.addEventListener("click", async () => {
      if (!hostBase) return;
      try {
        const cur = await chrome.storage.local.get({ blocked_domains: [] });
        const list = new Set((cur.blocked_domains || []).map((d) => String(d).toLowerCase()));
        list.add(hostBase);
        await chrome.storage.local.set({ blocked_domains: [...list] });
        status.textContent = `🚫 Will never suggest on ${hostBase}.`;
        refresh();
      } catch (_) { status.textContent = "⚠️ Could not save setting"; }
    });
  }
  folderSel.addEventListener("change", render);
  typeSel.addEventListener("change", render);

  async function fetchEntry(kind, id) {
    const r = await withTimeout(
      chrome.runtime.sendMessage({ type: "PV_FETCH", kind, id }),
      QUERY_TIMEOUT_MS, "fetch");
    if (!r || !r.ok || !r.entry) throw new Error((r && r.error) || "fetch failed");
    return r.entry;
  }

  function brandRow(icon, title, sub, pageUrl) {
    const row = document.createElement("div");
    row.className = "row";
    row.tabIndex = 0;
    const wrap = document.createElement("div");
    wrap.className = "brandrow";
    const ic = buildBrandIcon(icon, pageUrl);
    const tx = document.createElement("div");
    tx.className = "brandtx";
    const hd = document.createElement("div");
    hd.className = "t";
    hd.textContent = title;
    const u = document.createElement("div");
    u.className = "u";
    u.textContent = sub;
    tx.append(hd, u);
    wrap.append(ic, tx);
    row.append(wrap);
    return row;
  }
  // Brand icon: real favicon image only (transparent container, no
  // background circle). Letter fallback keeps its brand color bg since a
  // bare letter on transparent looks lost.
  function buildBrandIcon(icon, pageUrl) {
    const wrap = document.createElement("div");
    wrap.className = "brandic";
    const fallback = () => {
      wrap.textContent = icon.letter;
      wrap.style.background = icon.bg;
      wrap.style.borderRadius = "16px";
      wrap.style.color = icon.fg;
    };
    try {
      const raw = String(pageUrl || "").trim();
      if (!raw) { fallback(); return wrap; }
      const page = raw.includes("://") ? raw : "https://" + raw;
      new URL(page); // validate only
      const img = document.createElement("img");
      img.width = 26;
      img.height = 26;
      img.alt = "";
      img.referrerPolicy = "no-referrer";
      img.onerror = fallback;
      img.src = chrome.runtime.getURL(
        `/_favicon/?pageUrl=${encodeURIComponent(page)}&size=32`);
      wrap.appendChild(img);
    } catch (_) {
      fallback();
    }
    return wrap;
  }
  function actionButtons(row, onFill, onCopy) {
    const btns = document.createElement("div");
    btns.className = "btns";
    const fill = document.createElement("button");
    fill.className = "fill";
    fill.textContent = t("fill");
    fill.addEventListener("click", (ev) => { ev.stopPropagation(); onFill(); });
    const copy = document.createElement("button");
    copy.textContent = t("copy");
    copy.addEventListener("click", (ev) => { ev.stopPropagation(); onCopy(copy); });
    btns.append(fill, copy);
    row.append(btns);
    return { fill, copy };
  }
  function wireKeys(row, idx, entry, onFill) {
    row.addEventListener("click", () => focusRow(idx));
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowDown") { ev.preventDefault(); focusRow(idx + 1); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); focusRow(idx - 1); }
      else if (ev.key === "Enter") { ev.preventDefault(); onFill(entry); }
      else if (ev.key === "Escape") { window.close(); }
    });
  }
  async function clipText(text, btn) {
    try { await navigator.clipboard.writeText(text || ""); btn.textContent = t("copied"); }
    catch (_) { btn.textContent = t("blocked_cb"); }
  }
  let lastActPing = 0;
  function touchActivityPing() {
    try {
      const now = Date.now();
      if (now - lastActPing < 30000) return;
      lastActPing = now;
      const p = chrome.runtime.sendMessage({ type: "PV_ACTIVITY" });
      if (p && p.catch) p.catch(() => {});
    } catch (_) {}
  }
  // Masked preview: last-3 hint beside Pass (•••x9z). Enough to tell
  // sibling accounts apart, useless to a shoulder-surfer without the rest.
  // Tier-1 rows render it immediately (secret in hand); metadata rows fill
  // their spans the first time any action fetches the password.
  function maskedPreview(secret) {
    const s = String(secret || "");
    if (s.length <= 3) return "•••";
    return "•••" + s.slice(-3);
  }
  function paintPreviews(id, password) {
    const hint = maskedPreview(password);
    document.querySelectorAll(`[data-preview-for="${id}"]`).forEach((el) => {
      el.textContent = hint;
      el.style.display = "";
    });
  }
  // In-popup password view: masked dots + 👁️ toggle. Plaintext lives only
  // in the row element; re-masks on second click or after 15 s (ephemeral).
  // getSecret resolves the plaintext (direct or via PV_FETCH); gateLabel
  // enables the master-reprompt confirm for sensitive rows.
  function passwordReveal(parent, getSecret, gateLabel) {
    const line = document.createElement("div");
    line.className = "pwline";
    const dots = document.createElement("code");
    dots.className = "pwDots";
    dots.textContent = "••••••••";
    const eye = document.createElement("button");
    eye.className = "eye";
    eye.textContent = t("eye_show");
    eye.title = "Reveal password";
    let timer = 0;
    const mask = () => {
      clearTimeout(timer); timer = 0;
      dots.textContent = "••••••••";
      eye.textContent = t("eye_show");
    };
    eye.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      touchActivityPing();
      if (timer) { mask(); return; }
      if (gateLabel && !window.confirm(`🔒 "${gateLabel}" needs verification before revealing. Reveal now?`)) return;
      eye.textContent = "…";
      try {
        const secret = await getSecret();
        if (!secret) { eye.textContent = t("eye_show"); return; }
        dots.textContent = secret;
        eye.textContent = t("eye_hide");
        timer = setTimeout(() => { if (dots.isConnected) mask(); }, 15000);
      } catch (err) { status.textContent = "⚠️ " + ((err && err.message) || err); eye.textContent = t("eye_show"); }
    });
    line.append(dots, eye);
    parent.append(line);
  }

  // TOTP live countdown (desktop-hub-ring pattern, popup edition): one
  // 1s ticker updates every visible code's remaining seconds + bar; on a
  // 30s period rollover it silently re-queries fresh codes (no popup
  // reopen, no list rebuild — DOM nodes update in place by entry id).
  let totpTicker = 0;
  let totpLastPeriod = Math.floor(Date.now() / 1000 / 30);
  function totpRemaining() {
    const epoch = Math.floor(Date.now() / 1000);
    totpLastPeriodCheck(epoch);
    return 30 - (epoch % 30);
  }
  function totpLastPeriodCheck(epoch) {
    const p = Math.floor(epoch / 30);
    if (p !== totpLastPeriod) {
      totpLastPeriod = p;
      refreshTotpCodes();
    }
  }
  function paintTotpTimers() {
    const remain = totpRemaining();
    document.querySelectorAll("[data-totp-id]").forEach((code) => {
      const timer = code.parentElement?.querySelector(".totpTimer");
      if (timer) timer.textContent = `0:${String(remain).padStart(2, "0")}`;
      const bar = code.parentElement?.parentElement?.querySelector(".totpBar > div");
      if (bar) bar.style.width = `${(remain / 30) * 100}%`;
    });
  }
  async function refreshTotpCodes() {
    try {
      if (!host) return;
      const q = await withTimeout(
        chrome.runtime.sendMessage({ type: "PV_QUERY", app: host }), QUERY_TIMEOUT_MS, "totp refresh");
      if (!q || !q.ok || !q.entries) return;
      const fresh = new Map(q.entries.map((e) => [e.id, e.totp]));
      let changed = 0;
      document.querySelectorAll("[data-totp-id]").forEach((code) => {
        const id = code.getAttribute("data-totp-id");
        if (fresh.has(id) && fresh.get(id) && fresh.get(id) !== code.textContent) {
          code.textContent = fresh.get(id);
          changed++;
        }
      });
      if (changed) console.log(`PV TOTP auto-refresh: ${changed} code(s)`);
      // Keep the in-memory entries fresh too (copy buttons read them).
      suggEntries.forEach((e) => { if (fresh.has(e.id) && fresh.get(e.id)) e.totp = fresh.get(e.id); });
    } catch (_) {}
  }
  function startTotpTicker() {
    if (totpTicker) return;
    paintTotpTimers();
    totpTicker = setInterval(paintTotpTimers, 1000);
  }
  // Full login row (suggestion tier): USERNAME is the bold primary line,
  // domain/title secondary — 20+ same-domain accounts scan by email, not
  // by identical titles. TOTP badge, compact audit, Fill/Copy/Copy-user.
  function buildLoginRow(e, idx) {
    const uname = e.username || e.title || "(untitled)";
    // ✅ = user-confirmed working password (never the password itself —
    // suggestions stay screen-share safe by design). Health icons mirror
    // the desktop audit kinds (breach N/A here — needs the desktop audit).
    const healthIcon = e.health === "reused" ? "♻️" : e.health === "weak" ? "🟡" : e.health === "stale" ? "🕰️" : "";
    const sub = [e.reprompt ? "🔒" : "", e.title || "", e.verified ? "✅" : "", healthIcon].filter(Boolean).join(" ");
    const row = brandRow(brandIcon(e), uname, sub, (e.urls && e.urls[0]) || "");
    if (e.totp) {
      const badge = document.createElement("div");
      badge.className = "t2fa";
      badge.textContent = "🔑 2FA";
      badge.title = "Authenticator code available";
      row.querySelector(".brandtx").append(badge);
      const tot = document.createElement("div");
      tot.className = "totp";
      const code = document.createElement("code");
      code.textContent = e.totp;
      code.setAttribute("data-totp-id", e.id);
      const timer = document.createElement("span");
      timer.className = "totpTimer";
      const bar = document.createElement("div");
      bar.className = "totpBar";
      const barFill = document.createElement("div");
      bar.append(barFill);
      const cp = document.createElement("button");
      cp.textContent = t("copy2fa");
      cp.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        // H14: TOTP copy on a reprompt row needs the same gate as Fill.
        if (e.reprompt && !window.confirm(`🔒 "${e.title || "Sensitive credential"}" needs verification before copying the 2FA code. Copy now?`)) return;
        // Copy the LIVE displayed code (auto-refresh may have replaced it).
        try { await navigator.clipboard.writeText(code.textContent); cp.textContent = t("copied"); }
        catch (_) { cp.textContent = t("blocked_cb"); }
      });
      tot.append(code, timer, cp);
      row.append(tot, bar);
    }
    // Compact audit: rendered ONLY when ever filled (no dead "Never" line).
    if (lastFilledMap[e.id]) {
      const audit = document.createElement("div");
      audit.className = "audit";
      audit.textContent = t("last_filled", ago(lastFilledMap[e.id]));
      row.append(audit);
    }
    // In-popup password view (Tier 1 rows carry the secret already).
    passwordReveal(row, async () => e.password || "", e.reprompt ? (e.title || "Sensitive credential") : null);
    // H14: password Copy on a reprompt row needs the same gate as Fill
    // (previously only the Fill button was protected).
    const { copy: passBtn } = actionButtons(row, () => doFill(e), (btn) => {
      if (e.reprompt && !window.confirm(`🔒 "${e.title || "Sensitive credential"}" needs verification before copying. Copy now?`)) return;
      clipText(e.password, btn);
    });
    passBtn.textContent = t("pass_btn");
    // Masked preview beside Pass (Tier-1 secret in hand).
    const prev = document.createElement("span");
    prev.className = "pwPrev";
    prev.title = "Password ends with…";
    prev.textContent = maskedPreview(e.password);
    row.querySelector(".btns").append(prev);
    // Quick username copy beside Fill/Pass.
    const btns = row.querySelector(".btns");
    if (btns && e.username) {
      const cu = document.createElement("button");
      cu.textContent = t("user_btn");
      cu.title = "Copy username";
      cu.addEventListener("click", (ev) => { ev.stopPropagation(); touchActivityPing(); clipText(e.username, cu); });
      btns.append(cu);
    }
    // Per-row Fill+Submit: fill, then the form's own submit path.
    if (btns) {
      const sb = document.createElement("button");
      sb.textContent = t("submit_btn");
      sb.title = "Fill + submit";
      sb.addEventListener("click", (ev) => { ev.stopPropagation(); doFillSubmit(e); });
      btns.append(sb);
    }
    wireKeys(row, idx, e, doFill);
    rows.push(row);
    return row;
  }
  // Metadata login row: secrets fetched on demand, then same doFill path.
  // Includes an on-demand 🔑 2FA button (fetches live code, copies it with
  // auto-clear) so All-items rows show authenticator codes too.
  function buildLoginMetaRow(e) {
    const idx = rows.length;
    const healthIcon = e.health === "reused" ? " ♻️" : e.health === "weak" ? " 🟡" : e.health === "stale" ? " 🕰️" : "";
    const row = brandRow(brandIcon(e), (e.reprompt ? "🔒 " : "") + (e.title || "(untitled)") + (e.verified ? " ✅" : "") + healthIcon, e.username || "", (e.urls && e.urls[0]) || "");
    const fillOne = async () => {
      try {
        const full = await fetchEntry(1, e.id);
        await doFill(full);
      } catch (err) { status.textContent = "⚠️ " + (err.message || err); }
    };
    const copyOne = async (btn) => {
      // H14: metadata-row copy needs the reprompt gate (fetch returns secrets).
      if (e.reprompt && !window.confirm(`🔒 "${e.title || "Sensitive credential"}" needs verification before copying. Copy now?`)) return;
      try {
        const full = await fetchEntry(1, e.id);
        paintPreviews(e.id, full.password);
        await clipText(full.password, btn);
      } catch (err) { status.textContent = "⚠️ " + (err.message || err); }
    };
    const totpOne = async (btn) => {
      if (e.reprompt && !window.confirm(`🔒 "${e.title || "Sensitive credential"}" needs verification before copying the 2FA code. Copy now?`)) return;
      btn.textContent = "…";
      try {
        const full = await fetchEntry(1, e.id);
        if (!full.totp) { btn.textContent = "—"; return; }
        try {
          await navigator.clipboard.writeText(full.totp);
          btn.textContent = full.totp;
          setTimeout(() => {
            navigator.clipboard.writeText("").catch(() => {});
            btn.textContent = "🔑 2FA";
          }, 30000);
        } catch (_) { btn.textContent = t("blocked_cb"); }
      } catch (err) { status.textContent = "⚠️ " + (err.message || err); btn.textContent = "🔑 2FA"; }
    };
    // In-popup password view (metadata tier: secret fetched on demand).
    passwordReveal(row, async () => {
      const pw = (await fetchEntry(1, e.id)).password || "";
      paintPreviews(e.id, pw);
      return pw;
    }, e.reprompt ? (e.title || "Sensitive credential") : null);
    const { copy: passBtn } = actionButtons(row, fillOne, copyOne);
    passBtn.textContent = t("pass_btn");
    // Masked preview placeholder: hidden until the first fetch paints it
    // (copy/eye/fill) — no "..." clutter on untouched rows.
    const mprev = document.createElement("span");
    mprev.className = "pwPrev";
    mprev.title = "Password ends with…";
    mprev.setAttribute("data-preview-for", e.id);
    mprev.style.display = "none";
    mprev.textContent = "•••";
    row.querySelector(".btns").append(mprev);
    // Extra 2FA button beside Fill/Pass — ONLY when the entry has TOTP
    // (list arm's has_totp; no fetch-guessing, no dead buttons).
    // Username copy + submit likewise need their data to exist.
    const btns = row.querySelector(".btns");
    if (btns) {
      if (e.has_totp) {
        const tb = document.createElement("button");
        tb.textContent = "🔑 2FA";
        tb.addEventListener("click", (ev) => { ev.stopPropagation(); totpOne(tb); });
        btns.append(tb);
      }
      if (e.username) {
        const cu = document.createElement("button");
        cu.textContent = t("user_btn");
        cu.title = "Copy username";
        cu.addEventListener("click", (ev) => { ev.stopPropagation(); touchActivityPing(); clipText(e.username, cu); });
        btns.append(cu);
      }
      const sb = document.createElement("button");
      sb.textContent = t("submit_btn");
      sb.title = "Fill + submit";
      sb.addEventListener("click", (ev) => {
        ev.stopPropagation();
        (async () => {
          try {
            await doFillSubmit(await fetchEntry(1, e.id));
          } catch (err) { status.textContent = "⚠️ " + ((err && err.message) || err); }
        })();
      });
      btns.append(sb);
    }
    wireKeys(row, idx, e, fillOne);
    rows.push(row);
    return row;
  }
  function buildCardRow(c) {
    const idx = rows.length;
    const row = brandRow(brandIcon({ ...c, username: c.cardholder }), "💳 " + (c.title || "Card"), `${c.cardholder || ""} ${c.masked || ""}`.trim());
    const fillOne = async () => {
      try {
        const full = await fetchEntry(4, c.id);
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || tab.id == null) return;
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: (cc) => {
            const set = (sel, v) => {
              const el = document.querySelector(sel);
              if (!el || !v) return;
              Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set.call(el, v);
              el.dispatchEvent(new Event("input", { bubbles: true }));
            };
            set('input[autocomplete="cc-number"], input[name*="cardnumber" i]', cc.number || "");
            set('input[autocomplete="cc-exp"], input[name*="expir" i]', (cc.exp_month && cc.exp_year) ? `${cc.exp_month}/${cc.exp_year}` : "");
            set('input[autocomplete="cc-csc"], input[name*="cvv" i], input[name*="cvc" i]', cc.cvv || "");
            set('input[autocomplete="cc-name"]', cc.cardholder || "");
          },
          args: [full],
        });
        try { await chrome.runtime.sendMessage({ type: "PV_FILLED", id: c.id }); } catch (_) {}
        window.close();
      } catch (err) { status.textContent = "⚠️ " + (err.message || err); }
    };
    const copyOne = async (btn) => {
      try {
        const full = await fetchEntry(4, c.id);
        await clipText(full.number, btn);
      } catch (err) { status.textContent = "⚠️ " + (err.message || err); }
    };
    // Quick-view: masked sub + eye reveal for the full number (15s remask).
    passwordReveal(row, async () => (await fetchEntry(4, c.id)).number || "", null);
    actionButtons(row, fillOne, copyOne);
    wireKeys(row, idx, c, fillOne);
    rows.push(row);
    return row;
  }
  function buildIdentityRow(i) {
    const idx = rows.length;
    const row = brandRow(brandIcon({ ...i, username: i.full_name }), "🪪 " + (i.title || i.full_name || "Identity"), [i.full_name, i.email].filter(Boolean).join(" • "));
    const fillOne = async () => {
      try {
        const full = await fetchEntry(5, i.id);
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || tab.id == null) return;
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: (idn) => {
            const set = (sel, v) => {
              const el = document.querySelector(sel);
              if (!el || !v) return;
              const proto = el.tagName === "TEXTAREA" ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
              Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
              el.dispatchEvent(new Event("input", { bubbles: true }));
            };
            set('input[autocomplete="name"], input[name*="fullname" i]', idn.full_name || "");
            set('input[autocomplete="email"], input[type="email"]', idn.email || "");
            set('input[autocomplete="tel"], input[name*="phone" i]', idn.phone || "");
            set('input[autocomplete="street-address"], input[name*="address" i]', idn.address || "");
          },
          args: [full],
        });
        try { await chrome.runtime.sendMessage({ type: "PV_FILLED", id: i.id }); } catch (_) {}
        window.close();
      } catch (err) { status.textContent = "⚠️ " + (err.message || err); }
    };
    const copyOne = async (btn) => {
      try {
        const full = await fetchEntry(5, i.id);
        await clipText(full.email || full.full_name, btn);
      } catch (err) { status.textContent = "⚠️ " + (err.message || err); }
    };
    actionButtons(row, fillOne, copyOne);
    wireKeys(row, idx, i, fillOne);
    rows.push(row);
    return row;
  }
  function buildNoteRow(n) {
    const idx = rows.length;
    const row = brandRow(brandIcon({ title: n.title, username: "" }), "📝 " + (n.title || "(untitled)"), "");
    const copyOne = async (btn) => {
      try {
        const full = await fetchEntry(3, n.id);
        await clipText(full.content, btn);
      } catch (err) { status.textContent = "⚠️ " + (err.message || err); }
    };
    // Quick-view: eye reveal for the note body (ellipsis + 15s remask).
    passwordReveal(row, async () => (await fetchEntry(3, n.id)).content || "", null);
    actionButtons(row, copyOne, copyOne);
    wireKeys(row, idx, n, copyOne);
    rows.push(row);
    return row;
  }
  function focusRow(i) {
    const n = rows.length;
    if (!n) return;
    const j = ((i % n) + n) % n;
    rows.forEach((r) => r.classList.remove("focused"));
    rows[j].classList.add("focused");
    rows[j].focus();
  }
  // Boot: desktop-synced gate first, then data.
  startTotpTicker();
  ensureUnlocked().then((ok) => { if (ok) refresh(); });
})();
