// Popup: matching credentials with live TOTP, keyboard nav, fill audit,
// 📊 Stats dashboard, ⚙️ settings, and BN/EN i18n.
//
// Hang-proof: every bridge round-trip races a 10s timeout, so the popup can
// NEVER stick on "Loading…".
(async () => {
  const DEFAULTS = {
    show_suggestions: true,
    suggest_cards: true,
    suggest_identities: true,
    autofill_on_load: true,
    auto_inject_totp: true,
    show_context_menu: true,
    match_mode: "base",
    auto_submit: false,
    blocked_domains: [],
    lang: "en",
  };
  const TOGGLES = [
    ["show_suggestions", "suggest_show", "Show autofill suggestions on form fields"],
    ["suggest_cards", "suggest_cards", "Display Cards as suggestions on checkout"],
    ["suggest_identities", "suggest_ids", "Display Identities as suggestions on forms"],
    ["autofill_on_load", "autofill_load", "Enable Auto-fill on Page Load"],
    ["auto_inject_totp", "auto_totp", "Hands-free 2FA / TOTP injection"],
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
      copy2fa: "📋 Copy 2FA", no_match: (h) => `No credentials match “${h}”.`,
      open_site: "🌐 Open a real website tab first, then click the PhantomVault icon.",
      last_filled: (a) => `Last filled: ${a}`,
      never_filled: "Never filled yet",
      just_now: "just now", min_ago: (n) => `${n}m ago`, hour_ago: (n) => `${n}h ago`, day_ago: (n) => `${n}d ago`,
      score: "Security Score", fills: "Total Fills", stale_n: "Stale passwords", reused_n: "Reused groups",
    },
    bn: {
      vault: "🔑 ভল্ট", stats: "📊 পরিসংখ্যান", settings: "⚙️ অটোফিল সেটিংস",
      loading: "লোড হচ্ছে…", save: "💾 সেটিংস সংরক্ষণ", saved: "✅ সংরক্ষিত — সব ট্যাবে প্রযোজ্য।",
      match_label: "ডিফল্ট URI মিল", blocked_h: "🚫 ব্লকড ডোমেইন",
      blocked_hint: "প্রতি লাইনে একটি — এখানে ব্যাজ/অটোফিল বন্ধ।",
      retry: "🔄 পুনরায়", fill: "⚡ পূরণ", copy: "📋 কপি", copied: "✅ কপি হয়েছে", blocked_cb: "⚠️ ব্যর্থ",
      copy2fa: "📋 2FA কপি", no_match: (h) => `“${h}” এর কোনো তথ্য নেই।`,
      open_site: "🌐 আগে আসল ওয়েবসাইট খুলুন, তারপর আইকনে ক্লিক করুন।",
      last_filled: (a) => `শেষ পূরণ: ${a}`,
      never_filled: "এখনো পূরণ হয়নি",
      just_now: "এক্ষুনি", min_ago: (n) => `${n} মি আগে`, hour_ago: (n) => `${n} ঘ আগে`, day_ago: (n) => `${n} দি আগে`,
      score: "নিরাপত্তা স্কোর", fills: "মোট পূরণ", stale_n: "পুরনো পাসওয়ার্ড", reused_n: "পুনর্ব্যবহৃত গ্রুপ",
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
    if (id === "tabStats") loadStats();
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
    show_suggestions: "suggest_show", suggest_cards: "suggest_cards",
    suggest_identities: "suggest_ids", autofill_on_load: "autofill_load",
    auto_inject_totp: "auto_totp", show_context_menu: "ctx_menu", auto_submit: "auto_submit",
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

  const list = document.getElementById("list");
  const status = document.getElementById("status");
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
  try {
    const [tab] = await withTimeout(
      chrome.tabs.query({ active: true, currentWindow: true }),
      QUERY_TIMEOUT_MS, "tab lookup");
    host = tab && tab.url ? new URL(tab.url).host : "";
  } catch (_) { showLocked("no active tab"); return; }
  if (!host) { status.textContent = t("open_site"); return; }

  async function doFill(entry) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id == null) return;
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (e) => {
        const set = (el, v) => {
          if (!el) return;
          Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set.call(el, v);
          el.dispatchEvent(new Event("input", { bubbles: true }));
        };
        set(document.querySelector('input[type="text"], input[type="email"]'), e.username || "");
        set(document.querySelector('input[type="password"]'), e.password || "");
      },
      args: [{ username: entry.username, password: entry.password }],
    });
    try { await chrome.runtime.sendMessage({ type: "PV_FILLED", id: entry.id }); } catch (_) {}
    window.close();
  }

  let res;
  try {
    res = await withTimeout(
      chrome.runtime.sendMessage({ type: "PV_QUERY", app: host }),
      QUERY_TIMEOUT_MS, "vault bridge");
  } catch (e) { showLocked("bridge unreachable"); return; }
  if (!res || !res.ok) {
    const err = (res && res.error) || "";
    if (/lock/i.test(err)) showLocked();
    else if (err) status.textContent = "⚠️ " + err;
    else showLocked();
    return;
  }
  const entries = res.entries || [];
  if (!entries.length) { status.textContent = t("no_match", host); return; }
  status.textContent = "";
  const rows = [];
  entries.slice(0, 8).forEach((e, idx) => {
    const row = document.createElement("div");
    row.className = "row";
    row.tabIndex = 0;
    const hd = document.createElement("div");
    hd.className = "t";
    hd.textContent = (e.reprompt ? "🔒 " : "") + (e.title || "(untitled)");
    const u = document.createElement("div");
    u.className = "u";
    u.textContent = e.username || "";
    row.append(hd, u);
    if (e.totp) {
      const tot = document.createElement("div");
      tot.className = "totp";
      const code = document.createElement("code");
      code.textContent = e.totp;
      const cp = document.createElement("button");
      cp.textContent = t("copy2fa");
      cp.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        try { await navigator.clipboard.writeText(e.totp); cp.textContent = t("copied"); }
        catch (_) { cp.textContent = t("blocked_cb"); }
      });
      tot.append(code, cp);
      row.append(tot);
    }
    const audit = document.createElement("div");
    audit.className = "audit";
    audit.textContent = t("last_filled", ago(lastFilledMap[e.id]));
    row.append(audit);
    const btns = document.createElement("div");
    btns.className = "btns";
    const fill = document.createElement("button");
    fill.className = "fill";
    fill.textContent = t("fill");
    fill.addEventListener("click", () => doFill(e));
    const copy = document.createElement("button");
    copy.textContent = t("copy");
    copy.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      try { await navigator.clipboard.writeText(e.password || ""); copy.textContent = t("copied"); }
      catch (_) { copy.textContent = t("blocked_cb"); }
    });
    btns.append(fill, copy);
    row.append(btns);
    row.addEventListener("click", () => focusRow(idx));
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowDown") { ev.preventDefault(); focusRow(idx + 1); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); focusRow(idx - 1); }
      else if (ev.key === "Enter") { ev.preventDefault(); doFill(e); }
      else if (ev.key === "Escape") { window.close(); }
    });
    list.append(row);
    rows.push(row);
  });
  function focusRow(i) {
    const n = rows.length;
    if (!n) return;
    const j = ((i % n) + n) % n;
    rows.forEach((r) => r.classList.remove("focused"));
    rows[j].classList.add("focused");
    rows[j].focus();
  }
  focusRow(0);
})();
