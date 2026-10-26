// PhantomVault Smart Autofill Engine (content script).
// Bitwarden-surpassing automation: zero-click load fill, hands-free TOTP,
// inline login/card/identity suggestions, base-domain matching, plus
// next-gen guards (anti-phishing, clickjacking, blocked domains).
(() => {
  "use strict";
  if (window.__pvEngine) return;
  window.__pvEngine = true;

  // P6: this engine boots in every frame (all_frames:true), including
  // cross-origin login widgets (Stripe/Okta/SSO). Every domain decision below
  // derives from THIS frame's own location; the top document's origin is
  // never read. An embedded frame can therefore only ever see/fill
  // credentials saved for its OWN origin. The embedding page cannot smuggle
  // another site's password into a third-party iframe, and a malicious iframe
  // cannot borrow the top page's match. Popup/hotkey route explicitly to the
  // frame that owns the form.

  const DEFAULTS = {
    show_suggestions: true,
    show_suggestions_on_icon_click_only: false,
    suggest_cards: true,
    suggest_identities: true,
    // M15: no silent zero-click fill on page load (was true) — user
    // gesture (badge/hotkey/menu) fills instead.
    autofill_on_load: false,
    auto_inject_totp: true,
    copy_totp_auto: true,
    show_context_menu: true,
    match_mode: "base", // base | host | exact
    auto_submit: false,
    blocked_domains: [],
  };
  let settings = { ...DEFAULTS };
  // H15: multi-step pending entry lives in this isolated-world closure var,
  // NEVER in page-readable sessionStorage (any XSS/third-party script could
  // read password+TOTP from there for the whole login window).
  let pvPending = null;
  // Cross-navigation bridge: full page loads (login POST → 2FA page) wipe
  // JS memory, so the ACCOUNT ID is mirrored to chrome.storage.session —
  // extension-owned (page JS CANNOT read it, unlike window.sessionStorage),
  // tab-lifetime, 5-minute expiry, consumed on fill. Never the raw DOM store.
  //
  // P1-b: no secret material is written here any more. The old stash held the
  // raw password AND a pre-generated TOTP code, so the one thing an extension
  // compromise (or another extension with storage access) wanted was sitting in
  // a store for the whole ceremony. What actually crosses the navigation is the
  // question "which account is step 2 for" — an id, which is already in the
  // popup's own replies and is useless without the vault. The password stays in
  // JS memory (lost on a full page load, which is the honest trade: the user
  // re-fills one field instead of us parking their password on disk), and the
  // code is minted natively at the moment of fill, so it is never stored stale.
  const PV_PENDING_TTL_MS = 5 * 60 * 1000;
  function pvPendingPersist() {
    try {
      if (pvPending && pvPending.totpId) {
        chrome.storage.session.set({
          pvPending: { totpId: pvPending.totpId, at: Date.now() },
        }).catch(() => {});
      }
    } catch (_) {}
  }
  function pvPendingRestore() {
    try {
      chrome.storage.session.get({ pvPending: null }).then((s) => {
        const p = s && s.pvPending;
        // `totpId` only — a legacy stash carrying `password`/`totp` is dropped
        // on sight rather than migrated, so a pre-upgrade copy can never be
        // read back into memory.
        if (p && p.totpId && !(p.password || p.totp) &&
            Date.now() - (p.at || 0) < PV_PENDING_TTL_MS) {
          pvPending = { password: "", totpId: p.totpId };
          console.log("PV pending restored across navigation");
          try { sweepOtpOnce(); } catch (_) {}
        } else if (p && (p.password || p.totp)) {
          chrome.storage.session.remove("pvPending").catch(() => {});
          console.log("PV dropped a legacy secret-bearing pending stash");
        }
      }).catch(() => {});
    } catch (_) {}
  }
  function pvPendingClear() {
    pvPending = null;
    try { sessionStorage.removeItem("__pv_pending"); } catch (_) {}
    try { chrome.storage.session.remove("pvPending").catch(() => {}); } catch (_) {}
  }
  // K1: non-secret multi-page carry. A signup often splits email (page 1) and
  // password (page 2); page 2 has no username to pair with the typed password.
  // We mirror the USERNAME only (never the password — P1-b) into
  // chrome.storage.session for the tab, keyed by page base, 5-minute TTL. It is
  // consumed to associate the later password step and never gates a fill.
  const PV_CARRY_TTL_MS = 5 * 60 * 1000;
  let pvCarryUser = "";
  // Scope the carry to THIS tab: chrome.storage.session is extension-wide, so a
  // single key let two tabs on the same site clobber each other. The tab id is
  // opaque (no PII) and survives cross-origin navigation, unlike sessionStorage.
  // Tests/background-less contexts fall back to the legacy shared key.
  const pvCarryKeyReady = (async () => {
    try {
      const r = await chrome.runtime.sendMessage({ type: "PV_TAB_ID" });
      if (r && r.ok && r.tabId != null) return "pvCaptureCarry:" + r.tabId;
    } catch (_) {}
    return "pvCaptureCarry";
  })();
  function pvCarrySave(base, username) {
    const u = (username || "").trim();
    if (!base || !u) return;
    pvCarryUser = u;
    pvCarryKeyReady.then((key) => {
      try {
        chrome.storage.session.set({
          [key]: { base, username: u, at: Date.now() },
        }).catch(() => {});
      } catch (_) {}
    }).catch(() => {});
  }
  function pvCarryLoad(base) {
    pvCarryKeyReady.then((key) => {
      try {
        chrome.storage.session.get({ [key]: null }).then((s) => {
          const c = s && s[key];
          if (c && c.base === base && c.username &&
              Date.now() - (c.at || 0) < PV_CARRY_TTL_MS) {
            pvCarryUser = c.username;
          }
        }).catch(() => {});
      } catch (_) {}
    }).catch(() => {});
  }
  function pvCarryClear() {
    pvCarryUser = "";
    pvCarryKeyReady.then((key) => {
      try { chrome.storage.session.remove(key).catch(() => {}); } catch (_) {}
    }).catch(() => {});
  }
  chrome.storage.local.get(DEFAULTS).then((s) => { settings = { ...DEFAULTS, ...s }; });
  chrome.storage.onChanged.addListener((ch, area) => {
    if (area !== "local") return;
    for (const k of Object.keys(DEFAULTS)) {
      if (ch[k]) settings[k] = ch[k].newValue;
    }
  });

  // ---------- domain utils ----------
  // Single implementation lives in domain.js (loaded before content.js by the
  // manifest; importScripts() in the background SW). E1/E2: no local copies.
  const registrable = (host) => PVDomain.registrable(host);
  function pageBase() { return registrable(location.hostname); }
  // P1 capture metadata: strip query + hash (tokens/PII) and trailing slashes
  // so the vault stores a stable origin+path; the path is kept for prefix/exact
  // URL rules. Unparseable input falls back to a raw string split.
  function captureUrl() {
    try {
      const u = new URL(location.href);
      const path = u.pathname && u.pathname !== "/" ? u.pathname.replace(/\/+$/, "") : "";
      return u.origin + path;
    } catch (_) {
      return String(location.href || "").split(/[?#]/)[0].replace(/\/+$/, "");
    }
  }
  // P1 title: prefer the site's own brand declaration over the document title,
  // then drop "Sign in - X" style suffixes. Generic-only titles fall back to
  // the registrable host.
  const TITLE_GENERIC = /^(sign in|signin|log in|login|sign up|signup|register|account|home|welcome|password)$/i;
  function captureTitle() {
    const meta = (sel) => {
      const el = document.querySelector(sel);
      const c = el && el.getAttribute("content");
      return c ? c.trim() : "";
    };
    const brand = meta('meta[property="og:site_name"]') ||
      meta('meta[name="application-name"]') ||
      meta('meta[name="apple-mobile-web-app-title"]');
    const clean = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, 60);
    if (brand) return clean(brand);
    const parts = String(document.title || "")
      .split(/\s+[|·•—–-]\s+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const pick = parts.find((p) => p.length >= 3 && !TITLE_GENERIC.test(p)) ||
      parts[0] || pageBase();
    return clean(pick);
  }
  const EQUIV_CLUSTERS = PVDomain.EQUIV_CLUSTERS;
  const memberHit = (m, d) => PVDomain.memberHit(m, d);
  const domainsEquiv = (a, b) => PVDomain.domainsEquiv(a, b);
  // Brand letter for inline rows (mirrors desktop brand_of tints loosely).
  // Subdomain prefixes (www., m., accountscenter., login., …) are stripped
  // first — "www.facebook.com" and "accountscenter.facebook.com" both yield
  // F, never W or A. Stored-URL hosts win over free-text titles.
  const HOST_PREFIXES = ["accountscenter.", "accounts.", "account.", "signin.", "login.", "auth.", "myaccount.", "mobile.", "secure.", "sso.", "mail.", "app.", "www.", "m.", "id."];
  function stripHostPrefixes(h) {
    h = String(h || "").toLowerCase();
    let hit = true;
    while (hit) {
      hit = false;
      for (const p of HOST_PREFIXES) {
        if (h.startsWith(p) && h.length > p.length + 2) { h = h.slice(p.length); hit = true; break; }
      }
    }
    return h;
  }
  function brandLetter(entry) {
    const urls = (entry && entry.urls) || [];
    for (const raw of urls) {
      try {
        const t = (typeof raw === "string") ? raw : (raw && raw.url) || "";
        const h = stripHostPrefixes(new URL(t.includes("://") ? t : "https://" + t).hostname);
        const m = h.match(/[a-z0-9]/);
        if (m) return m[0].toUpperCase();
      } catch (_) { /* next source */ }
    }
    // Title/username with leading host-ish prefixes stripped ("www
    // facebook" → "facebook" → F).
    const s = String(((entry && entry.title) || "") + " " + ((entry && entry.username) || ""))
      .replace(/^(www|m|mobile|accountscenter|accounts|account|login|signin|auth|sso)\b[^a-z0-9]*/i, "");
    const m = s.match(/[A-Za-z0-9\u0980-\u09FF]/);
    return (m ? m[0] : "?").toUpperCase();
  }
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
  // Entry allow-list by match mode. P0: entries WITHOUT a stored URL have no
  // domain binding, so they can NEVER be verified against the page — refuse
  // them on every web surface. Native query matching is title/username
  // substring based, so a lookalike host could otherwise pull a desktop-
  // captured item ("Discord") for "discord-login.com". App/desktop items stay
  // usable through the app-aware QuickBar + Auto-Type instead.
  // Per-URL rule override (0 Default → global match_mode; 1 base, 2 host,
  // 3 exact, 4 prefix, 5 never). Host may send strings (legacy/default)
  // or {url, rule} objects — both shapes accepted.
  function entryAllowed(entry) {
    const urls = entry.urls || [];
    if (!urls.length) return false;
    const pageHost = location.hostname.toLowerCase();
    const pageHref = location.href.split("#")[0].replace(/\/$/, "");
    const normHref = (h) => h.split("#")[0].replace(/\/$/, "");
    for (const raw of urls) {
      const text = (typeof raw === "string") ? raw : (raw && raw.url) || "";
      const rule = (typeof raw === "object" && raw && Number.isInteger(raw.rule)) ? raw.rule : 0;
      if (!text) continue;
      // NEVER: this URL never authorizes a fill (but doesn't veto siblings).
      if (rule === 5) continue;
      let u;
      try { u = new URL(text.includes("://") ? text : "https://" + text); }
      catch (_) { continue; }
      const mode = rule === 0 ? (settings.match_mode || "base")
        : rule === 1 ? "base" : rule === 2 ? "host" : rule === 3 ? "exact"
        : rule === 4 ? "prefix" : "base";
      if (mode === "exact") {
        if (normHref(u.href) === pageHref) return true;
      } else if (mode === "host") {
        if (u.hostname.toLowerCase() === pageHost) return true;
      } else if (mode === "prefix") {
        if (pageHref.startsWith(normHref(u.href))) return true;
      } else {
        // Base domain OR equivalent sibling (youtube ↔ google, …).
        if (registrable(u.hostname) === pageBase()) return true;
        if (domainsEquiv(u.hostname, pageHost)) return true;
      }
    }
    return false;
  }
  function filterEntries(entries) {
    const ok = [];
    let refused = false;
    for (const e of entries || []) {
      // Unbound (no URL) entries cannot be site-verified — skip silently.
      // Only a real stored-URL domain mismatch is a phishing signal.
      if (!(e.urls && e.urls.length)) continue;
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
  // React / modern SPA value injection: raw `el.value = x` is ignored by
  // controlled components — the native prototype setter plus bubbling
  // input/change events is what React's dispatcher listens for.
  function setNativeValue(el, value) {
    const proto = el.tagName === "TEXTAREA"
      ? window.HTMLTextAreaElement.prototype
      : window.HTMLInputElement.prototype;
    try { el.focus({ preventScroll: true }); } catch (_) {}
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
        // Only blank what is still ours — never clobber user-copied data.
        navigator.clipboard.readText().then((cur) => {
          if (cur === text) navigator.clipboard.writeText("").catch(() => {});
        }).catch(() => {});
      }, ms);
    }).catch(() => {
      // http://, file://, or denied permission: say so, don't fake success.
      toast("⚠️ Copy blocked by the page — click 📋 again or copy manually.");
    });
  }

  // "3m ago" from an absolute epoch second (the shape the sidecar stores).
  // Display only — nothing here feeds a freshness decision, which is entirely
  // the bridge's job; a skewed client clock can make a label wrong but must
  // never make it fill a code that is about to die.
  function ago(epochSec) {
    const s = Math.max(0, Math.floor(Date.now() / 1000) - Number(epochSec || 0));
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h`;
    const d = Math.floor(h / 24);
    return d < 30 ? `${d}d` : `${Math.floor(d / 30)}mo`;
  }

  // ---------- 2FA ambiguity picker ----------
  // Rendered inside a Shadow DOM so the host page's CSS (and ours) cannot reach
  // into each other: a 2FA ceremony is a hostile page to style a widget on, and
  // `all: initial` on the host keeps inherited `font-size`/`line-height` from
  // shredding the layout.
  let pvPicker = null;
  // Set only when the USER dismisses the picker (Esc / click-away). A dead
  // handle from a page re-render is NOT a dismissal — the sweep may re-open
  // that one, but must not re-pop a picker the user just closed on purpose.
  let otpPickerUserClosed = false;
  function closeOtpPicker(userClosed) {
    if (userClosed) otpPickerUserClosed = true;
    if (pvPicker) {
      // Stop the countdown BEFORE detaching the node: an interval that outlives
      // its host keeps calling the bridge once a second for as long as the tab
      // lives, and nothing about the picker looks alive any more.
      try { if (pvPicker.timer) clearInterval(pvPicker.timer); } catch (_) {}
      try { pvPicker.host.remove(); } catch (_) {}
      pvPicker = null;
    }
    document.removeEventListener("keydown", pvPickerEsc, true);
    document.removeEventListener("mousedown", pvPickerOutside, true);
  }
  // "Is the picker actually on screen?", not "was it ever opened?". An SPA
  // re-render can rip our host node out of the DOM while `pvPicker` still
  // points at the corpse — and then the sweep reads it as "already open",
  // refuses to re-open, and only ever shows the fallback toast. A dead handle
  // is closed (which also kills its interval) and reported as not-live.
  function otpPickerLive() {
    if (!pvPicker) return false;
    if (!pvPicker.host || !pvPicker.host.isConnected) { closeOtpPicker(false); return false; }
    return true;
  }
  function pvPickerEsc(e) { if (e.key === "Escape") closeOtpPicker(true); }
  function pvPickerOutside(e) {
    // Left-click only: right-click / long-press preview must not dismiss.
    if (e.button !== 0) return;
    if (!pvPicker) return;
    // Clicking the OTP field the picker is anchored to means "fill this one",
    // not "dismiss" — treat the anchor as inside, like the login dropdown does.
    const a = pvPicker.anchor;
    if (a && (a === e.target || a.contains(e.target))) return;
    if (pvPicker.host && !pvPicker.host.contains(e.target)) closeOtpPicker(true);
  }

  // The rectangle the picker hangs from. A normal single OTP box is its own
  // rect; a split code screen (4–12 one-digit boxes) is ONE logical field, so
  // the picker must sit under the whole strip and span its full width instead
  // of dangling off box 0. Only siblings that are visible one-char narrow
  // inputs are united — an unrelated code box elsewhere never widens the anchor
  // — and anything unexpected falls back to the plain field rect unchanged.
  function otpAnchorRect(anchor) {
    if (!anchor) return null;
    try {
      const ml = String(anchor.getAttribute("maxlength") || "");
      const narrow = ml === "1" || (anchor.size === 1 && ml === "");
      if (narrow && anchor.parentElement) {
        const boxes = [...anchor.parentElement.children].filter((c) => {
          if (c.tagName !== "INPUT" || !isVisible(c)) return false;
          const t = (c.type || "").toLowerCase();
          if (t === "password" || t === "hidden") return false;
          const m = String(c.getAttribute("maxlength") || "");
          return m === "1" || (c.size === 1 && m === "");
        });
        if (boxes.length >= 2) {
          const rects = boxes.map((c) => c.getBoundingClientRect());
          const left = Math.min(...rects.map((x) => x.left));
          const right = Math.max(...rects.map((x) => x.right));
          const bottom = Math.max(...rects.map((x) => x.bottom));
          return { left, right, bottom, width: Math.max(0, right - left) };
        }
      }
    } catch (_) {}
    return anchor.getBoundingClientRect();
  }

  // `candidates` come straight from the native ranked payload. We never sort
  // here — the bridge already ordered them, and re-sorting in the client would
  // hide the tie it wants the user to resolve.
  function openOtpPicker(candidates, fields) {
    closeOtpPicker();
    if (!Array.isArray(candidates) || !candidates.length) return;
    const anchor = (fields && fields.otp && fields.otp[0]) || findFields().otp[0];
    const host = document.createElement("div");
    host.id = "__pv_otp_picker";
    host.style.cssText = "all:initial;position:absolute;z-index:2147483647;";
    const root = host.attachShadow ? host.attachShadow({ mode: "open" }) : host;
    const style = document.createElement("style");
    style.textContent = `
      .wrap{position:fixed;z-index:2147483647;min-width:min(92vw,250px);max-width:92vw;background:#17111f;color:#e9e5f0;
        border:1px solid #3a2c46;border-radius:12px;box-shadow:0 12px 40px #000d;
        font:13px/1.4 system-ui,-apple-system,Segoe UI,sans-serif;overflow:hidden}
      .hd{padding:8px 11px;font:700 11px system-ui;letter-spacing:.4px;text-transform:uppercase;
        color:#a99fb8;background:#1f1828;border-bottom:1px solid #3a2c46}
      .row{display:flex;align-items:center;gap:8px;padding:9px 11px;cursor:pointer;
        border-bottom:1px solid #2a2033}
      .row:last-child{border-bottom:0}
      .row:hover{background:#241b30}
      .brand{flex:none;width:22px;height:22px;border-radius:6px;object-fit:cover;
        background:#2a2033;font:700 11px system-ui;color:#c9c0d8;display:flex;
        align-items:center;justify-content:center;overflow:hidden;text-transform:uppercase}
      .meta{flex:1;min-width:0}
      .name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
      .sub{font-size:11px;color:#9b93ab;margin-top:2px;white-space:nowrap;overflow:hidden;
        text-overflow:ellipsis}
      .codebox{flex:none;text-align:right}
      .code{font:800 15px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:2px;
        color:#f5f3ff}
      .ttl{font:700 9px ui-monospace,monospace;color:#86efac}
      .ttl.warn{color:#fcd34d}
      .ttl.die{color:#fca5a5}
      .tag{font:700 9px system-ui;letter-spacing:.3px;padding:2px 5px;border-radius:5px;
        text-transform:uppercase;white-space:nowrap}
      .ok{background:#14532d;color:#86efac}
      .pri{background:#1e3a5f;color:#93c5fd}
      .dup{background:#4a2c0a;color:#fcd34d}
      .wait{font-size:11px;color:#9b93ab;padding:8px 11px;border-top:1px solid #3a2c46}
      .mark{flex:none;font:700 9px system-ui;letter-spacing:.3px;padding:4px 7px;border-radius:6px;
        cursor:pointer;white-space:nowrap;text-transform:uppercase;
        background:#2a2033;color:#9b93ab;border:1px solid #3a2c46}
      .mark:hover{background:#3a2c46;color:#e9e5f0}
      .mark[disabled]{opacity:.45;cursor:default}
    `;
    root.appendChild(style);
    const wrap = document.createElement("div");
    wrap.className = "wrap";
    wrap.innerHTML = '<div class="hd">Which 2FA account? / যে 2FA account?</div>';
    const tagEl = (cls, text) => {
      const s = document.createElement("span");
      s.className = "tag " + cls;
      s.textContent = text;
      return s;
    };
    // Brand mark: the page's own favicon (harvested once per page, and it IS
    // the site these candidates were ranked for), falling back to the issuer's
    // first letter. A per-account icon would mean resolving an issuer STRING to
    // a domain inside the vault, which is a lookup the bridge does not do and
    // which would hand a hostile page a free image-timing oracle for no gain.
    const brandSrc = typeof iconUrl === "string" ? iconUrl : "";
    const makeBrand = (label) => {
      const b = document.createElement("div");
      b.className = "brand";
      const initial = (label || "?").trim().charAt(0) || "?";
      b.textContent = initial;
      if (brandSrc) {
        const img = document.createElement("img");
        img.src = brandSrc;
        img.alt = "";
        // A blocked or missing icon must not leave a blank box: fall back to
        // the letter that is already underneath.
        img.addEventListener("error", () => { img.remove(); b.textContent = initial; }, { once: true });
        b.textContent = "";
        b.appendChild(img);
      }
      return b;
    };
    // One interval for the whole picker, cleared by closeOtpPicker. Per-row
    // timers would multiply on a busy page and keep ticking after the host node
    // was detached from the document.
    const ticker = [];
    for (const c of candidates) {
      const row = document.createElement("div");
      row.className = "row";
      row.tabIndex = 0;
      row.setAttribute("role", "option");
      row.setAttribute("aria-label", c.account || c.issuer || "2FA account");
      const name = c.account || c.issuer || "(unnamed)";
      row.setAttribute("data-pv-id", String(c.id || ""));
      row.innerHTML =
        `<div class="meta"><div class="name"></div>` +
        `<div class="sub"><span class="iss"></span><span class="used"></span><span class="health"></span><span class="tags"></span></div></div>` +
        `<div class="codebox"><div class="code"></div><div class="ttl"></div></div>` +
        `<button class="mark"></button>`;
      row.insertBefore(makeBrand(c.issuer || name), row.firstChild);
      // textContent, never innerHTML, for anything vault-derived.
      row.querySelector(".name").textContent = name;
      const iss = row.querySelector(".iss");
      iss.textContent = c.issuer && c.issuer !== name ? c.issuer : "";
      if (!iss.textContent) iss.remove();
      // G7: the same stamp that drives the invisible +10 recency bonus, shown
      // so the ordering the user is looking at is explicable rather than magic.
      const used = row.querySelector(".used");
      used.textContent = c.last_filled ? ` · last ${ago(c.last_filled)}` : "";
      if (!used.textContent) used.remove();
      const tags = row.querySelector(".tags");
      const mark = row.querySelector(".mark");
      const codeEl = row.querySelector(".code");
      const ttlEl = row.querySelector(".ttl");
      // Mutable view state, kept off the payload object so a repaint never
      // mutates what the bridge sent.
      let code = c.code || "";
      // `expires_in` is a RELATIVE second count. The client only counts it down
      // and never derives a window from a raw clock; `null` means counter-based
      // HOTP, which has no window and therefore no countdown at all.
      let remaining = typeof c.expires_in === "number" ? c.expires_in : null;
      let waiting = c.next_in != null ? Math.max(0, Number(c.next_in) || 0) : null;
      // Rebuilt in place on toggle, so the badge reflects what the bridge
      // actually stored rather than what we optimistically assumed.
      const paint = () => {
        tags.textContent = "";
        if (c.verified) tags.appendChild(tagEl("ok", "✅ Working"));
        if (c.is_dup) tags.appendChild(tagEl("dup", "⚠️ DUP"));
        if (!c.verified && !c.is_dup && c.rank === 1) tags.appendChild(tagEl("pri", "Primary"));
        if (c.source === "login") tags.appendChild(tagEl("pri", "from login"));
        mark.textContent = c.verified ? "✓ Working" : "Mark working";
        mark.title = c.verified
          ? "Working mark সরান (এটা working নয়)"
          : "এই account-টি কাজ করেছে — চিহ্নিত করুন";
      };
      const paintCode = () => {
        if (code) {
          codeEl.textContent = code;
          if (remaining == null) {
            ttlEl.textContent = "";
            ttlEl.className = "ttl";
          } else {
            ttlEl.textContent = `${remaining}s`;
            ttlEl.className = "ttl" + (remaining <= 5 ? " die" : remaining <= 10 ? " warn" : "");
          }
        } else {
          // Withheld by the native guard, or our own countdown reached zero and
          // the refresh has not landed yet. Never display a code we know is dead.
          codeEl.textContent = "······";
          ttlEl.textContent = waiting != null ? `⏳ ${waiting}s` : "";
          ttlEl.className = "ttl warn";
        }
      };
      // One native re-query when this row's window closes, so a picker left open
      // across a rollover fills the NEXT code instead of the dead one. `busy`
      // keeps a slow bridge from stacking refreshes up behind one interval.
      let busy = false;
      const refresh = async () => {
        if (busy) return;
        busy = true;
        try {
          const list = await totpCandidates();
          const fresh = list.find((x) => x.id === c.id);
          if (!fresh) {
            // The account stopped being offered (deleted, or the site changed).
            code = "";
            waiting = null;
          } else {
            c.verified = fresh.verified;
            code = fresh.code || "";
            remaining = typeof fresh.expires_in === "number" ? fresh.expires_in : null;
            waiting = fresh.next_in != null ? Math.max(0, Number(fresh.next_in) || 0) : null;
          }
          paint();
          paintCode();
        } catch (_) {
          // Keep the last known state rather than blanking a working row.
        } finally {
          busy = false;
        }
      };
      paint();
      paintCode();
      ticker.push(() => {
        if (remaining != null) {
          if (remaining > 0) {
            remaining -= 1;
            if (remaining === 0) {
              // Window closed: withdraw the dead code BEFORE asking for a new
              // one, so a slow bridge can never leave a stale code clickable.
              code = "";
              paintCode();
              refresh();
            }
          }
        } else if (code && waiting != null && waiting > 0) {
          waiting -= 1;
          if (waiting === 0) refresh();
        }
        if (code || waiting != null) paintCode();
      });
      mark.addEventListener("click", async (e) => {
        // The row click means "fill this code"; the button must not also do it.
        e.stopPropagation();
        e.preventDefault();
        mark.disabled = true;
        const now = await pvVerify(c.id, !c.verified);
        mark.disabled = false;
        if (now === null) {
          toast("🛡️ Working mark বাতিল — vault locked, ব্লকড সাইট, বা decoy।");
          return;
        }
        c.verified = now;
        paint();
        toast(now ? `✅ ${name} — working মার্ক হলো` : `⚠️ ${name} — working mark সরানো হলো`);
      });
      row.addEventListener("click", () => {
        if (!code) {
          const w = remaining != null ? remaining : waiting;
          toast(w != null ? `⏳ নতুন code আসতে বাকি ${w}s` : "⏳ একটু পরে আবার চেপুন।");
          return;
        }
        closeOtpPicker();
        fillFromCandidate({ id: c.id, code });
        notePicked();
      });
      row.addEventListener("keydown", (e) => {
        if (e.key !== "Enter" && e.key !== " ") return;
        e.preventDefault();
        row.click();
      });
      wrap.appendChild(row);
    }
    // A row with no code is a withheld (expiring) one; clicking it says when
    // to come back instead of doing nothing.
    if (!candidates.some((c) => c && c.code)) {
      const wait = candidates[0] ? candidates[0].next_in : null;
      const w = document.createElement("div");
      w.className = "wait";
      w.textContent = `সব code-ই মেয়াদ শেষ — ${wait != null ? wait + "s পরে" : "কিছুক্ষণ পরে"} আবার চেপুন।`;
      wrap.appendChild(w);
    }
    root.appendChild(wrap);
    wrap.setAttribute("role", "listbox");
    wrap.setAttribute("aria-label", "2FA accounts");
    // Health icons (♻️/🟡/🕰️) for login-sourced rows — same signal the login
    // dropdown shows. Joined client-side from PV_QUERY by id: hub cards carry
    // no password so they stay unmarked; totp_lookup itself is untouched.
    try {
      queryHost("PV_QUERY", pageBase()).then((logins) => {
        if (!pvPicker || pvPicker.host !== host) return; // closed/replaced
        const health = new Map();
        for (const e of logins || []) {
          if (e && e.id && e.health) health.set(String(e.id), e.health);
        }
        const hIcon = (h) => (h === "reused" ? "♻️" : h === "weak" ? "🟡" : h === "stale" ? "🕰️" : "");
        for (const c of candidates) {
          const icon = hIcon(health.get(String(c && c.id)));
          if (!icon) continue;
          const row = [...host.querySelectorAll(".row")].find(
            (r) => r.getAttribute("data-pv-id") === String(c.id));
          const el = row && row.querySelector(".health");
          if (el) { el.textContent = " " + icon; el.title = health.get(String(c.id)); }
        }
      }).catch(() => {});
    } catch (_) {}
    wrap.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      e.preventDefault();
      const rows = [...wrap.querySelectorAll(".row")];
      const i = rows.indexOf(document.activeElement);
      const n = rows[(i + (e.key === "ArrowDown" ? 1 : rows.length - 1)) % Math.max(rows.length, 1)];
      if (n) n.focus();
    });
    document.documentElement.appendChild(host);
    // Anchor under the OTP box; fall back to top-right when it has no box.
    // RTL: anchor from the right edge instead so the picker never hugs the
    // wrong side on right-to-left pages.
    const r = otpAnchorRect(anchor);
    // Login-dropdown parity: as wide as the OTP box it anchors to (clamped to
    // the viewport), so both dropdowns read as the same component.
    const W = r ? Math.max(220, Math.min(r.width, window.innerWidth - 24)) : 300;
    wrap.style.width = `${W}px`;
    const rtl = document.dir === "rtl";
    if (rtl && r) {
      host.style.right = `${Math.max(12, Math.min(window.innerWidth - r.right, window.innerWidth - W - 12))}px`;
    } else {
      host.style.left = r ? `${Math.min(r.left, window.innerWidth - W - 12)}px` : "12px";
    }
    host.style.top = r ? `${Math.min(r.bottom + 6, window.innerHeight - 220)}px` : "80px";
    pvPicker = { host, anchor, timer: setInterval(() => { for (const t of ticker) { try { t(); } catch (_) {} } }, 1000) };
    document.addEventListener("keydown", pvPickerEsc, true);
    document.addEventListener("mousedown", pvPickerOutside, true);
  }

  // Shared checkout selectors: used by detection (badges + save prompt) and
  // by fillCard, so a card the extension captures can always be filled back.
  const CARD_NUM_SEL = 'input[autocomplete="cc-number"], input[name*="cardnumber" i], ' +
    'input[name*="card_number" i], input[id*="cardnumber" i], input[id*="card-number" i], ' +
    'input[name*="card" i][name*="num" i], input[id*="card" i][id*="num" i], ' +
    'input[data-stripe="number"]';
  const CARD_NAME_SEL = 'input[autocomplete="cc-name"], input[name*="cardholder" i], ' +
    'input[name*="card_holder" i], input[id*="cardholder" i], ' +
    'input[name*="card" i][name*="name" i], input[id*="card" i][id*="name" i]';
  const CARD_CVV_SEL = 'input[autocomplete="cc-csc"], input[name*="cvv" i], ' +
    'input[name*="cvc" i], input[name*="securitycode" i], input[name*="security-code" i], ' +
    'input[id*="cvv" i], input[id*="cvc" i]';
  const CARD_EXP_SEL = 'input[autocomplete="cc-exp"], input[name*="expir" i], ' +
    'input[name*="exp-date" i], input[name*="expiry" i], ' +
    'input[name*="card" i][name*="exp" i], input[id*="card" i][id*="exp" i]';
  const CARD_EXP_M_SEL = 'input[autocomplete="cc-exp-month"], select[autocomplete="cc-exp-month"], ' +
    'input[name*="exp-month" i], select[name*="exp-month" i], input[name*="expmonth" i], ' +
    'select[name*="expmonth" i], input[name*="exp_month" i], select[name*="exp_month" i]';
  const CARD_EXP_Y_SEL = 'input[autocomplete="cc-exp-year"], select[autocomplete="cc-exp-year"], ' +
    'input[name*="exp-year" i], select[name*="exp-year" i], input[name*="expyear" i], ' +
    'select[name*="expyear" i], input[name*="exp_year" i], select[name*="exp_year" i]';

  // New/confirm password = signup, reset or password-change field. Shared by
  // classification and the generator so it never overwrites a CURRENT
  // password box while filling the confirmation.
  function isNewPasswordField(el) {
    const ac = (el.autocomplete || "").toLowerCase();
    const nameId = ((el.name || "") + " " + (el.id || "")).toLowerCase();
    return ac === "new-password" || nameId.includes("new");
  }

  function findFields() {
    // Strict classifier: search bars NEVER classify (YouTube/Google/Amazon
    // search boxes must not get badges, listeners, or dropdowns). Login =
    // autocomplete username/email, type=email, or type=text beside a password
    // in the SAME form. Password = type=password only. OTP =
    // autocomplete=one-time-code or otp/2fa/code/token/verif name/id.
    const all = [...document.querySelectorAll("input")].filter(isVisible);
    const pass = [], newPass = [], users = [], otp = [];
    for (const el of all) {
      const type = (el.type || "").toLowerCase();
      // M15: type=password is NEVER a search box (forgot/find-password
      // pages like id="findPassword" were badge-less and unfillable).
      if (type !== "password" && isSearchField(el)) continue;
      if (type === "password") {
        if (isNewPasswordField(el)) newPass.push(el);
        else pass.push(el);
        continue;
      }
      if (isOtpField(el)) { otp.push(el); continue; }
      if (isUsernameField(el)) { users.push(el); continue; }
    }
    const q = (s) => [...document.querySelectorAll(s)].filter(isVisible).filter((el) => !isSearchField(el));
    const cards = q(CARD_NUM_SEL);
    const addr = q('input[autocomplete="street-address"], input[autocomplete="address-line1"], ' +
      'input[name*="address" i], input[autocomplete="tel"], input[name*="phone" i]');
    return { pass, newPass, users, otp, cards, addr };
  }

  // ---------- payment-card capture (save prompt) ----------
  // Luhn gate is the typo filter: a mistyped PAN must never be offered for
  // vault storage. Expiry is normalized to the vault's MM / YY pair.
  function digitsOf(v) { return String(v == null ? "" : v).replace(/\D/g, ""); }
  function luhnOk(d) {
    if (!/^\d{12,19}$/.test(d)) return false;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let n = +d[d.length - 1 - i];
      if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    return sum % 10 === 0;
  }
  function firstVisibleIn(root, sel) {
    try {
      for (const el of (root || document).querySelectorAll(sel)) {
        if (isVisible(el)) return el;
      }
    } catch (_) {}
    return null;
  }
  function monthDigits(el) {
    const v = digitsOf(el.value);
    if (v) return v;
    const opt = el.selectedOptions && el.selectedOptions[0];
    const t = ((el.value || "") + " " + ((opt && opt.textContent) || "")).toLowerCase();
    const names = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    const i = names.findIndex((n) => t.includes(n));
    return i >= 0 ? String(i + 1) : "";
  }
  // Reads the card currently typed into `root` (a form, or the document for
  // SPA checkouts that never emit a submit event). NULL unless the PAN passes
  // Luhn and a usable month/year pair is present.
  function readFormCard(root) {
    const scope = root || document;
    const numEl = firstVisibleIn(scope, CARD_NUM_SEL);
    if (!numEl) return null;
    const number = digitsOf(numEl.value);
    if (!luhnOk(number)) return null;
    const holderEl = firstVisibleIn(scope, CARD_NAME_SEL);
    const cvvEl = firstVisibleIn(scope, CARD_CVV_SEL);
    let mm = "", yy = "";
    const mEl = firstVisibleIn(scope, CARD_EXP_M_SEL);
    const yEl = firstVisibleIn(scope, CARD_EXP_Y_SEL);
    if (mEl && yEl) {
      mm = monthDigits(mEl);
      yy = digitsOf(yEl.value);
    } else {
      const expEl = firstVisibleIn(scope, CARD_EXP_SEL);
      const raw = expEl ? String(expEl.value || "").trim() : "";
      const m = raw.match(/(\d{1,4})\s*[\/\-.]\s*(\d{1,4})/);
      if (m) {
        // Accept MM/YY, MM/YYYY and YYYY-MM; MMYY (no separator) too.
        if (m[1].length === 4) { mm = m[2]; yy = m[1]; }
        else { mm = m[1]; yy = m[2]; }
      } else if (/^\d{4}$/.test(raw)) {
        mm = raw.slice(0, 2);
        yy = raw.slice(2);
      }
    }
    if (yy.length === 4) yy = yy.slice(2);
    if (!/^(0?[1-9]|1[0-2])$/.test(mm) || !/^\d{2}$/.test(yy)) return null;
    const cvv = digitsOf(cvvEl && cvvEl.value);
    if (cvv && (cvv.length < 3 || cvv.length > 4)) return null;
    return {
      number,
      cardholder: (holderEl && holderEl.value || "").trim(),
      exp_month: mm.padStart(2, "0"),
      exp_year: yy,
      cvv,
    };
  }
  // Identity reader for the save prompt. Requires a real full name plus at
  // least one contact field (phone OR street address) — name+email alone is a
  // signup/newsletter shape, not a profile worth capturing.
  function readFormIdentity(form) {
    const scope = form || document;
    const pick = (sel) => {
      const el = [...scope.querySelectorAll(sel)].find((e) => isVisible(e) && !isSearchField(e));
      return el ? String(el.value || "").trim() : "";
    };
    const full_name = pick('input[autocomplete="name"], input[name*="fullname" i], input[name*="full_name" i], input[name="name" i]');
    const email = pick('input[autocomplete="email"], input[type="email"]');
    const phone = pick('input[autocomplete="tel"], input[type="tel"], input[name*="phone" i]');
    const address = pick('input[autocomplete="street-address"], input[name*="address" i], input[name*="street" i]');
    if (!full_name || (!phone && !address)) return null;
    return { full_name, email, phone, address };
  }
  function cardBrand(num) {
    const d = digitsOf(num);
    if (/^4/.test(d)) return "Visa";
    if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(d)) return "Mastercard";
    if (/^3[47]/.test(d)) return "Amex";
    if (/^(6011|65|64[4-9])/.test(d)) return "Discover";
    if (/^(3(0[0-5]|[68])|35)/.test(d)) return "Diners/JCB";
    return "";
  }

  // ---------- strict field classifier (search-blindness fix) ----------
  // NEVER attach badges, listeners, or dropdowns to search/filter inputs.
  const SEARCH_WORDS = ["search", "search_query", "query", "keyword", "find"];
  function fieldText(el) {
    return [el.name, el.id, el.placeholder, el.getAttribute("aria-label")]
      .filter(Boolean).join(" ").toLowerCase();
  }
  function isSearchField(el) {
    if (!el || el.tagName !== "INPUT") return false;
    // M15: password exemption — defense in depth alongside the findFields
    // ordering fix above (any caller checking search-first stays safe).
    if ((el.type || "").toLowerCase() === "password") return false;
    if ((el.type || "").toLowerCase() === "search") return true;
    if ((el.getAttribute("role") || "").toLowerCase() === "searchbox") return true;
    const form = el.closest("form");
    if (form && (form.getAttribute("role") || "").toLowerCase() === "search") return true;
    const hay = fieldText(el);
    for (const w of SEARCH_WORDS) {
      if (hay.includes(w)) return true;
    }
    // Bare "q" (Google's ?q= search box) matches as a STANDALONE token only:
    // substring would nuke "unique", "request", "antique", ...
    if (hay.split(/[^a-z0-9]+/).includes("q")) return true;
    return false;
  }
  // Form-less SPA logins have no <form> to scope the username box, but the old
  // document-wide fallback badged EVERY text input on the page (nickname,
  // sidebar, comment boxes) whenever any password field existed. Keep the
  // fallback inside the login cluster instead: the same tight container, or a
  // password box sitting right next to the field.
  function tightCommonAncestor(a, b) {
    const chain = new Set();
    let x = a.parentElement;
    while (x) { chain.add(x); x = x.parentElement; }
    let y = b.parentElement;
    while (y && !chain.has(y)) y = y.parentElement;
    // body/html would re-create the page-wide false positive.
    if (!y || y === document.body || y === document.documentElement) return null;
    return y.querySelectorAll("input, select, textarea").length <= 8 ? y : null;
  }
  // A standalone email/username box only earns a shield when the page itself
  // reads like a credential step. Otherwise a matched domain badged every
  // newsletter/contact email field on the site (page-match rule (a)).
  function loginContextFor(el) {
    const ac = (el.autocomplete || "").toLowerCase();
    if (ac === "username" || ac === "email") return true;
    if (el.form && /log ?in|sign ?in|sign ?up|register|auth/i.test(el.form.action || "")) return true;
    return /log ?in|sign ?in|sign ?up|register|auth/i.test(location.pathname + " " + (document.title || ""));
  }
  function passwordNear(el) {
    const pw = [...document.querySelectorAll('input[type="password"]')].filter(isVisible);
    if (!pw.length) return false;
    if (el.form) return pw.some((p) => p.form === el.form);
    let r = null;
    try { r = el.getBoundingClientRect(); } catch (_) {}
    const laidOut = !!(r && (r.width > 0 || r.height > 0));
    for (const p of pw) {
      if (laidOut) {
        try {
          const q = p.getBoundingClientRect();
          if (q.width > 0 || q.height > 0) {
            const dx = Math.max(0, Math.max(r.left - q.right, q.left - r.right));
            const dy = Math.max(0, Math.max(r.top - q.bottom, q.top - r.bottom));
            if (Math.hypot(dx, dy) <= 320) return true;
          }
        } catch (_) {}
      }
      if (tightCommonAncestor(el, p)) return true;
    }
    return false;
  }
  function isUsernameField(el) {
    if (isSearchField(el)) return false;
    const ac = (el.autocomplete || "").toLowerCase();
    if (ac === "username" || ac === "email") return true;
    const type = (el.type || "").toLowerCase();
    if (type === "email") return true;
    if (type !== "text") return false;
    // type=text counts ONLY beside a password field in the SAME form, or in
    // the same login cluster when the site wraps fields without a <form>.
    return passwordNear(el);
  }
  // Split-input OTP groups (Google/Stripe/banks) give their boxes names like
  // "digit-0" or no name at all, so every keyword path below misses them and
  // the whole ceremony went unrecognised. A tight sibling shape fixes it: 4-12
  // children where EVERY child is a one-digit input. Requiring all children to
  // be narrow boxes is what keeps this from firing on a quantity stepper or an
  // expiry-year pair.
  function inSplitOtpGroup(el) {
    const p = el.parentElement;
    if (!p) return false;
    const sibs = [...p.children];
    if (sibs.length < 4 || sibs.length > 12) return false;
    let narrow = 0;
    for (const c of sibs) {
      if (c.tagName !== "INPUT") return false;
      const t = (c.type || "").toLowerCase();
      if (t === "password" || t === "hidden") return false;
      if (String(c.getAttribute("maxlength") || "") !== "1") return false;
      narrow++;
    }
    return narrow >= 4;
  }

  function isOtpField(el) {
    if (isSearchField(el)) return false;
    const type = (el.type || "").toLowerCase();
    // A password box is never an OTP box here; neither is a hidden input or an
    // email box (2FA-by-email still uses a dedicated short code field).
    if (type === "password" || type === "hidden" || type === "email") return false;
    if ((el.autocomplete || "").toLowerCase() === "one-time-code") return true;
    if (inSplitOtpGroup(el)) return true;

    const hay = ((el.name || "") + " " + (el.id || "") + " " +
      ((el.getAttribute && el.getAttribute("aria-label")) || "")).toLowerCase();
    // Strong tokens are decisive: nobody names a repository field "totp".
    // Compact matching covers the separated spellings ("security_code",
    // "verification code") that Bitwarden's TotpFieldNames also accept.
    if (STRONG_OTP_TOKEN.test(hay) ||
      STRONG_OTP_COMPACT.test(hay.replace(/[\s_-]+/g, ""))) return true;

    // Generic free-text fields (repo name, title, description, message, …) are
    // not code boxes. Without this gate any form whose surrounding copy
    // happened to contain the word "code" classified as a 2FA ceremony — that
    // is how the picker opened on GitHub's "New repository" form.
    if (isGenericTextField(el)) return false;

    const hint = explicitHintText(el);
    const weakToken = ((hay + " " + hint).split(/[^a-z0-9]+/).includes("code")) ||
      ((hay + " " + hint).split(/[^a-z0-9]+/).includes("token"));
    // "code"/"token" alone is a weak signal, so the box must also look like a
    // code box (short and/or numeric) or the page must explicitly announce a
    // code ceremony next to this input.
    if (weakToken) {
      if (looksLikeCodeBox(el) || CEREMONY_HINT.test(hint)) return true;
    }
    if (WEAK_OTP_PHRASE.test(hint) && looksLikeCodeBox(el)) return true;
    return false;
  }
  // OTP tokens strong enough to classify on their own.
  const STRONG_OTP_TOKEN = /\b(totp|otp|otc|2fa|mfa|two-factor|twofactor|one-time|onetime|authenticator)\b/;
  const STRONG_OTP_COMPACT = /(totpcode|otpcode|2facode|mfacode|onetimecode|onetimepassword|verificationcode|securitycode|authcode|confirmationcode|approvalscode|secondfactor|twofactorcode)/;
  // Words that say "this is the code step" when they sit on the field's own
  // label/hint. Deliberately narrow: bare "verify" is a captcha, not an OTP.
  const CEREMONY_HINT = /^(code|enter code|enter the code|login code|sign-?in code|security code|verification code|confirmation code|2fa code)$|enter (the )?code|code (sent|via)|6.?digit|one.?time|verification code|security code|two.?step|two.?factor|authenticator/;
  const WEAK_OTP_PHRASE = /\b(verification|security|auth|confirmation)\b/;
  // Free-text tokens: a field carrying one of these is never an OTP box.
  const GENERIC_TEXT_TOKENS = new Set([
    "repository", "repo", "name", "title", "description", "desc", "subject",
    "message", "comment", "body", "gist", "filename", "file", "path", "branch",
    "tag", "url", "link", "label", "project", "workspace", "organization",
    "org", "team", "folder", "directory", "company", "website", "display",
    "note", "notes", "snippet", "content", "query", "search",
  ]);
  function isGenericTextField(el) {
    const hay = ((el.name || "") + " " + (el.id || "") + " " +
      ((el.getAttribute && el.getAttribute("aria-label")) || "")).toLowerCase();
    return hay.split(/[^a-z0-9]+/).some((t) => t && GENERIC_TEXT_TOKENS.has(t));
  }
  // A real code box is short and/or numeric; a repository name is neither.
  function looksLikeCodeBox(el) {
    const t = (el.type || "").toLowerCase();
    if (t === "number") return true;
    if (((el.getAttribute && el.getAttribute("inputmode")) || "").toLowerCase() === "numeric") return true;
    const pat = (el.getAttribute && el.getAttribute("pattern")) || "";
    if (/\d/.test(pat)) return true;
    const max = parseInt((el.getAttribute && el.getAttribute("maxlength")) || "", 10);
    return Number.isFinite(max) && max >= 4 && max <= 8;
  }
  // ONLY text the page ties to this input: <label>, aria-labelledby,
  // aria-label, aria-describedby, placeholder. Page/form copy is excluded on
  // purpose — that is where the false "code" came from.
  function explicitHintText(el) {
    const parts = [];
    try {
      if (el.labels) for (const l of el.labels) parts.push(l.textContent || "");
      const lb = (el.getAttribute && el.getAttribute("aria-labelledby")) || "";
      for (const id of lb.split(/\s+/)) {
        if (!id) continue;
        const n = document.getElementById(id);
        if (n) parts.push(n.textContent || "");
      }
      const db = (el.getAttribute && el.getAttribute("aria-describedby")) || "";
      for (const id of db.split(/\s+/)) {
        if (!id) continue;
        const n = document.getElementById(id);
        if (n) parts.push(n.textContent || "");
      }
      parts.push((el.getAttribute && el.getAttribute("aria-label")) || "");
      parts.push(el.placeholder || "");
    } catch (_) {}
    return parts.join(" ").replace(/\s+/g, " ").trim().toLowerCase().slice(0, 240);
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
  // Cards are not URL-bound (a card works on every checkout), so they must
  // NOT pass through filterEntries() — that gate drops rows without `urls`,
  // which silently killed every card suggestion/fill. `all` asks the host for
  // the whole active card list.
  function queryCards() {
    const req = chrome.runtime.sendMessage({ type: "PV_CARDS", app: pageBase(), all: true })
      .then((res) => {
        if (!res || !res.ok) throw new Error((res && res.error) || "bridge failed");
        return Array.isArray(res.entries) ? res.entries : [];
      });
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("vault bridge timed out")), 10000);
    });
    return Promise.race([req, timeout]).finally(() => clearTimeout(timer));
  }
  // Identities are not URL-bound either, but filterEntries() drops every row
  // without `urls` — which silently killed identity suggestions. Bypass it,
  // exactly like cards.
  function queryIdentities() {
    const req = chrome.runtime.sendMessage({ type: "PV_IDENTITIES", app: pageBase() })
      .then((res) => {
        if (!res || !res.ok) throw new Error((res && res.error) || "bridge failed");
        return Array.isArray(res.entries) ? res.entries : [];
      });
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("vault bridge timed out")), 10000);
    });
    return Promise.race([req, timeout]).finally(() => clearTimeout(timer));
  }

  // ---------- desktop-synced gate (in-page actions, no PIN) ----------
  // Allowed when the desktop vault is reachable AND the background session
  // is not inactivity-locked. A successful probe is cached briefly so a
  // multi-field fill does not re-probe per field — but the cache EXPIRES (E5):
  // it is bounded by EXT_DESK_OK_TTL_MS and dropped on tab refocus / bfcache
  // restore, so a vault locked mid-page cannot keep authorizing page actions
  // until reload. UX-only either way — the native bridge still gates every
  // secret.
  const EXT_DESK_OK_TTL_MS = 30 * 1000;
  let extDeskOkPage = false;
  let extDeskOkAt = 0;
  let extDeskPending = null;
  function extDeskCacheFresh() {
    return extDeskOkPage && Date.now() - extDeskOkAt < EXT_DESK_OK_TTL_MS;
  }
  function extDeskInvalidate() {
    extDeskOkPage = false;
    extDeskOkAt = 0;
  }
  async function requireExtPin() {
    if (extDeskCacheFresh()) return true;
    if (extDeskPending) return extDeskPending;
    extDeskPending = (async () => {
      try {
        let sess = null;
        try { sess = await chrome.runtime.sendMessage({ type: "PV_SESSION_STATE" }); } catch (_) {}
        if (sess && sess.ok && sess.locked) {
          extDeskInvalidate();
          console.log("PV gate: session inactive — refusing page action");
          toast("🔒 Session auto-locked — open the PhantomVault popup and press Retry.");
          return false;
        }
        let pong = null;
        try { pong = await chrome.runtime.sendMessage({ type: "PV_PING" }); } catch (_) {}
        if (pong && pong.ok && pong.unlocked !== false) {
          extDeskOkPage = true;
          extDeskOkAt = Date.now();
          console.log("PV gate: desktop present — page action allowed");
          return true;
        }
        extDeskInvalidate();
        console.log("PV gate: desktop unreachable — refusing page action");
        toast("🔒 Vault is locked. Unlock PhantomVault desktop app.");
        return false;
      } finally {
        extDeskPending = null;
      }
    })();
    return extDeskPending;
  }
  // E5: returning to the tab must re-verify, and a bfcache restore must not
  // inherit a pre-lock "ok" verdict. `PV_GATE_LOCKED` is pushed by the
  // background the moment ANY surface discovers a desktop lock / idle timeout,
  // so every tab drops its warm cache immediately (not just after 30 s).
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) extDeskInvalidate();
  });
  window.addEventListener("focus", extDeskInvalidate);
  window.addEventListener("pageshow", (e) => {
    if (e.persisted) extDeskInvalidate();
  });

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
      ov.setAttribute("role", "dialog");
      ov.setAttribute("aria-modal", "true");
      ov.setAttribute("aria-label", "Verify before fill");
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
      const done = (v) => { document.removeEventListener("keydown", trap, true); ov.remove(); resolve(v); };
      // Focus trap: Tab cycles between the two buttons, Escape cancels.
      // (Keydown on ov alone rarely fires — ov is not focusable.)
      const trap = (e) => {
        if (e.key === "Escape") { e.stopPropagation(); done(false); }
        else if (e.key === "Tab") {
          e.preventDefault();
          (document.activeElement === ok ? no : ok).focus();
        }
      };
      document.addEventListener("keydown", trap, true);
      ok.addEventListener("click", () => done(true));
      no.addEventListener("click", () => done(false));
      ok.focus();
    });
  }
  function pingFilled(id) {
    if (!id) return;
    chrome.runtime.sendMessage({ type: "PV_FILLED", id }).catch(() => {});
  }
  // The user's own "this is the working one" verdict, for logins and 2FA hub
  // accounts alike. Returns the resulting `verified` state, or null when the
  // bridge refused (locked vault, decoy cover, unknown/stale id) — callers must
  // treat null as "nothing changed" and say so, never optimistically re-badge.
  // Shared by every surface that draws the ✅ Working badge so the gates below
  // (blocklist, phishing, extension PIN) can never be bypassed by a UI that
  // forgot to re-check them.
  async function pvVerify(id, on) {
    if (!id) return null;
    if (isBlocked() || !location.host) return null;
    if (!(await requireExtPin())) return null;
    try {
      const res = await chrome.runtime.sendMessage({ type: "PV_VERIFY", id, on: !!on });
      if (!res || res.ok !== true) return null;
      return !!res.verified;
    } catch (_) {
      return null;
    }
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
    // Single-field / multi-step pages (FxA, Google step 1): fill WHICHEVER
    // fields exist right now — never abort for a missing password step.
    if (f.users[0] && entry.username) setNativeValue(f.users[0], entry.username);
    if (f.pass[0] && entry.password) {
      setNativeValue(f.pass[0], entry.password);
      // Full fill on this step (own username + password): the carry is
      // redundant now, and clearing it stops a stale "this step" marker.
      // A password-only step keeps it — watchSubmit still needs it for pairing.
      if (f.users[0]) pvCarryClear();
      // Multi-step chaining: remember the step-2 password in JS memory and
      // remember only WHICH account the OTP step belongs to.
      pvPending = { password: entry.password, totpId: entry.id || "" };
      pvPendingPersist();
      try { sessionStorage.removeItem("__pv_pending"); } catch (_) {}
    } else if (f.users[0] && entry.username && entry.password) {
      // Step 1 filled email only: stash so the password step (rendered later)
      // can chain via chainPendingStep/otpObserver.
      pvPending = { password: entry.password, totpId: entry.id || "" };
      pvPendingPersist();
      try { sessionStorage.removeItem("__pv_pending"); } catch (_) {}
    }
    // `entry.totp` is read as a PRESENCE HINT ONLY — never as the code. Native
    // mints it fresh for this query (`live_totp`) and returns "" for a row with
    // no secret, so its truthiness answers "does this row carry a 2FA secret at
    // all", nothing more. Replaying the VALUE was the bug G4 fixed; gating on the
    // flag is not that. Without the gate every ordinary username+password fill
    // also attempted the id-scoped lookup, found nothing, and showed a false
    // "2FA code পাওয়া যায়নি" error toast plus an extra native round-trip.
    const otpFilled = entry.totp ? await fillLoginOtp(entry) : false;
    staleNudge(entry);
    // Exactly one `filled` stamp per user gesture: `fillFromCandidate` pings the
    // candidate it filled, so ping here only when no OTP candidate claimed it.
    if (!otpFilled) pingFilled(entry.id);
    notePicked();
    if (settings.auto_submit) {
      const form = (f.pass[0] || f.users[0] || document.activeElement || {}).form;
      if (form && form.requestSubmit) form.requestSubmit();
    }
  }
  // ---------- OTP field writing ----------
  // Split-input ("one box per digit") OTP groups are the norm on Google,
  // Stripe and most bank 2FA screens, and they are what broke hands-free fill:
  // stuffing the whole code into box 0 left boxes 1..n empty, so the page's
  // validator rejected a code that was perfectly valid.
  //
  // `maxlength="1"` is the reliable signal. Grouping is scoped to a common
  // ancestor so two unrelated one-char inputs elsewhere on the page (an expiry
  // year, a quantity stepper) never get concatenated into one fake "code".
  // Returns null when this is not a group that matches the code length.
  function otpBoxGroup(codeLen) {
    if (!codeLen) return null;
    const narrow = [...document.querySelectorAll("input")].filter((el) => {
      if (!isVisible(el)) return false;
      const t = (el.type || "").toLowerCase();
      if (t === "password" || t === "hidden") return false;
      const ml = String(el.getAttribute("maxlength") || "");
      if (ml === "1") return true;
      // `size=1` is the older spelling of the same one-digit intent, but only
      // trust it when maxlength was left unset rather than set to "-1".
      return el.size === 1 && ml === "";
    });
    if (narrow.length < codeLen) return null;
    // Group by parent element; take the tightest run that covers the code.
    const byParent = new Map();
    for (const el of narrow) {
      const p = el.parentElement;
      if (!p) continue;
      if (!byParent.has(p)) byParent.set(p, []);
      byParent.get(p).push(el);
    }
    let best = null;
    for (const [, group] of byParent) {
      if (group.length < codeLen) continue;
      if (!best || group.length < best.length) best = group;
    }
    return best && best.length >= codeLen ? best.slice(0, codeLen) : null;
  }

  // Write one digit into one box WITHOUT blurring it: `setNativeValue` fires a
  // blur per call, and blurring every box as we go makes most OTP components
  // reset or re-render the group mid-distribution.
  function setBoxDigit(el, digit) {
    const proto = window.HTMLInputElement.prototype;
    try { el.focus({ preventScroll: true }); } catch (_) {}
    try {
      Object.getOwnPropertyDescriptor(proto, "value").set.call(el, digit);
    } catch (_) { el.value = digit; }
    // keyup matters as much as input here: several OTP libraries advance focus
    // and recompute the joined value on keyup, not input.
    for (const t of ["input", "change", "keyup"]) {
      try { el.dispatchEvent(new Event(t, { bubbles: true })); } catch (_) {}
    }
  }

  // The login-fill OTP half. `entry.totp` (as shipped by `PV_QUERY`) is
  // deliberately NOT used: it was minted when that query ran, which can be many
  // seconds before the fill because a reprompt confirm() or an extension-PIN
  // prompt sits between them. Replaying it injected a code that was already
  // dying — past the native 3s guard, past its window, with no way to notice.
  //
  // One id-scoped lookup replaces it: native mints the code on the spot for this
  // exact row and applies the expiry guard, so the two properties we need are no
  // longer in tension. The scope also keeps coverage this path used to get from
  // the fallback, because a row the issuer/domain scorer cannot match is still
  // served when the caller states which row it means.
  // Returns true only when a code actually reached a field. Callers use that to
  // keep the `filled` stamp single: `fillFromCandidate` already pings on success,
  // so a caller that also pings unconditionally double-counts one user gesture
  // (auto-verify then fires a fill early, and stats inflate).
  async function fillLoginOtp(entry) {
    if (!entry || !entry.id) return false;
    const list = await totpCandidates(undefined, entry.id);
    const c = list.find((x) => x.id === entry.id);
    if (!c) {
      toast("🛡️ এই entry-র জন্য 2FA code পাওয়া গেল না।");
      return false;
    }
    if (!c.code) {
      // Withheld by the native expiry guard. Say when to come back rather than
      // substituting a stale code, which is exactly what this path used to do.
      toast(`⏳ নতুন code আসতে বাকি ${c.next_in != null ? c.next_in + "s" : "কিছুক্ষণ"}`);
      return false;
    }
    return fillFromCandidate(c);
  }

  function fillTotpNow(code, fields) {
    if (!code) return;
    const digits = String(code).replace(/\s/g, "");
    const f = fields || findFields();
    // Multi-box is checked FIRST, on purpose: `autocomplete="one-time-code"`
    // routinely sits on box 0 of a split group, so a single-box-first order
    // would funnel the entire code into the first digit box.
    const boxes = otpBoxGroup(digits.length);
    if (boxes && boxes.length === digits.length) {
      boxes.forEach((box, i) => setBoxDigit(box, digits[i]));
      if (settings.copy_totp_auto !== false) copyWithAutoclear(digits);
      return true;
    }
    if (f.otp[0]) {
      setNativeValue(f.otp[0], digits);
      // Paste-ready fallback, auto-cleared in 30s — only when the
      // "Copy TOTP automatically" setting is on.
      if (settings.copy_totp_auto !== false) copyWithAutoclear(digits);
      return true;
    }
    if (settings.copy_totp_auto !== false) {
      copyWithAutoclear(digits);
      toast("✅ 2FA code copied (no OTP field found)");
    }
    return false;
  }

  // Fill from a ranked candidate and stamp it. The single place a code reaches
  // the DOM from `PV_FILL_OTP`/`PV_FILL_OTP_ID`, so the native expiry guard can
  // never be skipped by a caller that forgot to check `code !== null`, and the
  // sidecar stamp (which drives recency ranking + 3rd-fill auto-verify) can
  // never be skipped by a caller that forgot to ping.
  function fillFromCandidate(c) {
    if (!c || !c.code) return false;
    const f = findFields();
    if (!fillTotpNow(c.code, f)) return false;
    // Same "already served" stamp the sweep sets: a later page re-render must
    // not read the (now filled) OTP box as an unfilled one and re-pop the
    // picker over a login the user already completed.
    if (f.otp[0]) f.otp[0].dataset.pvOtpFilled = "1";
    if (c.id) pingFilled(c.id);
    toast("⚡ 2FA code filled");
    return true;
  }

  // One ranked lookup, gated, with the payload normalised. Returns `[]` on any
  // failure (locked vault, blocklist, offline host) so callers can treat "no
  // candidates" uniformly instead of each re-implementing its own try/catch.
  //
  // `id` narrows the answer to one known row: native then serves that row even
  // if its issuer/domain text would not have scored as a match, so a caller that
  // already knows its entry id never loses coverage to a text-matching gap. It
  // widens matching only — the code is still minted on the spot and still passes
  // the expiry guard.
  async function totpCandidates(app, id) {
    if (isBlocked() || phishingRefuse() || !location.host) return [];
    try {
      const res = await chrome.runtime.sendMessage({
        type: "PV_TOTP_LOOKUP",
        app: app || pageBase(),
        ...(id ? { id: String(id) } : {}),
      });
      if (!res || res.ok !== true) return [];
      return Array.isArray(res.candidates) ? res.candidates.filter(Boolean) : [];
    } catch (_) {
      return [];
    }
  }

  // Selects (expiry month/year) reject the native input setter; set the
  // matching option value instead, accepting "7" vs "07" and option text.
  function setCardSelect(el, want) {
    const w = String(want || "").trim();
    if (!w) return;
    if (el.tagName !== "SELECT") { setNativeValue(el, w); return; }
    const norm = (s) => String(s == null ? "" : s).replace(/^0+/, "");
    const opts = [...el.options];
    const opt = opts.find((o) => o.value === w)
      || opts.find((o) => norm(o.value) === norm(w))
      || opts.find((o) => digitsOf(o.textContent) === norm(w));
    if (!opt) return;
    el.value = opt.value;
    for (const t of ["input", "change"]) {
      el.dispatchEvent(new Event(t, { bubbles: true }));
    }
  }
  function fillCard(entry) {
    const num = firstVisibleIn(document, CARD_NUM_SEL);
    const holder = firstVisibleIn(document, CARD_NAME_SEL);
    const cvc = firstVisibleIn(document, CARD_CVV_SEL);
    if (holder && entry.cardholder) setNativeValue(holder, entry.cardholder);
    if (num && entry.number) setNativeValue(num, entry.number);
    // Split month/year selects first; a combined cc-exp input is the fallback.
    const mEl = firstVisibleIn(document, CARD_EXP_M_SEL);
    const yEl = firstVisibleIn(document, CARD_EXP_Y_SEL);
    if (mEl && yEl && (entry.exp_month || entry.exp_year)) {
      setCardSelect(mEl, entry.exp_month);
      setCardSelect(yEl, entry.exp_year);
    } else {
      const exp = firstVisibleIn(document, CARD_EXP_SEL);
      if (exp && (entry.exp_month || entry.exp_year)) {
        setNativeValue(exp, `${entry.exp_month || ""}/${entry.exp_year || ""}`);
      }
    }
    if (cvc && entry.cvv) setNativeValue(cvc, entry.cvv);
    pingFilled(entry.id);
    notePicked();
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
    notePicked();
  }
  function masked(num) {
    const d = String(num || "").replace(/\D/g, "");
    return d.length > 4 ? "•••• " + d.slice(-4) : "••••";
  }

  // ---------- inline suggestions dropdown ----------
  let dropEl = null;
  let dropAnchor = null;
  let dropOpenedAt = 0;
  let dropSelfClosing = false;
  function closeDrop(reason) {
    if (!dropEl) return;
    suggestGen++;
    dropSelfClosing = true;
    try {
      console.log(`PV dropdown closed: ${reason || "?"}`);
      dropEl.remove();
    } finally {
      dropEl = null;
      dropSelfClosing = false;
    }
    dropAnchor = null;
    document.removeEventListener("click", outsideDrop, true);
  }
  // If the PAGE itself rips our node out (framework cleaner, overlay swap),
  // say so loudly — otherwise it looks exactly like our own close.
  new MutationObserver(() => {
    if (dropEl && !dropEl.isConnected && !dropSelfClosing) {
      console.log("PV dropdown REMOVED BY PAGE (not our close)");
      dropEl = null;
      dropAnchor = null;
      document.removeEventListener("click", outsideDrop, true);
    }
  }).observe(document.documentElement, { childList: true, subtree: true });
  function outsideDrop(e) {
    // Synthetic ghosts (site analytics, auto-dismiss timers, focus-trackers
    // that replay clicks — Instagram does this ~1s after field focus) must
    // never close the dropdown; only real user clicks outside do. Plus a
    // short grace so the opening click's own echoes can't kill it.
    if (!e.isTrusted) return;
    if (e.button !== 0) return;
    if (Date.now() - dropOpenedAt < 800) return;
    if (dropEl && !dropEl.contains(e.target)) closeDrop("outside-click");
  }
  function showDrop(anchor, rows) {
    closeDrop("replace");
    if (!rows.length || !isVisible(anchor)) return;
    dropEl = document.createElement("div");
    dropEl.style.cssText = "position:absolute;z-index:2147483647;" +
      "background:#111827;border:1px solid #1e293b;border-radius:8px;padding:6px;" +
      "box-shadow:0 12px 40px #000d;font:13px system-ui;color:#eef1ff;box-sizing:border-box;";
    // Container-level blur guard: mousedown ANYWHERE inside the dropdown must
    // not steal focus from the input (React/SPA pages re-render or dismiss on
    // blur, which otherwise cancels the row click before it fires).
    // pointerdown capture: same modal-killer defense as the badge — overlay
    // outside-click closers must not see dropdown interactions either.
    dropEl.addEventListener("pointerdown", (e) => { e.stopPropagation(); }, true);
    dropEl.addEventListener("mousedown", (e) => { e.preventDefault(); });
    // Searchable dropdown: filter input on top (20+ same-domain accounts).
    // Re-renders row buttons live; indexed binding rebuilt per render so a
    // mid-click re-render can never mis-fire (same lesson as before).
    const list = document.createElement("div");
    const paint = (filter) => {
      list.innerHTML = "";
      const q = filter.trim().toLowerCase();
      const items = rows
        // Action rows (e.g. Generate) always stay visible; only accounts filter.
        .filter((r) => r.action || !q || ((r.title || "") + " " + (r.sub || "")).toLowerCase().includes(q))
        .slice(0, 8);
      if (!items.length) {
        const none = document.createElement("div");
        none.style.cssText = "color:#8e99c0;font-size:12px;padding:8px 10px;";
        none.textContent = "No match — refine the filter.";
        list.append(none);
        return;
      }
      items.forEach((r, index) => {
        const b = document.createElement("button");
        b.type = "button";
        b.dataset.pvIndex = String(index);
        b.dataset.pvAction = r.action ? "1" : "0";
        b.style.cssText = "display:flex;width:100%;text-align:left;background:transparent;border:0;" +
          "color:#eef1ff;padding:8px 10px;border-radius:8px;cursor:pointer;align-items:center;gap:10px;" +
          (r.dim ? "opacity:.55;" : "");
        // Service brand-icon circle (Bitwarden row layout).
        const icon = document.createElement("div");
        icon.style.cssText = "flex:0 0 auto;width:30px;height:30px;border-radius:15px;background:#8b7cf6;" +
          "color:#080c14;font-weight:900;font-size:15px;display:flex;align-items:center;justify-content:center;";
        icon.textContent = r.glyph || brandLetter(r.entry || {});
        const tx = document.createElement("div");
        tx.style.cssText = "flex:1;min-width:0;";
        const t = document.createElement("div");
        t.style.fontWeight = "700";
        t.textContent = r.title;
        const s = document.createElement("div");
        s.style.cssText = "color:#8e99c0;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;";
        s.textContent = r.sub;
        tx.append(t, s);
        b.append(icon, tx);
        b.addEventListener("mouseenter", () => { b.style.background = "#1a2333"; });
        b.addEventListener("mouseleave", () => { b.style.background = "transparent"; });
        b.addEventListener("mousedown", (e) => {
          e.preventDefault();
          e.stopPropagation();
          const pick = items[index] && items[index].onPick;
          if (typeof pick === "function") pick();
          closeDrop("pick");
        });
        list.append(b);
      });
    };
    const accounts = rows.filter((r) => !r.action);
    if (accounts.length > 1) {
      const head = document.createElement("div");
      head.style.cssText = "display:flex;align-items:center;gap:8px;padding:2px 4px 8px;";
      const search = document.createElement("input");
      search.type = "text";
      search.placeholder = `🔍 Filter ${accounts.length} accounts…`;
      search.setAttribute("autocomplete", "off");
      search.setAttribute("aria-label", `Filter ${accounts.length} accounts`);
      search.style.cssText = "flex:1;min-width:0;background:#0b1226;color:#eef1ff;" +
        "border:1px solid #26315c;border-radius:8px;padding:7px 10px;font-size:13px;outline:none;";
      // Don't let page shortcuts swallow filter keystrokes (or vice versa).
      // Enter picks the first visible row (keyboard-first flow).
      search.addEventListener("keydown", (e) => {
        e.stopPropagation();
        if (e.key === "Enter") {
          e.preventDefault();
          const first = [...list.querySelectorAll("button")]
            .find((b) => b.dataset.pvAction !== "1");
          if (first) first.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true }));
        }
      });
      search.addEventListener("keyup", (e) => { e.stopPropagation(); });
      search.addEventListener("input", () => paint(search.value));
      head.append(search);
      dropEl.append(head);
      setTimeout(() => { try { search.focus({ preventScroll: true }); } catch (_) {} }, 0);
    }
    paint("");
    dropEl.append(list);
    document.documentElement.appendChild(dropEl);
    const rc = anchor.getBoundingClientRect();
    // Bitwarden parity: dropdown matches the input's EXACT bounding box.
    dropEl.style.width = rc.width + "px";
    dropEl.style.left = (rc.left + window.scrollX) + "px";
    dropEl.style.top = (rc.bottom + window.scrollY + 4) + "px";
    dropEl.style.boxSizing = "border-box";
    dropAnchor = anchor;
    dropOpenedAt = Date.now();
    console.log(`PV dropdown open: ${rows.length} row(s) on`, location.host);
    document.addEventListener("click", outsideDrop, true);
  }
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrop("escape"); }, true);

  // One ranking for EVERY fill path (in-page dropdown, hotkey, context menu):
  // carried account → verified → recently filled → A→Z. Ordering only —
  // callers must never drop rows because of it (K1: a carry cannot gate a fill).
  function carriedUserFor(f) {
    const typed = ((f && f.users) || [])
      .map((el) => String(el.value || "").trim())
      .find(Boolean) || "";
    return (typed || pvCarryUser || "").trim().toLowerCase();
  }
  function loginCarryHit(e, carried) {
    return !!(carried && String((e && e.username) || "").trim().toLowerCase() === carried);
  }
  function rankLogins(list, carried) {
    return [...(list || [])].sort(
      (a, b) =>
        (loginCarryHit(b, carried) ? 1 : 0) - (loginCarryHit(a, carried) ? 1 : 0) ||
        (b.verified ? 1 : 0) - (a.verified ? 1 : 0) ||
        (b.last_filled || 0) - (a.last_filled || 0) ||
        String(a.username || "").localeCompare(String(b.username || ""), undefined, { sensitivity: "base" }),
    );
  }

  // Shared row resolver: classifies the anchor, queries the vault ONCE, and
  // returns dropdown rows (or null when nothing applies). Used by both the
  // passive focus path and the badge-click path so they can never disagree.
  async function resolveRows(anchor, f) {
    // Explicit parens: card-field OR checkout-form context (was `a || b && c`
    // which misclassified address inputs on /checkout as card fields).
    const form = anchor.closest("form");
    const inCheckoutForm = !!form &&
      /check|pay|card/i.test(((form.id || "") + " " + location.pathname));
    const isAddr = f.addr.includes(anchor);
    // A checkout path makes *unclassified* fields card-ish, but an explicit
    // address field must still get identity suggestions (billing step).
    const isCard = f.cards.includes(anchor) || (inCheckoutForm && !isAddr);
    // Unclassified inputs (search bars, plain textareas-as-inputs, unknown
    // widgets) get NO dropdown — previously EVERY input fell into login query.
    const isLogin = f.users.includes(anchor) || f.pass.includes(anchor) || f.newPass.includes(anchor);
    if (f.otp.includes(anchor)) return null; // OTP: auto-inject owns it, no dropdown
    if (!isCard && !isAddr && !isLogin) return null;
    // Each context resolves ONLY its own kind. Falling through used to offer
    // login rows on card/address fields when a suggestions toggle was off.
    if (isCard) {
      if (!settings.suggest_cards) return null;
      const cards = await queryCards();
      return cards.map((c) => ({
        entry: { title: c.title, username: c.cardholder },
        title: "💳 " + (c.title || "Card"),
        sub: `${c.cardholder || ""} ${masked(c.number)}`.trim(),
        onPick: () => fillCard(c),
      }));
    }
    if (isAddr) {
      if (!settings.suggest_identities) return null;
      const ids = await getIdentities();
      return ids.map((i) => ({
        entry: { title: i.title, username: i.full_name },
        title: "🪪 " + (i.title || i.full_name || "Identity"),
        sub: [i.full_name, i.email].filter(Boolean).join(" • "),
        onPick: () => fillIdentity(i),
      }));
    }
    const logins = await queryHost("PV_QUERY", pageBase());
    // Multi-page login (Google-style): the email typed on the previous step is
    // carried in session storage. Rank that account FIRST — ordering only,
    // never a filter, so the K1 invariant (a carry must not gate a fill) still
    // holds. A username the page already prefilled wins over the carry.
    const carried = carriedUserFor(f);
    // Trust rank: carried account → verified → recently filled → A→Z. Fakes
    // (unverified, never filled) sink to the bottom automatically.
    const hIcon = (h) => (h === "reused" ? "♻️" : h === "weak" ? "🟡" : h === "stale" ? "🕰️" : "");
    const agoShort = (ts) => {
      const s = Math.max(0, Math.floor(Date.now() / 1000) - (ts || 0));
      if (s < 60) return "just now";
      if (s < 3600) return `${Math.floor(s / 60)}m ago`;
      if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
      return `${Math.floor(s / 86400)}d ago`;
    };
    const ranked = rankLogins(logins, carried);
    return ranked.map((e) => {
      const badge = [e.verified ? "✅" : "", hIcon(e.health)].filter(Boolean).join(" ");
      const sub = [e.username || "", badge, loginCarryHit(e, carried) ? "this step" : "",
        e.last_filled ? `Last ${agoShort(e.last_filled)}` : ""]
        .filter(Boolean)
        .join(" · ");
      // Likely-unused laboratory: dimmed, never hidden (user is the judge).
      const dim = !e.verified && !e.last_filled;
      return {
        entry: e,
        title: "🔑 " + (e.title || "(untitled)") + (dim ? " (unused?)" : ""),
        sub,
        dim,
        onPick: () => fillLogin(e, f),
      };
    });
  }
  // Post-pick cooldown: after a successful fill, passive focus-driven
  // dropdowns stay suppressed briefly so they never cover the page's own
  // Next/Submit buttons. Explicit badge clicks bypass it (user asked).
  let suppressDropUntil = 0;
  function notePicked() {
    suppressDropUntil = Date.now() + 3000;
  }
  // OTP-field focus parity with the login dropdown: several accounts for
  // this site ⇒ the same picker opens under the box the user just focused,
  // instead of the old "open the popup" toast. Gated identically to the
  // passive login path (`show_suggestions` + not icon-click-only), one query
  // per field at a time, and the pick cooldown stops SPA refocus storms
  // from re-opening it right after a fill.
  let otpSuggestBusy = null;
  async function suggestOtpFor(field) {
    if (!settings.show_suggestions || isBlocked() || phishingRefuse()) return;
    if (!location.host || !field || !field.isConnected) return;
    if (settings.show_suggestions_on_icon_click_only) return;
    if (otpPickerLive() || otpSuggestBusy === field || Date.now() < suppressDropUntil) return;
    otpSuggestBusy = field;
    try {
      if (!(await requireExtPin())) return;
      const list = await totpCandidates();
      if (otpPickerLive() || !field.isConnected) return;
      const ambiguous = list.length > 1 || list.some((c) => c && c.is_dup);
      if (ambiguous) {
        otpPickerUserClosed = false; // explicit focus = fresh intent
        openOtpPicker(list, { otp: [field] });
      }
    } catch (_) {
      /* bridge down: stay silent, popup explains */
    } finally {
      if (otpSuggestBusy === field) otpSuggestBusy = null;
    }
  }
  async function suggestFor(anchor) {
    if (!settings.show_suggestions || isBlocked() || phishingRefuse()) return;
    if (!location.host) return;
    if (isSearchField(anchor)) return; // search bars: never touch, never query
    // Our own UI is not a page field: the dropdown filter input lives in
    // the page DOM — focusing it must NEVER trigger a re-query, or the
    // autofocus → focusin → replace → autofocus cycle flickers forever.
    try {
      if (anchor instanceof HTMLInputElement && dropEl && dropEl.contains(anchor)) return;
      if (anchor instanceof HTMLInputElement && anchor.closest("#__pv_saver")) return;
    } catch (_) {}
    // One query per anchor at a time + never rebuild an open dropdown on
    // the same anchor (Instagram refocus-storms fields; each storm used to
    // close+re-query with a ~1s empty gap).
    if (suggestBusy === anchor) return;
    if (dropEl && dropAnchor === anchor) return;
    suggestBusy = anchor;
    const gen = suggestGen;
    try {
      if (!(await requireExtPin())) return;
      const rows = await resolveRows(anchor, findFields());
      if (gen !== suggestGen) return; // picked/closed meanwhile: stale
      if (rows) showDrop(anchor, rows);
    } catch (err) {
      // Passive path stays quiet, except an explicit timeout (locked vault /
      // dead host) which gets one discoverable hint — popup explains the rest.
      if (err && String(err.message || "").includes("timed out")) {
        toast("🔒 Vault unreachable — open the popup to reconnect.");
      }
    }
    finally {
      if (suggestBusy === anchor) suggestBusy = null;
    }
  }
  // Smart badge click: exactly 1 match fills IMMEDIATELY; several toggle the
  // dropdown (open ↔ close) with zero flicker; zero matches says so quietly.
  async function badgeFill(field) {
    if (isBlocked() || phishingRefuse() || !location.host) return;
    if (dropEl && dropAnchor === field) { closeDrop("toggle"); return; }
    if (!(await requireExtPin())) return;
    const gen = suggestGen;
    try {
      const rows = await resolveRows(field, findFields());
      if (gen !== suggestGen) return; // closed meanwhile: stale
      if (!rows || !rows.length) { toast("🛡️ No matching credential — open the popup to save this login."); return; }
      if (rows.length === 1) { rows[0].onPick(); return; }
      showDrop(field, rows);
    } catch (_) { /* bridge down: stay silent, popup explains */ }
  }
  // Password-change context: one shield must serve BOTH intents, so clicking
  // it opens fill rows plus a generate row (instead of a second dice icon).
  // No saved logins ⇒ generating is the only useful action, do it directly.
  async function badgeActionMenu(field) {
    if (isBlocked() || phishingRefuse() || !location.host) return;
    if (dropEl && dropAnchor === field) { closeDrop("toggle"); return; }
    if (!(await requireExtPin())) return;
    const gen = suggestGen;
    try {
      const f = findFields();
      const group = badgeGroup(field);
      const target = f.newPass.find((x) => isVisible(x) && badgeGroup(x) === group) || field;
      const rows = await resolveRows(field, f);
      if (gen !== suggestGen) return; // closed meanwhile: stale
      const genRow = {
        action: true,
        glyph: "🎲",
        title: "Generate strong password",
        sub: "Fill new password + confirmation",
        onPick: () => generateInto(target),
      };
      if (!rows || !rows.length) { genRow.onPick(); return; }
      showDrop(field, [genRow, ...rows]);
    } catch (_) { /* bridge down: stay silent */ }
  }
  document.addEventListener("focusin", (e) => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement) || !isVisible(el)) return;
    if (isSearchField(el)) return; // YouTube/Google/Amazon search: stay blind
    // Bitwarden parity: when icon-click-only mode is on, passive focus NEVER
    // opens the dropdown — the shield badge is the only trigger.
    if (settings.show_suggestions_on_icon_click_only) return;
    if (isOtpField(el)) { suggestOtpFor(el); return; }
    suggestFor(el);
  });

  // ---------- badge (in-field shield) + generator dice ----------
  // Right-side overlay: position:fixed from the input's viewport rect, so it
  // can never be crushed by inline layout or clipped by a left border.
  // Repositioned on scroll/resize/DOM churn (see scan() tail).
  const BADGE_SIZE = 28;
  const badges = new Map(); // button -> field
  function badgeRightOffset(field) {
    // Native reveal/caps-lock icons, site eye-toggles, sibling manager
    // badges: if anything live sits at the field's right edge, dock further
    // left so icons never collide.
    try {
      const r = field.getBoundingClientRect();
      const el = document.elementFromPoint(r.right - 6, r.top + r.height / 2);
      if (el && el !== field && !badges.has(el) && !(el.dataset && el.dataset.pvBadged)) return 34;
    } catch (_) {}
    return 10;
  }
  function positionBadge(b, field) {
    if (!isVisible(field)) { b.style.display = "none"; return; }
    b.style.display = "flex";
    const r = field.getBoundingClientRect();
    const off = badgeRightOffset(field);
    b.style.left = Math.max(0, r.right - BADGE_SIZE - off) + "px";
    b.style.top = Math.max(0, r.top + (r.height - BADGE_SIZE) / 2) + "px";
  }
  function repositionBadges() {
    for (const [b, field] of badges) {
      if (!field.isConnected) { b.remove(); badges.delete(b); continue; }
      positionBadge(b, field);
    }
  }
  function placeBadge(field, withGen) {
    if (field.dataset.pvBadged) return;
    field.dataset.pvBadged = "1";
    const b = document.createElement("button");
    b.type = "button";
    b.dataset.pvKind = "shield";
    b.dataset.pvGen = withGen ? "1" : "0";
    b.title = withGen
      ? "Fill a saved login or generate a new password (PhantomVault)"
      : "Fill with PhantomVault";
    b.textContent = "🛡️";
    b.style.cssText = "position:fixed;z-index:2147483647;width:28px;height:28px;" +
      "display:flex;align-items:center;justify-content:center;" +
      "border:1px solid #8b7cf6;border-radius:8px;background:#0d131fee;cursor:pointer;font-size:14px;padding:0;";
    // mousedown first: preventDefault keeps input focus (no blur flicker),
    // then click smart-fills (1 match) or toggles the dropdown (several).
    // pointerdown CAPTURE is the real modal-killer fix: overlay "click
    // outside to close" handlers (bubble or document-level) must never see
    // our badge — it lives at document root, outside their modal container.
    // preventDefault also blocks focus theft (no blur-close either).
    b.addEventListener("pointerdown", (e) => { e.preventDefault(); e.stopPropagation(); }, true);
    b.addEventListener("mousedown", (e) => { e.preventDefault(); e.stopPropagation(); }, true);
    b.addEventListener("click", async (ev) => {
      ev.preventDefault(); ev.stopPropagation();
      if (b.dataset.pvGen === "1") await badgeActionMenu(field);
      else await badgeFill(field);
    });
    document.documentElement.appendChild(b);
    badges.set(b, field);
    positionBadge(b, field);
  }
  function genPassword(len = 20) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_+=";
    const buf = new Uint32Array(len);
    crypto.getRandomValues(buf);
    return [...buf].map((x) => chars[x % chars.length]).join("");
  }
  // Shared generator core: fills the target + its visible confirmation
  // sibling, copies with auto-clear, and prompts to save. Used by the 🎲
  // dice badge AND the right-click "Generate Password Here" menu.
  function generateInto(field) {
    if (!field || !isVisible(field)) return false;
    const pw = genPassword();
    setNativeValue(field, pw);
    const form = field.form;
    if (form) {
      // Only fill a NEW/confirm password sibling. On a change-password form
      // the first other password is the CURRENT one - filling it with the
      // generated value would corrupt the very credential being rotated.
      const others = [...form.querySelectorAll('input[type="password"]')]
        .filter((x) => x !== field && isVisible(x) && isNewPasswordField(x));
      const confirm = others.find((x) => /confirm|repeat|verify|again/i.test(
        ((x.name || "") + " " + (x.id || "")).toLowerCase())) || others[0];
      if (confirm) setNativeValue(confirm, pw);
    }
    copyWithAutoclear(pw);
    toast("🎲 Strong password filled + copied — save it in PhantomVault!");
    return true;
  }
  function placeDice(field) {
    if (field.dataset.pvDice) return;
    field.dataset.pvDice = "1";
    const b = document.createElement("button");
    b.type = "button";
    b.dataset.pvKind = "dice";
    b.title = "Generate strong password (PhantomVault)";
    b.textContent = "🎲";
    b.style.cssText = "position:fixed;z-index:2147483647;width:24px;height:24px;" +
      "display:flex;align-items:center;justify-content:center;" +
      "border:1px solid #10b981;border-radius:8px;background:#0d131fee;cursor:pointer;font-size:13px;padding:0;";
    b.addEventListener("mousedown", (e) => { e.preventDefault(); e.stopPropagation(); }, true);
    b.addEventListener("pointerdown", (e) => { e.preventDefault(); e.stopPropagation(); }, true);
    b.addEventListener("click", async (ev) => {
      ev.preventDefault(); ev.stopPropagation();
      if (!(await requireExtPin())) return;
      generateInto(field);
    });
    document.documentElement.appendChild(b);
    badges.set(b, field);
    positionBadge(b, field);
  }

  // ---------- zero-click load + multi-step chaining ----------
  async function autofillOnLoad() {
    if (!settings.autofill_on_load || isBlocked() || phishingRefuse()) return;
    if (!location.host) return;
    if (!(await requireExtPin())) return;
    try {
      const logins = await queryHost("PV_QUERY", pageBase());
      console.log(`PV autofill-on-load: ${logins.length} login(s) for ${pageBase()}`);
      if (logins.length !== 1) {
        // Multi-step: a pending entry from step 1 + password field now visible?
        await chainPendingStep();
        return;
      }
      const f = findFields();
      console.log(`PV fields: users=${f.users.length} pass=${f.pass.length} newPass=${f.newPass.length}`);
      if ((f.users[0] || f.pass[0]) && (logins[0].username || logins[0].password)) {
        fillLogin(logins[0], f);
      } else {
        console.log("PV autofill-on-load: no fillable field on this page");
      }
    } catch (_) {}
  }
  async function chainPendingStep() {
    const pending = pvPending;
    if (!pending) return;
    const f = findFields();
    if (f.pass[0] && pending.password) {
      setNativeValue(f.pass[0], pending.password);
      // The OTP half of the chain no longer replays a stored code. Resolve the
      // pinned account through the ranked lookup instead, so this path gets the
      // native freshness guard and the sidecar stamp like every other fill.
      if (settings.auto_inject_totp && pending.totpId) {
        const r = await resolveOtpCode();
        if (r.code) {
          fillTotpNow(r.code, findFields());
          if (r.id) pingFilled(r.id);
        } else if (r.expired && r.wait != null) {
          toast(`⏳ নতুন code আসতে বাকি ${r.wait}s`);
        }
      }
      pvPendingClear();
    }
  }
  // OTP fields that render late (SPA step 3): inject live TOTP on sight.
  // Runs once at boot too — direct 2FA URLs render the field before any
  // mutation fires, which used to leave the observer permanently silent.
  let otpDiagAt = 0;
  // Decide what (if anything) may be auto-filled on this page.
  //
  // A step-1 fill pins WHICH account the ceremony belongs to (`pvPending.totpId`),
  // but that pin resolves to a candidate, never to a stored code. The stash used
  // to hand back its own cached `totp` string, which meant a code minted at step
  // 1 could still be injected minutes later on step 3 — past the 3s guard, past
  // its window, and with no way to notice. Re-querying by id keeps the native
  // freshness guard and the sidecar stamp on this path too.
  async function resolveOtpCode() {
    const list = await totpCandidates();
    if (!list.length) return { code: "" };
    // Pinned identity wins the ambiguity check (a known id is not a guess), but
    // only while it is still among this site's ranked candidates.
    const pinnedId = pvPending && pvPending.totpId;
    const top = (pinnedId && list.find((c) => c.id === pinnedId)) || null;
    if (top) {
      if (!top.code) {
        return { code: "", candidates: [top], expired: true, wait: top.next_in };
      }
      return { code: top.code, source: "pinned", id: top.id, expiresIn: top.expires_in };
    }
    // Invariant: no blind guessing. More than one candidate, or any of them
    // colliding on (issuer, account), means the user picks — a wrong code
    // reads as "my authenticator is broken" and can lock the account out.
    const ambiguous = list.length > 1 || list.some((c) => c.is_dup);
    if (ambiguous) return { code: "", candidates: list, ambiguous: true };
    if (!list[0].code) {
      // Withheld by the native expiry guard: say when to retry rather than
      // filling null and reporting a bridge failure.
      return { code: "", candidates: list, expired: true, wait: list[0].next_in };
    }
    return { code: list[0].code, source: "ranked", id: list[0].id, expiresIn: list[0].expires_in };
  }
  // The sweep is passive (mutation-driven); the picker is not. Only an
  // explicit user gesture — focus inside the code box — or a pinned account
  // from step 1 justifies covering the page with a menu.
  function otpSweepMayPrompt(f) {
    if (pvPending && pvPending.totpId) return true;
    const box = f && f.otp && f.otp[0];
    if (!box) return false;
    const active = document.activeElement;
    if (!active) return false;
    if (active === box || box.contains(active)) return true;
    // Split code screen: the user is in a sibling box of the same OTP group.
    return active.tagName === "INPUT" && isOtpField(active);
  }
  function sweepOtpOnce() {
    sweepOtpAsync().catch(() => {});
  }  async function sweepOtpAsync() {
    try {
      if (!settings.auto_inject_totp || isBlocked()) {
        if (Date.now() - otpDiagAt > 5000) {
          otpDiagAt = Date.now();
          console.log(`PV OTP sweep skip: auto=${!!settings.auto_inject_totp} blocked=${isBlocked()}`);
        }
        return;
      }
      const f = findFields();
      if (!f.otp.length || f.otp[0].dataset.pvOtpFilled) {
        // No OTP box on this screen any more (SPA route change, 2FA already
        // done, or a sighting that turned out false): take the picker down with
        // it. The host lives on documentElement, not inside the field, so a
        // bare `return` here would leave it floating over an unrelated page.
        if (!f.otp.length && pvPicker) closeOtpPicker(false);
        if (!f.otp.length && Date.now() - otpDiagAt > 5000) {
          otpDiagAt = Date.now();
          const all = [...document.querySelectorAll("input")].filter(isVisible);
          const desc = all.map((el) => {
            const lab = (el.labels && el.labels[0] && (el.labels[0].innerText || "").trim().slice(0, 40)) || "";
            return `${el.type || "?"}#${el.id || "-"}[${el.name || "-"}|ac=${el.autocomplete || "-"}|lab=${lab || "-"}]`;
          });
          console.log(`PV OTP sweep: ${all.length} visible input(s), 0 OTP. Fields: ${desc.join(" ; ")}`);
        }
        return;
      }
      const pinnedId = (pvPending && pvPending.totpId) || "";
      console.log(`PV OTP field sighted (${f.otp.length}), pinned: ${pinnedId || "none"}`);
      const r = await resolveOtpCode();
      if (r.ambiguous) {
        // Several accounts for this site: the picker opens right here under
        // the OTP box (login-dropdown parity). The popup Fill-2FA path is
        // unchanged and still works as a fallback.
        if (settings.show_suggestions) {
          // Already showing the picker for this site? Say nothing — the sweep
          // fires on every mutation and a live picker must not re-toast or
          // rebuild. Re-open a dead handle (page re-render), but never re-pop
          // one the user just dismissed — focus/badge is the way back.
          if (otpPickerLive() || otpPickerUserClosed) return;
          // Bitwarden parity: a passive page scan never opens the account
          // menu by itself. It opens only when the user is IN the code box
          // (focus is explicit intent) or when step 1 already pinned WHICH
          // account this ceremony belongs to. Without this gate the sweep
          // re-opened the picker on every unrelated mutation anywhere on the
          // page, and a merely *suspected* OTP field could summon it.
          if (!otpSweepMayPrompt(f)) {
            console.log(`PV OTP: ${r.candidates.length} candidates, no focus/pin — picker stays closed`);
            return;
          }
          console.log(`PV OTP picker open on #${f.otp[0].id || "-"}[${f.otp[0].name || "-"}], focus=${document.activeElement === f.otp[0]}, pinned=${pinnedId || "none"}`);
          openOtpPicker(r.candidates || [], f);
          return;
        }
        toast("🔐 একাধিক 2FA account — popup থেকে বেছে নিন।");
        console.log(`PV OTP: ${r.candidates.length} candidates, no blind auto-fill`);
        return;
      }
      if (r.expired) {
        const w = r.wait != null ? ` (${r.wait}s)` : "";
        toast(`⏳ নতুন code আসতে বাকি${w} — একটু পরে আবার চাপুন।`);
        return;
      }
      if (r.code) {
        f.otp[0].dataset.pvOtpFilled = "1";
        fillTotpNow(r.code, findFields());
        if (r.id) pingFilled(r.id);
        pvPendingClear();
        toast("⚡ 2FA code auto-filled");
      } else {
        console.log("PV OTP: no ranked candidate for this page");
      }
    } catch (_) {}
  }
  const otpObserver = new MutationObserver(() => sweepOtpOnce());
  // NOTE: observe() is inherently duplicate-safe (same args re-target).
  function armOtpObserver() {
    try {
      otpObserver.observe(document.documentElement, { childList: true, subtree: true });
    } catch (_) {}
    sweepOtpOnce();
  }

  async function hotkeyFill() {
    if (isBlocked() || phishingRefuse() || !location.host) return;
    if (!(await requireExtPin())) return;
    const f = findFields();
    try {
      if (f.cards[0] && settings.suggest_cards) {
        const cards = await queryCards();
        if (cards[0]) { fillCard(cards[0]); return; }
      }
      const logins = await queryHost("PV_QUERY", pageBase());
      const best = rankLogins(logins, carriedUserFor(f))[0];
      if (best) fillLogin(best, f);
      else toast("🛡️ No matching credential for this site.");
    } catch (e) {
      toast("⚠️ " + (e.message || "bridge failed"));
    }
  }

  // Zero false-positive badges: email/username fields get a badge ONLY when
  // (a) the vault actually holds credentials for this domain, OR (b) a
  // password field is present (login/registration forms). Newsletter /
  // contact / profile forms (no match + no password) stay badge-free.
  // Probe runs once per page; while unknown (locked/bridge fail) we fall
  // back to rule (b) so login pages never lose their badge.
  // 0 = unknown, 1 = match, -1 = confirmed none.
  let pageMatchState = 0;
  let pageMatchProbed = false;
  // Anchor with an in-flight suggest query (storm guard, see suggestFor).
  let suggestBusy = null;
  // Generation counter: any close/pick invalidates in-flight queries, so a
  // slow bridge response resolving AFTER a pick can never resurrect the
  // dropdown over the page's Next/Submit buttons.
  let suggestGen = 0;
  function probePageMatch() {
    if (pageMatchProbed) return;
    pageMatchProbed = true;
    (async () => {
      try {
        if (isBlocked() || phishingRefuse() || !location.host) return;
        const logins = await queryHost("PV_QUERY", pageBase());
        pageMatchState = (logins && logins.length) ? 1 : -1;
        scan(); // reconcile: confirmed match adds username icons, -1 removes them
        console.log(`PV badge gate: ${pageMatchState === 1 ? "match" : "no match"} for ${pageBase()}`);
      } catch (_) {}
    })();
  }
  // One credential context = one icon. A login form used to get a shield on
  // the username AND another on the password (plus a dice on every
  // new-password box), carpeting pages with icons. Group by <form>, or - for
  // form-less SPA logins - by the nearest ancestor that holds a password.
  function badgeGroup(el) {
    if (el.form) return el.form;
    let p = el.parentElement;
    while (p && p !== document.body && p !== document.documentElement) {
      const fields = p.querySelectorAll("input, select, textarea").length;
      if (fields >= 2 && [...p.querySelectorAll('input[type="password"]')].some(isVisible)) {
        return p;
      }
      p = p.parentElement;
    }
    return document.documentElement;
  }
  // Desired icon per context:
  //   password only            -> shield (fill saved login)
  //   password + new/confirm   -> shield with fill-or-generate menu
  //   new/confirm only         -> dice (generate + fill confirmation)
  //   username only + match    -> shield
  //   card                     -> its own shield (fill card is another action)
  // Reconciled on every scan (not appended): SPA transitions fold a username
  // shield into the password shield, flip shield<->dice, and drop icons for
  // removed/hidden groups without leaving duplicates behind.
  function scan() {
    if (isBlocked()) return;
    const f = findFields();
    probePageMatch();

    const groups = new Map();
    const groupFor = (el) => {
      const key = badgeGroup(el);
      let g = groups.get(key);
      if (!g) { g = { users: [], pass: [], newPass: [], cards: [] }; groups.set(key, g); }
      return g;
    };
    for (const el of f.users) if (isVisible(el)) groupFor(el).users.push(el);
    for (const el of f.pass) if (isVisible(el)) groupFor(el).pass.push(el);
    for (const el of f.newPass) if (isVisible(el)) groupFor(el).newPass.push(el);
    for (const el of f.cards) if (isVisible(el)) groupFor(el).cards.push(el);

    const want = new Map(); // field -> { kind: "shield"|"dice", gen: bool }
    for (const g of groups.values()) {
      if (g.cards.length && settings.suggest_cards) {
        want.set(g.cards[0], { kind: "shield", gen: false });
      }
      if (g.pass.length) {
        want.set(g.pass[0], { kind: "shield", gen: g.newPass.length > 0 });
      } else if (g.newPass.length) {
        want.set(g.newPass[0], { kind: "dice", gen: false });
      } else if (g.users.length && !g.cards.length && pageMatchState === 1) {
        // Standalone email/username: only on a credential-step page with a
        // known match (never newsletters or checkout billing emails).
        const user = g.users.find(loginContextFor);
        if (user) want.set(user, { kind: "shield", gen: false });
      }
    }
    // Warm the global card list only on checkout-shaped pages (never ship
    // PAN/CVV to every content script), once per frame/document.
    if (f.cards.length && !pvCardsWarmTried) {
      pvCardsWarmTried = true;
      getCards().catch(() => {});
    }

    for (const [b, field] of [...badges]) {
      const w = want.get(field);
      const kind = b.dataset.pvKind || "shield";
      const gen = b.dataset.pvGen === "1";
      if (!w || w.kind !== kind || !!w.gen !== gen) {
        b.remove();
        badges.delete(b);
        delete field.dataset.pvBadged;
        delete field.dataset.pvDice;
      }
    }
    const have = new Set(badges.values());
    for (const [field, w] of want) {
      if (have.has(field)) continue;
      if (w.kind === "dice") placeDice(field);
      else placeBadge(field, w.gen);
    }
    repositionBadges();
  }

  // ---------- auto-save: offer to store freshly submitted credentials ----------
  // Submitted-credential classifier (duplicate-guard pattern, bridge mirror):
  // "known" (same user+password — silent), {update} (same user, NEW
  // password — "Update existing?"), or "new" (unknown user — save prompt).
  // Username match is case-insensitive; password compare is exact.
  function classifySubmitted(existing, username, password) {
    const u = (username || "").toLowerCase();
    for (const e of existing || []) {
      if (((e.username || "").toLowerCase()) !== u) continue;
      if (e.password === password) return "known";
      return { update: e };
    }
    return "new";
  }
  function saverToast(username, password) {
    if (document.getElementById("__pv_saver")) return;
    const box = document.createElement("div");
    box.id = "__pv_saver";
    box.style.cssText = "position:fixed;bottom:16px;right:16px;z-index:2147483647;" +
      "background:#0d131f;border:1px solid #8b7cf6;border-radius:12px;padding:12px 14px;" +
      "font:13px system-ui;color:#eef1ff;box-shadow:0 12px 40px #000d;max-width:min(92vw,320px);";
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
    const dismissSave = () => { document.removeEventListener("keydown", escSave, true); box.remove(); };
    const escSave = (e) => { if (e.key === "Escape") { e.stopPropagation(); dismissSave(); } };
    document.addEventListener("keydown", escSave, true);
    no.addEventListener("click", dismissSave);
    setTimeout(dismissSave, 30000);
    save.focus();
    save.addEventListener("click", async () => {
      save.textContent = "⏳ Saving…";
      try {
        const res = await chrome.runtime.sendMessage({
          type: "PV_SAVE_LOGIN",
          username, password,
          url: captureUrl(),
          title: captureTitle(),
        });
        if (res && res.ok) {
          toast(res.updated ? "✅ Login updated in PhantomVault." : "✅ Login saved to PhantomVault.");
          pvCarryClear();
          pvExistingCache = null; // next prompt re-reads the fresh vault
          dismissSave();
        } else {
          save.textContent = "⚠️ " + ((res && res.error) || "failed");
        }
      } catch (_) {
        save.textContent = "⚠️ Bridge unreachable";
      }
    });
  }
  // Update prompt: same username, different password on a known site.
  // "Update" reuses the bridge upsert (PV_SAVE_LOGIN matches username +
  // domain → rotates into history, returns updated:true). Never auto-saves:
  // explicit click only, Not Now + 30s auto-dismiss like the save prompt.
  function updateToast(username, password) {
    if (document.getElementById("__pv_saver")) return;
    const box = document.createElement("div");
    box.id = "__pv_saver";
    box.style.cssText = "position:fixed;bottom:16px;right:16px;z-index:2147483647;" +
      "background:#0d131f;border:1px solid #fbbf24;border-radius:12px;padding:12px 14px;" +
      "font:13px system-ui;color:#eef1ff;box-shadow:0 12px 40px #000d;max-width:min(92vw,320px);";
    const t = document.createElement("div");
    t.style.cssText = "font-weight:700;margin-bottom:8px;";
    t.textContent = "🔄 Update existing?";
    const sub = document.createElement("div");
    sub.style.cssText = "color:#8e99c0;font-size:11px;margin-bottom:10px;";
    sub.textContent = `New password submitted for ${username} on ${pageBase()} — replace the stored one? (old kept in history)`;
    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:8px;";
    const save = document.createElement("button");
    save.textContent = "🔄 Update";
    save.style.cssText = "flex:1;background:#fbbf24;color:#080c14;border:0;border-radius:8px;padding:8px;font-weight:700;cursor:pointer;";
    const no = document.createElement("button");
    no.textContent = "✕ Not Now";
    no.style.cssText = "flex:1;background:#1a2450;color:#fff;border:1px solid #26315c;border-radius:8px;padding:8px;cursor:pointer;";
    row.append(save, no);
    box.append(t, sub, row);
    document.documentElement.append(box);
    const dismissUpd = () => { document.removeEventListener("keydown", escUpd, true); box.remove(); };
    const escUpd = (e) => { if (e.key === "Escape") { e.stopPropagation(); dismissUpd(); } };
    document.addEventListener("keydown", escUpd, true);
    no.addEventListener("click", dismissUpd);
    setTimeout(dismissUpd, 30000);
    save.focus();
    save.addEventListener("click", async () => {
      save.textContent = "⏳ Updating…";
      try {
        const res = await chrome.runtime.sendMessage({
          type: "PV_SAVE_LOGIN",
          username, password,
          url: captureUrl(),
          title: captureTitle(),
        });
        if (res && res.ok) {
          toast("✅ Login updated in PhantomVault (old kept in history).");
          pvCarryClear();
          pvExistingCache = null; // next prompt re-reads the fresh vault
          dismissUpd();
        } else {
          save.textContent = "⚠️ " + ((res && res.error) || "failed");
        }
      } catch (_) {
        save.textContent = "⚠️ Bridge unreachable";
      }
    });
  }
  // C1: a warm credential-list cache lets the submit handler decide + prompt
  // WITHOUT an await, so a full-page POST navigation can no longer unload the
  // document before the save banner shows. Warmed at boot; 60s TTL.
  let pvExistingCache = null;
  let pvExistingInflight = null;
  const PV_EXIST_CACHE_MS = 60000;
  async function getExisting(base) {
    const now = Date.now();
    if (pvExistingCache && pvExistingCache.base === base &&
        now - pvExistingCache.at < PV_EXIST_CACHE_MS) {
      return pvExistingCache.list;
    }
    // Share one in-flight query: boot warms this from both the badge probe and
    // the explicit warm call, and a duplicate host round-trip is pointless.
    if (pvExistingInflight && pvExistingInflight.base === base) {
      return pvExistingInflight.p;
    }
    const p = queryHost("PV_QUERY", base).then((list) => {
      pvExistingCache = { base, list: list || [], at: Date.now() };
      pvExistingInflight = null;
      return pvExistingCache.list;
    }).catch((e) => {
      pvExistingInflight = null;
      throw e;
    });
    pvExistingInflight = { base, p };
    return p;
  }
  function existingSync(base) {
    return (pvExistingCache && pvExistingCache.base === base) ? pvExistingCache.list : null;
  }
  function offerSave(verdict, username, password) {
    if (!verdict || verdict === "known") return;
    if (verdict !== "new") updateToast(username, password);
    else saverToast(username, password);
  }

  // ---------- card save: prompt + dedup ----------
  // Cards are global (not URL-bound), so one warm list also tells us whether
  // the submitted PAN is already stored (silent), needs an update, or is new.
  let pvCardCache = null;
  let pvCardInflight = null;
  let pvCardsWarmTried = false;
  let cardOfferedFor = "";
  async function getCards() {
    if (pvCardCache) return pvCardCache;
    if (pvCardInflight) return pvCardInflight;
    const p = queryCards().then((list) => {
      pvCardCache = list || [];
      pvCardInflight = null;
      return pvCardCache;
    }).catch((e) => {
      pvCardInflight = null;
      throw e;
    });
    pvCardInflight = p;
    return p;
  }
  function cardsSync() { return pvCardCache; }
  function sameCard(a, card) {
    return digitsOf(a && a.number) === digitsOf(card.number)
      && String(a.exp_month || "") === card.exp_month
      && String(a.exp_year || "") === card.exp_year
      // A blank CVV on the page (saved-card checkout) must not force an
      // Update prompt on every submit: only compare when one was typed.
      && (!card.cvv || String(a.cvv || "") === card.cvv);
  }
  function offerCardSave(card) {
    if (!card) return;
    const pan = digitsOf(card.number);
    if (!pan) return;
    // Include expiry/CVV so a corrected retry on the same page can prompt.
    const fp = [pan, card.exp_month, card.exp_year, card.cvv || ""].join("|");
    if (cardOfferedFor === fp) return;
    cardOfferedFor = fp;
    const cached = cardsSync();
    if (cached) {
      const existing = cached.find((k) => digitsOf(k && k.number) === pan);
      if (existing && sameCard(existing, card)) return;
      cardSaverToast(card, !!existing);
      return;
    }
    // C1 parity: warm on boot so a normal submit can prompt synchronously
    // before navigation; this branch only covers a cold first submit.
    getCards().then((list) => {
      const existing = (list || []).find((k) => digitsOf(k && k.number) === pan);
      if (existing && sameCard(existing, card)) return;
      cardSaverToast(card, !!existing);
    }).catch(() => {}); // locked/bridge down: a save click would fail anyway
  }
  function cardSaverToast(card, updated) {
    if (document.getElementById("__pv_saver")) return;
    const brand = cardBrand(card.number);
    const box = document.createElement("div");
    box.id = "__pv_saver";
    box.style.cssText = "position:fixed;bottom:16px;right:16px;z-index:2147483647;" +
      "background:#0d131f;border:1px solid #10b981;border-radius:12px;padding:12px 14px;" +
      "font:13px system-ui;color:#eef1ff;box-shadow:0 12px 40px #000d;max-width:min(92vw,320px);";
    const t = document.createElement("div");
    t.style.cssText = "font-weight:700;margin-bottom:8px;";
    t.textContent = updated ? "🔄 Update card in PhantomVault?" : "🛡️ Save card to PhantomVault?";
    const sub = document.createElement("div");
    sub.style.cssText = "color:#8e99c0;font-size:11px;margin-bottom:10px;";
    sub.textContent = [brand || "Card", masked(card.number), card.cardholder]
      .filter(Boolean).join(" · ") + " — store it encrypted.";
    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:8px;";
    const save = document.createElement("button");
    save.textContent = updated ? "🔄 Update" : "💾 Save";
    save.style.cssText = "flex:1;background:#10b981;color:#04110b;border:0;border-radius:8px;padding:8px;font-weight:700;cursor:pointer;";
    const no = document.createElement("button");
    no.textContent = "✕ Not Now";
    no.style.cssText = "flex:1;background:#1a2450;color:#fff;border:1px solid #26315c;border-radius:8px;padding:8px;cursor:pointer;";
    row.append(save, no);
    box.append(t, sub, row);
    document.documentElement.append(box);
    const dismissCard = () => { document.removeEventListener("keydown", escCard, true); box.remove(); };
    const escCard = (e) => { if (e.key === "Escape") { e.stopPropagation(); dismissCard(); } };
    document.addEventListener("keydown", escCard, true);
    no.addEventListener("click", dismissCard);
    setTimeout(dismissCard, 30000);
    save.focus();
    save.addEventListener("click", async () => {
      save.textContent = "⏳ Saving…";
      try {
        const res = await chrome.runtime.sendMessage({
          type: "PV_SAVE_CARD",
          number: card.number,
          cardholder: card.cardholder || "",
          exp_month: card.exp_month,
          exp_year: card.exp_year,
          cvv: card.cvv || "",
          url: captureUrl(),
          title: captureTitle(),
        });
        if (res && res.ok) {
          toast(res.updated ? "✅ Card updated in PhantomVault." : "✅ Card saved to PhantomVault.");
          pvCardCache = null; // next prompt re-reads the fresh card list
          dismissCard();
        } else {
          save.textContent = "⚠️ " + ((res && res.error) || "failed");
        }
      } catch (_) {
        save.textContent = "⚠️ Bridge unreachable";
      }
    });
  }
  // ---------- identity save: prompt + dedup ----------
  // Identities are global (like cards) but they are PII, so the list is only
  // fetched when an identity dropdown opens or a form is submitted — never
  // pre-warmed on every page.
  let pvIdentityCache = null;
  let pvIdentityInflight = null;
  let identityOfferedFor = "";
  async function getIdentities() {
    if (pvIdentityCache) return pvIdentityCache;
    if (pvIdentityInflight) return pvIdentityInflight;
    const p = queryIdentities().then((list) => {
      pvIdentityCache = list || [];
      pvIdentityInflight = null;
      return pvIdentityCache;
    }).catch((e) => {
      pvIdentityInflight = null;
      throw e;
    });
    pvIdentityInflight = p;
    return p;
  }
  function identitiesSync() { return pvIdentityCache; }
  const idNorm = (s) => String(s == null ? "" : s).trim().toLowerCase();
  function sameIdentity(a, b) {
    if (!a) return false;
    if (idNorm(b.email)) return idNorm(a.email) === idNorm(b.email);
    if (idNorm(b.address)) {
      return idNorm(a.full_name) === idNorm(b.full_name) && idNorm(a.address) === idNorm(b.address);
    }
    return idNorm(a.full_name) === idNorm(b.full_name) && idNorm(a.phone) === idNorm(b.phone);
  }
  function identityChanged(a, b) {
    return (!!b.full_name && idNorm(a.full_name) !== idNorm(b.full_name))
      || (!!b.email && idNorm(a.email) !== idNorm(b.email))
      || (!!b.phone && idNorm(a.phone) !== idNorm(b.phone))
      || (!!b.address && idNorm(a.address) !== idNorm(b.address));
  }
  function offerIdentitySave(idf) {
    if (!idf) return;
    const fp = [idf.full_name, idf.email, idf.phone, idf.address].join("|").toLowerCase();
    if (identityOfferedFor === fp) return;
    identityOfferedFor = fp;
    const cached = identitiesSync();
    if (cached) {
      const existing = cached.find((i) => sameIdentity(i, idf));
      if (existing && !identityChanged(existing, idf)) return;
      identitySaverToast(idf, !!existing);
      return;
    }
    getIdentities().then((list) => {
      const existing = (list || []).find((i) => sameIdentity(i, idf));
      if (existing && !identityChanged(existing, idf)) return;
      identitySaverToast(idf, !!existing);
    }).catch(() => {}); // locked/bridge down: a save click would fail anyway
  }
  function identitySaverToast(idf, updated) {
    if (document.getElementById("__pv_saver")) return;
    const box = document.createElement("div");
    box.id = "__pv_saver";
    box.style.cssText = "position:fixed;bottom:16px;right:16px;z-index:2147483647;" +
      "background:#0d131f;border:1px solid #38e1ff;border-radius:12px;padding:12px 14px;" +
      "font:13px system-ui;color:#eef1ff;box-shadow:0 12px 40px #000d;max-width:min(92vw,320px);";
    const t = document.createElement("div");
    t.style.cssText = "font-weight:700;margin-bottom:8px;";
    t.textContent = updated ? "🔄 Update identity in PhantomVault?" : "🛡️ Save identity to PhantomVault?";
    const sub = document.createElement("div");
    sub.style.cssText = "color:#8e99c0;font-size:11px;margin-bottom:10px;";
    sub.textContent = [idf.full_name, idf.email || idf.phone || idf.address]
      .filter(Boolean).join(" · ") + " — store it encrypted.";
    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:8px;";
    const save = document.createElement("button");
    save.textContent = updated ? "🔄 Update" : "💾 Save";
    save.style.cssText = "flex:1;background:#38e1ff;color:#02131a;border:0;border-radius:8px;padding:8px;font-weight:700;cursor:pointer;";
    const no = document.createElement("button");
    no.textContent = "✕ Not Now";
    no.style.cssText = "flex:1;background:#1a2450;color:#fff;border:1px solid #26315c;border-radius:8px;padding:8px;cursor:pointer;";
    row.append(save, no);
    box.append(t, sub, row);
    document.documentElement.append(box);
    const dismissId = () => { document.removeEventListener("keydown", escId, true); box.remove(); };
    const escId = (e) => { if (e.key === "Escape") { e.stopPropagation(); dismissId(); } };
    document.addEventListener("keydown", escId, true);
    no.addEventListener("click", dismissId);
    setTimeout(dismissId, 30000);
    save.focus();
    save.addEventListener("click", async () => {
      save.textContent = "⏳ Saving…";
      try {
        const res = await chrome.runtime.sendMessage({
          type: "PV_SAVE_IDENTITY",
          full_name: idf.full_name || "",
          email: idf.email || "",
          phone: idf.phone || "",
          address: idf.address || "",
          url: captureUrl(),
          title: captureTitle(),
        });
        if (res && res.ok) {
          toast(res.updated ? "✅ Identity updated in PhantomVault." : "✅ Identity saved to PhantomVault.");
          pvIdentityCache = null; // next prompt re-reads the fresh identity list
          dismissId();
        } else {
          save.textContent = "⚠️ " + ((res && res.error) || "failed");
        }
      } catch (_) {
        save.textContent = "⚠️ Bridge unreachable";
      }
    });
  }
  // G3: form-scoped credential reader. Distinguishes signup (new-password or a
  // confirm field) from login, refuses to offer on a confirm-password mismatch
  // (a typo), and picks the "old" field on a change-password form.
  function readFormCreds(form) {
    const cands = [...form.querySelectorAll('input[type="text"], input[type="email"]')]
      .filter((el) => !isSearchField(el) && isVisible(el));
    const score = (el) => {
      const t = (el.type || "").toLowerCase();
      const ac = (el.autocomplete || "").toLowerCase();
      const ni = ((el.name || "") + " " + (el.id || "")).toLowerCase();
      if (t === "email" || ac === "email" || ac === "username") return 3;
      if (/email|user(name)?|login|account/.test(ni)) return 2;
      if (/first|last|fname|lname|full.?name|name/.test(ni)) return 0;
      return 1;
    };
    cands.sort((a, b) => score(b) - score(a));
    const pws = [...form.querySelectorAll('input[type="password"]')].filter(isVisible);
    let password = "";
    if (pws.length) {
      const isNew = (el) => (el.autocomplete || "").toLowerCase() === "new-password";
      const cur = pws.find((el) => !isNew(el)) || null;
      // G1/G3: prefer the NEW password field — a signup form's only password is
      // new-password (the old selector matched nothing and skipped
      // registration), and a change-password form must save the NEW value, not
      // the old one. Fall back to the current field (plain login) then the last
      // password input.
      let pwEl = pws.find(isNew) || cur || pws[pws.length - 1];
      if (!cur && pws.length > 1) {
        const a = pws[0].value || "", b = pws[1].value || "";
        if (a && b && a !== b) return null; // confirm mismatch → don't offer
        pwEl = pws[0];
      }
      password = pwEl.value || "";
    }
    // Username is returned even when no password field exists: a multi-step
    // signup submits the email on page 1 (no password here) and the caller
    // carries it to the password step.
    return {
      username: (cands[0] && cands[0].value || "").trim(),
      password,
    };
  }
  async function watchSubmit(form) {
    if (!form || form.dataset.pvWatched) return;
    form.dataset.pvWatched = "1";
    form.addEventListener("submit", () => {
      try {
        if (isBlocked() || phishingRefuse() || !location.host) return;
        // Card checkout: same submit, different secret shape. Checked first so
        // a checkout's billing name/email can never look like a login.
        const card = readFormCard(form);
        if (card) { offerCardSave(card); return; }
        // Identity: never on a credential form (a signup's name/email is a
        // login acquisition, not a profile) and only with a real contact
        // field — otherwise a newsletter/contact form gets a false prompt.
        if (!form.querySelector('input[type="password"]')) {
          const idf = readFormIdentity(form);
          if (idf) { offerIdentitySave(idf); return; }
        }
        const cred = readFormCreds(form);
        if (!cred) return;
        const base = pageBase();
        const username = cred.username || pvCarryUser || "";
        const password = cred.password || "";
        // Multi-page signup: page 1 submits an email only → carry the
        // (non-secret) username so the later password step can pair with it.
        if (username && !password) { pvCarrySave(base, username); return; }
        if (!username || !password) return;
        // C1: synchronous when the cache is warm (the common case) — the banner
        // is shown before the navigation commits.
        const cached = existingSync(base);
        if (cached) { offerSave(classifySubmitted(cached, username, password), username, password); return; }
        getExisting(base).then((list) => {
          offerSave(classifySubmitted(list, username, password), username, password);
        }).catch(() => {});
      } catch (_) {}
    });
  }
  function scanForms() {
    for (const f of document.querySelectorAll("form")) watchSubmit(f);
  }

  // ---------- SPA save detection: page-world fetch/XHR credential hook ----
  // React/Google/Twitter logins POST via fetch (no <form> submit ever fires),
  // and content scripts live in an ISOLATED world where wrapping fetch would
  // observe nothing. So hook.js runs in the MAIN world and sends a data-free
  // ping; WE re-read the credentials from the DOM here. A hostile page can
  // at worst trigger a prompt — never inject values. Pages whose CSP blocks
  // the injected script gracefully degrade to the submit-watcher above.
  let spaSaveOfferedFor = "";
  function injectPageHook() {
    if (document.documentElement.dataset.pvHook) return;
    document.documentElement.dataset.pvHook = "1";
    try {
      const s = document.createElement("script");
      s.src = chrome.runtime.getURL("hook.js");
      s.onload = () => s.remove();
      (document.head || document.documentElement).appendChild(s);
    } catch (_) {}
  }
  // ---------- hybrid favicon harvest (engine layer 2) ----------
  // Once per page: read the page's own <link rel=icon> (or /favicon.ico
  // fallback) and hand {domain, iconUrl} to the background, which fetches
  // with extension host permissions (page-CORS-proof) and pushes bytes to
  // the desktop disk cache. Page icon data is public chrome, never secrets.
  let faviconHarvested = false;
  function harvestFavicon() {
    if (faviconHarvested) return;
    faviconHarvested = true;
    try {
      if (!/^https?:$/i.test(location.protocol)) return;
      const host = location.hostname.toLowerCase();
      if (!host || host === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return;
      let href = "";
      try {
        const links = [...document.querySelectorAll('link[rel~="icon"]')];
        // Largest declared icon wins (apple-touch > 32px > 16px).
        let best = 0;
        for (const l of links) {
          const h = l.getAttribute("href") || "";
          if (!h || h.startsWith("data:") || h.startsWith("blob:")) continue;
          const sizes = l.getAttribute("sizes") || "";
          const m = sizes.match(/(\d+)\s*x\s*\d+/i);
          const px = m ? parseInt(m[1], 10) : 16;
          if (px >= best) { best = px; href = h; }
        }
      } catch (_) {}
      let iconUrl = "";
      try {
        iconUrl = href ? new URL(href, location.href).href : new URL("/favicon.ico", location.origin).href;
      } catch (_) { return; }
      chrome.runtime.sendMessage({ type: "PV_FAVICON_HARVEST", domain: host, iconUrl }).catch(() => {});
    } catch (_) {}
  }
  // Phase 3 relay: one held ceremony at a time (newest wins; the older
  // page promise falls back to native on its own timeout). Fulfillment
  // happens ONLY through PV_ASSERT_APPROVE / PV_ATTEST_APPROVE (popup
  // button) after the standard gates — never silently.
  let pvCeremony = null;
  function pvBufToB64(buf) {
    try {
      const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf);
      let s = "";
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s);
    } catch (_) { return ""; }
  }
  function pvB64ToBuf(s) {
    try {
      const bin = atob(String(s || ""));
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes.buffer;
    } catch (_) { return new ArrayBuffer(0); }
  }
  function pvB64ToB64Url(s) {
    return String(s || "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function pvCeremonyHold(d) {
    try {
      const kind = d.type === "PV_WEBAUTHN_CREATE" ? "create" : "get";
      const pk = d.publicKey || {};
      const allow = [];
      if (kind === "get" && pk.allowCredentials) {
        for (const c of pk.allowCredentials) {
          if (c && (c.id || c.id === 0)) {
            const b = pvBufToB64(c.id instanceof ArrayBuffer ? c.id : c.id.buffer || c.id);
            if (b) allow.push(b);
          }
        }
      }
      let user = null;
      if (kind === "create" && pk.user) {
        user = {
          idB64: pk.user.id ? pvBufToB64(pk.user.id instanceof ArrayBuffer ? pk.user.id : pk.user.id) : "",
          name: String(pk.user.name || ""),
          displayName: String(pk.user.displayName || pk.user.name || ""),
        };
      }
      pvCeremony = {
        reqId: String(d.reqId || ""),
        kind,
        rpId: String(d.rpId || "").toLowerCase(),
        origin: String(d.origin || ""),
        challengeB64: pk.challenge ? pvBufToB64(pk.challenge instanceof ArrayBuffer ? pk.challenge : pk.challenge) : "",
        allowCredIds: allow,
        user,
      };
      if (kind === "get") webauthnHint(pvCeremony.rpId);
      else toast(`🔑 Passkey registration for ${pvCeremony.rpId || "?"} held — approve in the popup to register from the vault.`);
    } catch (_) {}
  }
  function pvFulfill(credential) {
    try {
      if (!pvCeremony) return false;
      window.postMessage({ source: "__pv_relay", type: "PV_WEBAUTHN_FULFILL",
        reqId: pvCeremony.reqId, credential }, "*");
      pvCeremony = null;
      return true;
    } catch (_) { return false; }
  }
  async function pvApproveGet() {
    if (!pvCeremony || pvCeremony.kind !== "get") return { ok: false, error: "no pending ceremony" };
    if (isBlocked() || phishingRefuse() || !location.host) return { ok: false, error: "blocked" };
    if (!(await requireExtPin())) return { ok: false, error: "pin required" };
    const c = pvCeremony;
    let credId = "";
    if (c.allowCredIds && c.allowCredIds.length) {
      credId = c.allowCredIds[0];
    } else {
      const res = await chrome.runtime.sendMessage({ type: "PV_PASSKEY_LOOKUP", rp: c.rpId });
      const keys = (res && res.ok && res.passkeys) || [];
      if (keys.length !== 1) {
        return { ok: false, error: keys.length ? "multiple keys — narrow it in the vault first" : "no vault key for this site" };
      }
    }
    const r = await chrome.runtime.sendMessage({ type: "PV_ASSERT_SIGN",
      rpId: c.rpId, origin: c.origin, challengeB64: c.challengeB64, credentialId: credId });
    if (!(r && r.ok)) return { ok: false, error: (r && r.error) || "sign refused" };
    const rawId = pvB64ToBuf(r.credential_id);
    const credential = {
      id: pvB64ToB64Url(r.credential_id),
      rawId,
      type: "public-key",
      response: {
        authenticatorData: pvB64ToBuf(r.authenticatorData),
        clientDataJSON: pvB64ToBuf(r.clientDataJSON),
        signature: pvB64ToBuf(r.signature),
        userHandle: pvB64ToBuf(r.userHandle),
      },
      getClientExtensionResults: () => ({}),
    };
    pvFulfill(credential);
    return { ok: true };
  }
  async function pvApproveCreate() {
    if (!pvCeremony || pvCeremony.kind !== "create") return { ok: false, error: "no pending ceremony" };
    if (isBlocked() || phishingRefuse() || !location.host) return { ok: false, error: "blocked" };
    if (!(await requireExtPin())) return { ok: false, error: "pin required" };
    const c = pvCeremony;
    const r = await chrome.runtime.sendMessage({ type: "PV_ATTEST_SIGN",
      rpId: c.rpId, origin: c.origin, challengeB64: c.challengeB64,
      user: { id: (c.user && c.user.idB64) || "", name: (c.user && c.user.name) || "",
        displayName: (c.user && c.user.displayName) || "" } });
    if (!(r && r.ok)) return { ok: false, error: (r && r.error) || "registration refused" };
    const rawId = pvB64ToBuf(r.credential_id);
    const credential = {
      id: pvB64ToB64Url(r.credential_id),
      rawId,
      type: "public-key",
      response: {
        clientDataJSON: pvB64ToBuf(r.clientDataJSON),
        attestationObject: pvB64ToBuf(r.attestationObject),
        getTransports: () => ["internal"],
      },
      getClientExtensionResults: () => ({}),
    };
    pvFulfill(credential);
    return { ok: true };
  }
  // Passkey discovery hint: on a page WebAuthn ceremony, check the vault
  // for this rpId and toast the match (one toast per rp per page). The
  // ceremony itself is fulfilled ONLY via popup approval (see above).
  let webauthnHintedFor = "";
  async function webauthnHint(rpId) {
    try {
      const rp = (rpId || location.host || "").toLowerCase();
      if (!rp || webauthnHintedFor === rp) return;
      if (isBlocked() || phishingRefuse() || !location.host) return;
      if (!(await requireExtPin())) return;
      const res = await chrome.runtime.sendMessage({ type: "PV_PASSKEY_LOOKUP", rp });
      const keys = (res && res.ok && res.passkeys) || [];
      if (!keys.length) return;
      webauthnHintedFor = rp;
      const who = keys.slice(0, 2).map((k) => k.user || "?").join(", ");
      toast(`🔑 Vault passkey${keys.length > 1 ? "s" : ""} for ${rp}: ${who} — approve on desktop when asked.`);
    } catch (_) {}
  }
  // Pure-XHR multi-page (Google/Okta): step 1 posts only an identifier, so no
  // submit event fires and there is no password field yet. Mirror that username
  // into the secret-free carry (K1) so step 2 can rank and pair it.
  function maybeCarryFromDom() {
    try {
      if (isBlocked() || phishingRefuse() || !location.host) return;
      const f = findFields();
      if ((f.pass || []).length || (f.newPass || []).length) return;
      const el = (f.users || []).find(
        (x) => x instanceof HTMLInputElement && isVisible(x) && !isSearchField(x) &&
          String(x.value || "").trim(),
      );
      if (el) pvCarrySave(pageBase(), el.value);
    } catch (_) {}
  }
  async function maybeOfferSpaSave() {
    try {
      if (isBlocked() || phishingRefuse() || !location.host) return;
      const f = findFields();
      const userEl = (f.users[0] && isVisible(f.users[0])) ? f.users[0] : null;
      if (userEl && isSearchField(userEl)) return;
      // G2: consume findFields' newPass bucket — a signup page puts the field
      // in newPass, which the old code ignored (f.pass[0] only). New-password
      // first so a change-password page saves the NEW value.
      const passList = [...(f.newPass || []), ...(f.pass || [])].filter(isVisible);
      const pwEl = passList[0] || null;
      if (!pwEl) return;
      // K1: pair the typed password with the carried username when this step
      // has no username field of its own (multi-page signup step 2).
      const username = ((userEl && userEl.value) || "").trim() || pvCarryUser || "";
      const password = pwEl.value || "";
      if (!username || !password) return;
      // Confirm-password typo guard (two new fields that disagree → no offer).
      if (!(f.pass || []).length && passList.length > 1) {
        const a = passList[0].value || "", b = passList[1].value || "";
        if (a && b && a !== b) return;
      }
      const base = pageBase();
      const fp = username + "\n" + password;
      if (spaSaveOfferedFor === fp) return; // one prompt per credential
      spaSaveOfferedFor = fp;
      const cached = existingSync(base);
      if (cached) { offerSave(classifySubmitted(cached, username, password), username, password); return; }
      getExisting(base).then((list) => {
        offerSave(classifySubmitted(list, username, password), username, password);
      }).catch(() => {});
    } catch (_) {}
  }
  // SPA checkout: the page hook only says "a card-shaped request happened";
  // we re-read the typed card from our own DOM (same threat model as logins).
  async function maybeOfferSpaCardSave() {
    try {
      if (isBlocked() || phishingRefuse() || !location.host) return;
      const card = readFormCard(document);
      if (card) offerCardSave(card);
    } catch (_) {}
  }
  window.addEventListener("message", (e) => {
    try {
      if (e.source !== window) return;
      const d = e.data || {};
      if (d.source !== "__pv_hook") return;
      if (d.type === "PV_WEBAUTHN_GET" || d.type === "PV_WEBAUTHN_CREATE") {
        // Phase 3 relay: hold the ceremony for explicit popup approval.
        // No approval in time → the page hook falls back to native behavior.
        pvCeremonyHold(d);
        return;
      }
      if (d.type === "PV_SPA_CARD") {
        maybeOfferSpaCardSave();
        setTimeout(maybeOfferSpaCardSave, 400);
        return;
      }
      if (d.type === "PV_SPA_IDENT") {
        maybeCarryFromDom();
        return;
      }
      if (d.type !== "PV_SPA_LOGIN") return;
    } catch (_) { return; }
    // C2: read immediately — waiting a flat 2500 ms meant the SPA often
    // navigated first and the capture was lost. One short retry covers a
    // still-rendering step; `spaSaveOfferedFor` dedups the second read.
    maybeOfferSpaSave();
    setTimeout(maybeOfferSpaSave, 400);
  });
  injectPageHook();

  // OTP-page mode: a TOTP field is visible and no login/password fields
  // are (step-2/3 ceremonies). The popup asks this to offer a prominent
  // Fill-2FA button; page fills still flow through the normal gates.
  function otpPageMode() {
    try {
      const f = findFields();
      return f.otp.length > 0 && f.pass.length === 0 && f.newPass.length === 0;
    } catch (_) {
      return false;
    }
  }
  // ---------- messages from popup / menus / hotkey ----------
  chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
    (async () => {
      // E5: background saw a lock/timeout (own probe, popup, or another tab) —
      // drop the desktop gate cache before the next page action.
      if (msg.type === "PV_GATE_LOCKED") { extDeskInvalidate(); return { ok: true }; }
        if (msg.type === "PV_HOTKEY_FILL") { await hotkeyFill(); return { ok: true }; }
        // P3: popup quick-fill delegates here so React setters, multi-step
        // chaining and the URL gate are shared with hotkey/autofill. The
        // content script re-queries by domain (never trusts the popup's copy).
        if (msg.type === "PV_FILL_ENTRY") {
          if (isBlocked() || phishingRefuse() || !location.host) return { ok: false };
          if (!(await requireExtPin())) return { ok: false };
          const id = String(msg.id || "");
          if (!id) return { ok: false, error: "missing id" };
          const list = await queryHost("PV_QUERY", pageBase());
          const entry = list.find((e) => e.id === id);
          if (!entry) return { ok: false, error: "not for this site" };
          const fields = findFields();
          const filled = (fields.users.length ? 1 : 0) + (fields.pass.length ? 1 : 0);
          await fillLogin(entry, fields);
          return { ok: true, filled };
        }
      // Phase 3 relay: popup approval surface for the held ceremony.
      if (msg.type === "PV_ASSERT_PENDING") {
        return { ok: true, pending: pvCeremony ?
          { kind: pvCeremony.kind, rpId: pvCeremony.rpId, origin: pvCeremony.origin } : null };
      }
      if (msg.type === "PV_ASSERT_APPROVE") return await pvApproveGet();
      if (msg.type === "PV_ATTEST_APPROVE") return await pvApproveCreate();
      if (msg.type === "PV_OTP_STATUS") {
        return { ok: true, otpPage: otpPageMode() };
      }
      if (msg.type === "PV_FILL_OTP") {
        if (isBlocked() || phishingRefuse() || !location.host) return { ok: false };
        if (!(await requireExtPin())) return { ok: false };
        // ONE ranked source for the code, and no cached code either.
        //
        // The old flow was `pvPending.totp` else `PV_QUERY` +
        // `.find(x => x.totp)` else ranked lookup. Both shortcuts were wrong:
        // the stash replayed a code that could have died in flight (bypassing
        // the native 3s guard entirely), and the `.find()` took the FIRST login
        // row carrying a secret, with no issuer/domain ranking and no duplicate
        // check — so any site with two TOTP logins got an arbitrary account's
        // code injected with no picker. The bridge now ranks BOTH storage
        // shapes (hub cards AND logins with inline secrets) into one
        // `candidates[]`, so removing those branches costs no coverage.
        const list = await totpCandidates();
        // A step-1 fill already established WHICH account this ceremony belongs
        // to. That is a known identity, not a guess, so it may resolve without a
        // picker — but the code is still minted natively right now, never
        // replayed from the stash. If the pinned id no longer matches this site
        // (deleted account, a second tab on a different site) it is simply not
        // found, and the normal ambiguity rules apply again.
        const pinned = pvPending && pvPending.totpId
          ? list.find((c) => c.id === pvPending.totpId)
          : null;
        if (pinned) {
          if (!pinned.code) {
            toast(`⏳ নতুন code আসতে বাকি ${pinned.next_in != null ? pinned.next_in + "s" : "কিছুক্ষণ"}`);
            return { ok: false, error: "code expiring" };
          }
          return { ok: fillFromCandidate(pinned) };
        }
        const ambiguous = list.length > 1 || list.some((c) => c.is_dup);
        if (ambiguous) {
          // Explicit user gesture (popup button) — so opening UI here is
          // expected, unlike the passive sweep.
          openOtpPicker(list, findFields());
          return { ok: true, picker: true, candidates: list.length };
        }
        const only = list[0];
        if (only) {
          if (only.code) return { ok: fillFromCandidate(only) };
          if (only.next_in != null) {
            toast(`⏳ নতুন code আসতে বাকি ${only.next_in}s`);
            return { ok: false, error: "code expiring" };
          }
        }
        toast("🛡️ এই সাইটের জন্য কোনো 2FA code নেই।");
        return { ok: false };
      }
      // Step-1 handoff from popup fills (direct inject bypassed us): look
      // the entry up and stash pending for OTP chaining. Needs TOTP —
      // otherwise there is nothing later steps could use.
      if (msg.type === "PV_STASH_PENDING") {
        try {
        const logins = await getExisting(pageBase());
          const e = (logins || []).find((x) => x && x.id === msg.id);
          if (e && e.totp) {
            // The id is all we keep: it says which account the next OTP step
            // belongs to, and the code for it is minted fresh on arrival.
            pvPending = { password: e.password || "", totpId: e.id };
            pvPendingPersist();
            console.log("PV pending stashed from popup fill");
            try { sweepOtpOnce(); } catch (_) {}
          }
        } catch (_) {}
        return { ok: true };
      }
      // Fill by hub-account id. The popup shows the account + badge but NOT the
      // secret-bearing code as its source of truth: it asks us to name an id,
      // and the code is minted fresh inside the trusted host at this moment.
      // A code cached in the popup would be the one thing able to go stale.
      if (msg.type === "PV_FILL_OTP_ID") {
        if (isBlocked() || phishingRefuse() || !location.host) return { ok: false };
        if (!(await requireExtPin())) return { ok: false };
        if (!msg.id) return { ok: false, error: "id required" };
        const list = await totpCandidates(undefined, msg.id);
        const c = list.find((x) => x.id === msg.id);
        if (!c) return { ok: false, error: "account no longer offered" };
        if (!c.code) {
          toast(`⏳ নতুন code আসতে বাকি ${c.next_in != null ? c.next_in + "s" : "কিছুক্ষণ"}`);
          return { ok: false, error: "code expiring" };
        }
        closeOtpPicker();
        return { ok: fillFromCandidate(c) };
      }
      if (msg.type === "PV_MENU") {
        // Same guards as every other fill path: blocked domains, punycode /
        // spoofed hosts, and host-less pages (file://, about:blank) refuse.
        if (isBlocked() || phishingRefuse() || !location.host) return { ok: false };
        if (!(await requireExtPin())) return { ok: false };
        const f = findFields();
        if (msg.menu === "pv_fill_login") {
          const l = rankLogins(await queryHost("PV_QUERY", pageBase()), carriedUserFor(f));
          if (l[0]) fillLogin(l[0], f);
        } else if (msg.menu === "pv_fill_card") {
          const c = await queryCards();
          if (c[0]) fillCard(c[0]);
        } else if (msg.menu === "pv_fill_identity") {
          const ids = await getIdentities();
          if (ids[0]) fillIdentity(ids[0]);
        } else if (msg.menu === "pv_copy_password") {
          const l = rankLogins(await queryHost("PV_QUERY", pageBase()), carriedUserFor(f));
          if (l[0]) {
            if (l[0].reprompt && !(await confirmSensitive(l[0]))) return { ok: true };
            copyWithAutoclear(l[0].password);
          }
        } else if (msg.menu === "pv_copy_totp") {
          const l = rankLogins(await queryHost("PV_QUERY", pageBase()), carriedUserFor(f));
          const t = l.find((x) => x.totp);
          if (t) {
            if (t.reprompt && !(await confirmSensitive(t))) return { ok: true };
            copyWithAutoclear(t.totp);
          }
        } else if (msg.menu === "pv_generate_password") {
          // Registration pages: focused password field wins, else the first
          // visible new-password field, else the first password field.
          const ae = document.activeElement;
          const target = (ae instanceof HTMLInputElement && ae.type === "password" && isVisible(ae))
            ? ae
            : (f.newPass[0] || f.pass[0]);
          if (!generateInto(target)) toast("⚠️ No password field to fill here.");
        }
        return { ok: true };
      }
      return { ok: false };
    })().then(sendResponse).catch((e) => sendResponse({ ok: false, error: String(e && e.message || e) }));
    return true;
  });

  scan();
  scanForms();
  console.log("PV content boot:", location.host || "(no host)");
  try { harvestFavicon(); } catch (_) {}
  // E6: ONE debounced observer replaces two synchronous document-wide ones.
  // Framework re-render storms now coalesce into a single scan per 120 ms
  // instead of running both passes for every mutation batch. The immediate
  // scan()/scanForms() calls above still handle the cold page without delay.
  let pvScanTimer = 0;
  const pvScheduleScan = () => {
    if (pvScanTimer) return;
    pvScanTimer = setTimeout(() => {
      pvScanTimer = 0;
      scan();
      scanForms();
    }, 120);
  };
  new MutationObserver(pvScheduleScan).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
  // Fixed overlays must track the viewport (passive listeners, no jank).
  let reposT = 0;
  const queueRepos = () => {
    const now = Date.now();
    if (now - reposT < 100) return;
    reposT = now;
    requestAnimationFrame(repositionBadges);
  };
  window.addEventListener("scroll", queueRepos, { passive: true, capture: true });
  window.addEventListener("resize", queueRepos, { passive: true });
  armOtpObserver();
  pvPendingRestore();
  // C1/K1: warm the credential-list cache (synchronous submit decisions) and
  // restore the non-secret username carried across a multi-page signup.
  pvCarryLoad(pageBase());
  getExisting(pageBase()).catch(() => {});
  if (document.readyState === "complete" || document.readyState === "interactive") {
    autofillOnLoad();
  } else {
    window.addEventListener("DOMContentLoaded", autofillOnLoad, { once: true });
  }
})();
