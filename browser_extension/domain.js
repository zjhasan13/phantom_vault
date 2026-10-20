// Shared domain helpers — single source of truth for the extension.
//
// Loaded before content.js (manifest `js` order), before popup.js
// (popup.html), and via importScripts() in the service worker. Also exposes a
// CommonJS fallback so `tests/js/domain.test.mjs` can load it directly.
//
// E1/E2: this file replaces the three copies of `registrable()` and
// `EQUIV_CLUSTERS` that used to live in content.js / background.js /
// popup.js. Native host (`native_host.rs`) mirrors the same clusters.
(function (root, factory) {
  const api = factory();
  if (root) root.PVDomain = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  // Multi-label "public suffix" tails we refuse to split. A pragmatic subset
  // of the PSL covering the ccTLDs users actually hit: `foo.co.uk` must not
  // collapse to `co.uk`, or every unrelated site under the same registry
  // suffix looks equivalent (E1).
  const MULTI_LABEL_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "co.za", "net.za", "org.za", "gov.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "net.mx", "org.mx", "gob.mx",
    "com.tr", "net.tr", "org.tr", "gov.tr",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "co.kr", "ne.kr", "or.kr", "go.kr", "ac.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "ac.cn",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "co.id", "or.id", "web.id", "ac.id", "go.id",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "co.th", "in.th", "or.th", "ac.th", "go.th",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "com.ar", "net.ar", "org.ar", "gov.ar",
    "com.co", "net.co", "org.co", "gov.co",
    "com.pe", "net.pe", "org.pe", "gob.pe",
    "com.ua", "net.ua", "org.ua", "gov.ua",
    "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd",
    "co.ke", "or.ke", "ac.ke", "go.ke",
    "com.ng", "net.ng", "org.ng", "gov.ng",
    "co.zw", "co.bw", "co.tz", "co.ug",
    "com.es", "nom.es", "org.es", "gob.es", "edu.es",
    "com.pt", "org.pt", "gov.pt", "edu.pt",
    "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
  ]);

  // Label prefixes stripped when compiling domain candidates (login.x.com and
  // x.com should compare equal).
  const SUB_PREFIXES = ["account", "accounts", "login", "auth", "myaccount", "my", "app", "www", "signin", "sso", "secure", "id", "mail"];

  // Equivalent-domain clusters (one copy; `.*` = any ccTLD tail).
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

  // Registrable domain (public suffix + one label).
  function registrable(host) {
    const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    if (MULTI_LABEL_SUFFIXES.has(parts.slice(-2).join("."))) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  // Back-compat alias used by popup.js.
  function pageBase(h) {
    return registrable(h);
  }

  function stripSubs(host) {
    const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
    while (parts.length > 2 && SUB_PREFIXES.includes(parts[0])) parts.shift();
    return parts.join(".");
  }

  function memberHit(member, domain) {
    if (member.endsWith(".*")) {
      const p = member.slice(0, -2);
      return domain === p || domain.startsWith(p + ".");
    }
    return domain === member || domain.endsWith("." + member) || member.endsWith("." + domain);
  }

  function clusterStem(members) {
    const labels = members.map((m) => m.replace(/\.\*$/, "").split(".")[0] || "");
    let len = (labels[0] || "").length;
    for (const l of labels.slice(1)) {
      let i = 0;
      while (i < len && (labels[0][i] === l[i])) i++;
      len = Math.min(len, i);
    }
    return len >= 5 ? labels[0].slice(0, len) : null;
  }

  // Candidate domains for a host: stripped full host + multi-label suffixes.
  function domainCands(host) {
    const full = stripSubs(host);
    const parts = full.split(".").filter(Boolean);
    const out = [full];
    for (let i = 1; i < parts.length; i++) {
      if (parts.length - i >= 2) out.push(parts.slice(i).join("."));
    }
    return out;
  }

  // True when two domains are equivalent siblings (cluster or brand-stem).
  function domainsEquiv(a, b) {
    const ca = domainCands(a), cb = domainCands(b);
    for (const cluster of EQUIV_CLUSTERS) {
      const hitA = ca.some((d) => cluster.some((m) => memberHit(m, d)));
      if (!hitA) continue;
      if (cb.some((d) => cluster.some((m) => memberHit(m, d)))) return true;
      // Brand-stem fallback: distinctive shared root (>= 5 chars).
      const stem = clusterStem(cluster);
      if (stem) {
        const tok = (stripSubs(b).split(".")[0] || "");
        if (tok && (tok === stem || tok.startsWith(stem) || stem.startsWith(tok))) return true;
      }
    }
    return false;
  }

  // Blocked-domain gate: exact registrable match or a subdomain of a blocked
  // entry, mirroring content.js `isBlocked()`.
  function isBlockedHost(host, blocked) {
    const base = registrable(host);
    if (!base) return false;
    return (blocked || []).some((d) => {
      const t = String(d || "").trim().toLowerCase();
      return !!t && (base === t || base.endsWith("." + t));
    });
  }

  // Anti-phishing: punycode lookalikes never receive credentials.
  function isPunycodeHost(host) {
    return String(host || "").toLowerCase().includes("xn--");
  }

  return {
    registrable,
    pageBase,
    EQUIV_CLUSTERS,
    stripSubs,
    memberHit,
    clusterStem,
    domainCands,
    domainsEquiv,
    isBlockedHost,
    isPunycodeHost,
  };
});
