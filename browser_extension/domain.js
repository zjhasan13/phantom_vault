// Shared domain helpers — single source of truth for the extension.
//
// Classic script (loaded via popup.html before popup.js) that also exposes a
// CommonJS fallback so `tests/js/domain.test.mjs` can load it directly.
// Phase 3 will additionally wire content.js / background.js and fold in the
// `registrable()` / EQUIV_CLUSTERS duplication now living in those files.
(function (root, factory) {
  const api = factory();
  if (root) root.PVDomain = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  // Registrable-ish base domain: last two labels (`foo.bar.co.uk` → `co.uk`).
  // Deliberately simple — Phase 3 replaces this with a public-suffix-aware
  // implementation shared by content.js/background.js/popup.js.
  function pageBase(h) {
    const parts = String(h || "").toLowerCase().split(".").filter(Boolean);
    return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
  }

  // Blocked-domain gate: exact base match or a subdomain of a blocked entry,
  // mirroring content.js `isBlocked()`.
  function isBlockedHost(host, blocked) {
    const base = pageBase(host);
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

  return { pageBase, isBlockedHost, isPunycodeHost };
});
