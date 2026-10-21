// popup.js gate tests (P0). Popup runs against chrome.* APIs, so the security
// invariants are asserted on the source that ships in the extension.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const SRC = readFileSync(
  new URL("../../browser_extension/popup.js", import.meta.url), "utf8");

test("P0: popup fill + suggestion gates refuse URL-less items", () => {
  const allowed = SRC.match(/function entryAllowed\(e\) \{([\s\S]*?)\n  \}/);
  assert.ok(allowed, "entryAllowed present");
  assert.match(allowed[1], /if \(!urls\.length\) return false;/,
    "fill gate must refuse entries without a stored URL");

  const suggest = SRC.match(/function suggestMatch\(e\) \{([\s\S]*?)\n  \}/);
  assert.ok(suggest, "suggestMatch present");
  assert.match(suggest[1], /if \(!domains\.length\) return false;/,
    "suggestions must require a stored URL");
  assert.ok(!/hostBase/.test(suggest[1]),
    "no title-only fallback for unbound items");
});

test("P0: popup explains the unbound refusal instead of a phishing warning", () => {
  assert.match(SRC, /No site URL saved — edit this item and add one\./);
});

test("P3: popup quick-fill delegates to the content engine first", () => {
  const fill = SRC.match(/async function fillEntry\(tabId, entry\) \{([\s\S]*?)\n  \}/);
  assert.ok(fill, "fillEntry present");
  const body = fill[1];
  assert.ok(body.includes('type: "PV_FILL_ENTRY"'), "content engine message sent");
  assert.ok(body.indexOf("PV_FILL_ENTRY") < body.indexOf("injectFill"),
    "content engine tried before direct inject");
});
test("P4: popup suggestions rank the carried account first (ordering only)", () => {
  const read = SRC.match(/const key = "pvCaptureCarry:" \+ tab\.id;([\s\S]*?)carryUser = String\(c\.username\)/);
  assert.ok(read, "popup reads the per-tab carry from storage.session");
  assert.ok(!/sugg = sugg\.filter/.test(SRC.slice(SRC.indexOf("const isCarry"), SRC.indexOf("sugg.slice(0, 20)"))),
    "carry must never filter suggestions");
  assert.match(SRC, /const isCarry = \(e\) =>[\s\S]{0,220}sugg\.sort/,
    "carry participates in the suggestion sort");
});

test("P6: fill targets the frame that owns the login form", () => {
  const fill = SRC.match(/async function fillEntry\(tabId, entry\) \{([\s\S]*?)\n  \}/);
  assert.ok(fill, "fillEntry present");
  assert.match(fill[1], /\{ frameId: target \}/, "content message carries frameId");
  assert.match(fill[1], /injectFill\(tabId, entry, target\)/, "fallback inject uses the same frame");
  assert.match(fill[1], /entryMatchesHost\(entry, pick\.host\)/,
    "fallback inject refuses when the picked frame does not match the entry origin");
  assert.match(SRC, /frameIds: \[frameId\]/, "executeScript targets a single frame");
  assert.match(SRC, /async function fillTargetFrame\(tabId\)/, "frame picker present");
  assert.match(SRC, /PVDomain\.pickActionFrame\(rows\)/, "shared pick priority");
});

test("P6: popup gates and suggestions include embedded frame origins", () => {
  const match = SRC.match(/function hostMatchesPage\(h\) \{([\s\S]*?)\n  \}/);
  assert.ok(match, "hostMatchesPage present");
  assert.match(match[1], /frameHosts\.some/, "frame origins participate in matching");
  const blocked = SRC.match(/function siteBlocked\(entry, list\) \{([\s\S]*?)\n  \}/);
  assert.ok(blocked, "siteBlocked present");
  assert.match(blocked[1], /entryMatchesHost\(entry, fh\)/,
    "a blocked frame vetoes only credentials that belong to it");
  const puny = SRC.match(/function punycodeTarget\(entry\) \{([\s\S]*?)\n  \}/);
  assert.ok(puny, "punycodeTarget present");
  assert.match(puny[1], /entryMatchesHost\(entry, fh\)/,
    "a punycode frame vetoes only credentials that belong to it");
  const refresh = SRC.match(/const queryApps = \[\];([\s\S]*?)const \[q, l, \.\.\.extraQs\]/);
  assert.ok(refresh, "frame query fan-out present");
  assert.match(SRC, /extraQs/, "iframe suggestions merge into suggEntries");
  const decl = SRC.indexOf("let frameHosts = [];");
  const assign = SRC.indexOf("frameHosts = await loadFrameHosts");
  assert.ok(decl > 0 && decl < assign, "frameHosts declared before the init assignment (no TDZ)");
});