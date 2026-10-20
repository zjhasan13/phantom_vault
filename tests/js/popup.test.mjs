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
