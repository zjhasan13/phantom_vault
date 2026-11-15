// Gate for the non-technical manual test guide (docs/MANUAL_TEST_GUIDE.md).
// The guide is the only test path for a human tester years from now, so it must
// keep: every top-level section, the release pairing warning, the automated gate
// commands, and the "deliberately absent" list. A rewrite that drops one of
// these is a real regression, not a formatting nit.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const GUIDE = readFileSync(
  new URL("../../docs/MANUAL_TEST_GUIDE.md", import.meta.url), "utf8");

test("manual guide: every section a tester needs is present", () => {
  const sections = [
    "## 1. যা যা লাগবে",
    "## 2. কীভাবে ফেল রিপোর্ট করবেন",
    "## 3. প্রস্তুতি",
    "## 4. প্রথম চালু, আনলক, লক",
    "## 5. ভল্ট ব্যবহার",
    "## 6. ব্যাকআপ, রিকভারি, ইমপোর্ট/এক্সপোর্ট",
    "## 7. সিঙ্ক",
    "## 8. ব্রাউজার এক্সটেনশন",
    "## 9. Settings-এর প্রতিটা ট্যাব",
    "## 10. Automated gates",
    "## 11. যা এখনও অসম্পূর্ণ",
    "## 12. স্মোক টেস্ট",
    "## 13. টেস্টারের ট্র্যাপ",
  ];
  for (const s of sections) {
    assert.ok(GUIDE.includes(s), `missing section: ${s}`);
  }
  assert.ok(GUIDE.split("\n").length > 200, "guide is a checklist, not a stub");
});

test("manual guide: the release pairing requirement is spelled out", () => {
  // A27 step 2 refuses unverified frames in release builds. A tester who does
  // not know that will report the refusal as a bug.
  assert.match(GUIDE, /Show pairing code/);
  assert.match(GUIDE, /Revoke pairing/);
  assert.match(GUIDE, /extension not paired/);
  assert.match(GUIDE, /পেয়ার না করা পর্যন্ত/);
  assert.match(GUIDE, /৮ গ্রুপ/, "the code shape is documented");
});

test("manual guide: the four automated gates are copy-pasteable", () => {
  for (const cmd of [
    "cargo test -j 1",
    "cargo clippy --all-targets -j 1 -- -D warnings",
    "npm test",
    "npm run test:tokens",
  ]) {
    assert.ok(GUIDE.includes(cmd), `gate command missing: ${cmd}`);
  }
});

test("manual guide: reset path and demo isolation are documented", () => {
  // Testing on a real vault is the worst failure mode of a manual pass.
  assert.match(GUIDE, /PHANTOM_VAULT_DIR/);
  assert.match(GUIDE, /C:\\pv-demo/);
  assert.match(GUIDE, /আসল ভল্টে টেস্ট করবেন না/);
  assert.match(GUIDE, /রিসেট/);
});

test("manual guide: deliberate absences are listed so they are not filed as bugs", () => {
  for (const absent of [
    "Organizations",
    "dual-column",
    "AES-256-GCM",
    "quantum-immune",
  ]) {
    assert.ok(GUIDE.includes(absent), `absent-by-design item missing: ${absent}`);
  }
  assert.match(GUIDE, /iframe/, "top-frame-only autofill caveat present");
});

test("manual guide: open gaps stay honest", () => {
  assert.match(GUIDE, /unsigned/i);
  assert.match(GUIDE, /Firefox/);
  assert.match(GUIDE, /Response MAC/);
  assert.match(GUIDE, /Windows Hello/);
});
