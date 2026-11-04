// Offline equivalent-domain clusters: data/equivalent_domains.json is the
// canonical list. domain.js and native_host.rs each keep a literal copy so the
// content script can run without a fetch; this test is what stops the copies
// from drifting apart (the Rust side has the same guard).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const SRC = fs.readFileSync(
  path.join(ROOT, "..", "..", "browser_extension", "domain.js"),
  "utf8",
);
const doc = JSON.parse(
  fs.readFileSync(path.join(ROOT, "..", "..", "data", "equivalent_domains.json"), "utf8"),
);

function load() {
  const sandbox = { console };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox, { filename: "domain.js" });
  assert.ok(sandbox.PVDomain, "domain.js must expose PVDomain");
  return sandbox.PVDomain;
}

test("domain.js EQUIV_CLUSTERS equals the canonical JSON", () => {
  assert.ok(Array.isArray(doc.clusters), "clusters must be an array");
  // The vm sandbox has its own Array prototype, so compare serialized shapes.
  assert.equal(JSON.stringify(load().EQUIV_CLUSTERS), JSON.stringify(doc.clusters));
});

test("every cluster is a sane domain list", () => {
  const seen = new Set();
  for (const group of doc.clusters) {
    assert.ok(Array.isArray(group) && group.length >= 2, `cluster too small: ${group}`);
    for (const member of group) {
      assert.equal(typeof member, "string");
      assert.match(member, /^[a-z0-9.-]+(\.\*)?$/, `bad member: ${member}`);
      assert.ok(!member.startsWith(".") && !member.endsWith(".."), `bad member: ${member}`);
      // A domain must not live in two groups: the matcher takes the first hit,
      // so a duplicate would make the second group unreachable.
      assert.ok(!seen.has(member), `duplicate member across clusters: ${member}`);
      seen.add(member);
    }
  }
});

test("the clusters still resolve the Google family", () => {
  const { domainsEquiv } = load();
  assert.equal(domainsEquiv("accounts.google.com", "youtube.com"), true);
  assert.equal(domainsEquiv("mail.google.com", "gmail.com"), true);
  assert.equal(domainsEquiv("accounts.google.com", "evil.example"), false);
});
