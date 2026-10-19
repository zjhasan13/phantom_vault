#!/usr/bin/env node
// domain.js shared-helper tests. Loads the REAL file in a `vm` sandbox (same
// approach as harness.mjs) and asserts the guard predicates the popup uses to
// refuse fills on blocked / punycode hosts (E3).
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

function load() {
  const sandbox = { console };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox, { filename: "domain.js" });
  assert.ok(sandbox.PVDomain, "domain.js must expose PVDomain");
  return sandbox.PVDomain;
}

test("pageBase keeps the last two labels", () => {
  const { pageBase } = load();
  assert.equal(pageBase("example.com"), "example.com");
  assert.equal(pageBase("a.b.c"), "b.c");
  assert.equal(pageBase("APP.Example.COM"), "example.com");
  assert.equal(pageBase(""), "");
});

test("isBlockedHost matches exact and subdomain entries, case-insensitively", () => {
  const { isBlockedHost } = load();
  assert.equal(isBlockedHost("example.com", ["example.com"]), true);
  assert.equal(isBlockedHost("app.example.com", ["example.com"]), true);
  assert.equal(isBlockedHost("EXAMPLE.com", ["Example.COM"]), true);
  assert.equal(isBlockedHost("example.com", ["other.com"]), false);
  assert.equal(isBlockedHost("login.corp", ["corp"]), true);
  assert.equal(isBlockedHost("example.com", []), false);
  assert.equal(isBlockedHost("", ["example.com"]), false);
  assert.equal(isBlockedHost("example.com", ["  ", ""]), false);
});

test("isPunycodeHost flags IDN lookalikes only", () => {
  const { isPunycodeHost } = load();
  assert.equal(isPunycodeHost("xn--80ak6aa92e.com"), true);
  assert.equal(isPunycodeHost("XN--abc.example"), true);
  assert.equal(isPunycodeHost("example.com"), false);
  assert.equal(isPunycodeHost(""), false);
});
