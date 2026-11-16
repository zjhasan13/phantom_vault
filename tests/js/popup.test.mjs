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

// ---- A3: item editor ----

test("A3: popup sends create/update/delete only through the editor", () => {
  assert.match(SRC, /function openItemEditor\(entry, kind = "login"\)/, "editor present");
  assert.match(SRC, /type: isNew \? "PV_ITEM_CREATE" : "PV_ITEM_UPDATE"/);
  assert.match(SRC, /type: "PV_ITEM_DELETE"/);
  assert.match(SRC, /document\.getElementById\("addItemBtn"\)/, "Add button wired");
  assert.match(SRC, /function editButton\(id, kind = "login"\)/, "per-row edit control present");
});

test("A3: armed items require the master reprompt before any mutation", () => {
  const editor = SRC.slice(SRC.indexOf("async function requestReprompt"), SRC.indexOf("function currentFilter"));
  assert.match(editor, /type: "PV_REPROMPT"/, "reprompt goes through the bridge");
  const save = editor.slice(editor.indexOf("saveBtn.addEventListener"), editor.indexOf("if (delBtn)"));
  assert.match(save, /needsToken\(\)\) \{[\s\S]*requestReprompt/, "save gates on reprompt");
  assert.ok(save.indexOf("requestReprompt") < save.indexOf("chrome.runtime.sendMessage(payload)"),
    "reprompt happens before the mutation");
  const del = editor.slice(editor.indexOf("delBtn.addEventListener"));
  assert.match(del, /kind === "login" && entry\.reprompt[\s\S]*requestReprompt/, "delete gates on reprompt");
  assert.match(del, /PV_ITEM_DELETE/);
});

test("A3: edit flow never overwrites a TOTP secret with a live code", () => {
  assert.match(SRC, /if \(totpIn\.value\.trim\(\)\) payload\.totp = totpIn\.value\.trim\(\);/,
    "blank TOTP field is omitted, not sent");
  assert.match(SRC, /fetchEntry\(KIND_NUM\[kind\] \|\| 1, id\)/, "editor loads the full item on demand");
});

// ---- P1: read-only item view ----

test("P1: rows open a read-only view and edit lives inside it", () => {
  assert.match(SRC, /function openItemView\(entry, kind = "login"\)/, "read-only view present");
  assert.match(SRC, /function viewButton\(id, kind = "login"\)/, "per-row view control");
  assert.match(SRC, /viewButton\(e\.id\), editButton\(e\.id\)/, "view precedes edit");
  assert.match(SRC, /viewButton\(c\.id, "card"\), editButton\(c\.id, "card"\)/, "cards have a view");
  assert.match(SRC, /viewButton\(i\.id, "identity"\), editButton\(i\.id, "identity"\)/, "identities have a view");
  assert.match(SRC, /viewButton\(n\.id, "note"\), editButton\(n\.id, "note"\)/, "notes have a view");
  const view = SRC.slice(SRC.indexOf("function openItemView("), SRC.indexOf("function openItemEditor("));
  assert.match(view, /addRow\(t\("ed_password"\), entry\.password, \{ secret: true/, "password masked by default");
  assert.match(view, /t\("view_close"\)/, "close action");
  assert.match(view, /openItemEditor\(entry, kind\)/, "edit opens from the view");
});

// ---- P2: SSH + License editors ----

test("P2: SSH and License rows have view + edit and the editor maps both kinds", () => {
  assert.match(SRC, /ssh: 6, license: 7/, "kind map");
  assert.match(SRC, /viewButton\(s\.id, "ssh"\), editButton\(s\.id, "ssh"\)/, "SSH row actions");
  assert.match(SRC, /viewButton\(l\.id, "license"\), editButton\(l\.id, "license"\)/, "license row actions");
  assert.match(SRC, /else if \(kind === "license"\) \{[\s\S]*?License key/, "license fields");
  assert.match(SRC, /else if \(kind === "ssh"\) \{[\s\S]*?Private key/, "SSH fields");
  assert.match(SRC, /\["license", "License"\], \["ssh", "SSH key"\]/, "Add chooser entries");
  assert.match(SRC, /payload\.license_key = keyIn\.value\.trim\(\)/, "license save payload");
  assert.match(SRC, /payload\.private_key = privIn\.value\.trim\(\)/, "SSH save payload");
});

// ---- A4: clipboard auto-clear ----

test("A4: popup copies through the native host before the web clipboard", () => {
  const copy = SRC.match(/async function copySecret\(text, seconds\) \{([\s\S]*?)\n  \}/);
  assert.ok(copy, "copySecret present");
  const body = copy[1];
  assert.ok(body.includes('type: "PV_COPY_SECRET"'), "native copy requested");
  assert.ok(body.indexOf("PV_COPY_SECRET") < body.indexOf("navigator.clipboard.writeText"),
    "native path is tried before the web fallback");
  assert.match(body, /armClipboardClear\(await sha256Hex\(t\)\)/,
    "web fallback arms the hash-guarded clear");
  assert.match(body, /seconds: secs/,
    "native copy carries the configured auto-clear timeout");
  assert.match(body, /clipClearSec/,
    "the settings value is the fallback for the timeout");
  assert.ok(!/msg\.seconds = seconds/.test(body),
    "the timeout is always sent, never omitted");
  // Every popup copy surface goes through copySecret.
  assert.match(SRC, /await copySecret\(text\);\s*\n\s*btn\.textContent = t\("copied"\)/);
  assert.match(SRC, /await copySecret\(genOut\.textContent \|\| ""\)/);
  assert.match(SRC, /await copySecret\(live\)/);
  assert.match(SRC, /await copySecret\(full\.totp\)/);
  // No unconditional clipboard blank: the native timer and the hash-guarded
  // alarm own the clear now.
  assert.ok(!/navigator\.clipboard\.writeText\(""\)/.test(SRC),
    "popup must never blank the clipboard blind");
  const arm = SRC.match(/function armClipboardClear\(hash\) \{([\s\S]*?)\n  \}/);
  assert.ok(arm, "armClipboardClear present");
  assert.match(arm[1], /type: "PV_CLIP_ARM"/);
  assert.match(arm[1], /msg\.hash = hash/);
});

// ---- A27 L2: desktop pairing UI -----------------------------------------

function pairParser() {
  const m = SRC.match(/const PAIR_ALPHABET = "([^"]+)";[\s\S]*?\n  function parsePairCode\(input\) \{([\s\S]*?)\n  \}/);
  assert.ok(m, "parsePairCode present in popup.js");
  assert.equal(m[1], "0123456789ABCDEFGHJKMNPQRSTVWXYZ", "Crockford alphabet");
  return new Function(
    `const PAIR_ALPHABET = ${JSON.stringify(m[1])};` +
      `function parsePairCode(input) {${m[2]}\n  }` +
      "return parsePairCode;"
  )();
}

test("A27 L2: the popup decodes the desktop pairing code", () => {
  const parse = pairParser();
  // Same vector as host_pairing::tests: bytes 0..19.
  const bytes = parse("000G-40R4-0M30-E209-185G-R38E-1W81-24GK");
  assert.ok(bytes, "canonical code parses");
  assert.deepEqual(bytes, Array.from({ length: 20 }, (_, i) => i));
  // Case, spaces and Crockford lookalikes are tolerated.
  assert.deepEqual(parse(" 000g 40r4 0m30 e209 185g r38e 1w81 24gk "), bytes);
  assert.deepEqual(parse("000G-40R4-0M30-E209-185G-R38E-IW8I-24GK"), bytes,
    "I and L read as 1");
  // Wrong length, illegal letters and short codes are refused.
  assert.equal(parse("000G-40R4-0M30-E209-185G-R38E-1W81-24G"), null);
  assert.equal(parse("000G-40R4-0M30-E209-185G-R38E-1W81-24GK-0000"), null);
  assert.equal(parse("UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU"), null);
  assert.equal(parse(""), null);
});

test("A27 L2: the popup stores only the decoded secret and proves it", () => {
  assert.match(SRC, /await chrome\.storage\.local\.set\(\{ pv_pair_secret: b64 \}\)/,
    "the decoded bytes go to storage, not the typed code");
  assert.ok(!/pv_pair_secret: .*pairInput/.test(SRC), "the raw code is never stored");
  assert.match(SRC, /type: "PV_PAIR"/, "the popup asks the host to verify");
  const failed = SRC.match(/await chrome\.storage\.local\.remove\("pv_pair_secret"\);/g);
  assert.ok(failed && failed.length >= 2, "a refused code and Unpair both wipe the secret");
});

test("A27 L2: popup.html carries the pairing row the script binds to", () => {
  const HTML = readFileSync(
    new URL("../../browser_extension/popup.html", import.meta.url), "utf8");
  for (const id of ["pairHint", "pairCode", "pairBtn", "unpairBtn"]) {
    assert.match(HTML, new RegExp(`id="${id}"`), `${id} present`);
  }
});

test("A27 strict mode: the popup asks for the app PIN when the host says so", () => {
  // Settings → Security → "Browser bridge after PIN unlock" OFF writes no plain
  // bridge token. The host answers `need: "pin"`; the popup must prompt instead
  // of printing "Vault is Locked" at a user whose app is open and unlocked.
  const stats = SRC.match(/async function loadStats\(\) \{([\s\S]*?)\n  \}/);
  assert.ok(stats, "loadStats present");
  assert.match(stats[1], /s\.need === "pin"/, "stats honours need:pin");
  assert.match(stats[1], /showBridgePinLock\(\)/, "stats shows the PIN prompt");

  const lock = SRC.match(/function showBridgePinLock\(\) \{([\s\S]*?)\n  \}/);
  assert.ok(lock, "showBridgePinLock present");
  assert.match(lock[1], /type: "PV_BRIDGE_PIN"/, "the prompt posts the PIN to the router");
  assert.match(lock[1], /arm\(\); \/\/ loop: the next attempt must work/,
    "a wrong PIN re-arms the handler instead of bricking the popup");
  assert.match(lock[1], /res\.wiped/, "a 5-strike wipe is reported, not hidden");

  // Every path that can meet a strict-mode host must route to the prompt.
  assert.match(SRC, /if \(q\.need === "pin"\)/, "list/query refresh routes to the prompt");
  assert.match(SRC, /if \(l\.need === "pin"\)/, "list refresh routes to the prompt");
  assert.match(SRC, /pong\.need === "pin"/, "ping treats need:pin as reachable");

  for (const key of ["bridge_pin_title", "bridge_pin_sub", "bridge_pin_go",
    "bridge_pin_wrong", "bridge_pin_wiped"]) {
    const defined = SRC.match(new RegExp(`${key}:`, "g")) || [];
    assert.equal(defined.length, 2, `en + bn both define ${key}`);
  }
});

test("stats shows the real bridge refusal instead of a blanket lock", () => {
  // The desktop can be open and unlocked and still refuse the bridge: a build
  // with the PIN bridge switched off has no credential to unseal, and a release
  // host refuses a spawn that did not come from a signed browser. "Vault is
  // Locked" sent users in circles, so the popup must surface what the host
  // actually said.
  const stats = SRC.match(/async function loadStats\(\) \{([\s\S]*?)\n  \}/);
  assert.ok(stats, "loadStats present");
  assert.match(stats[1], /typeof s\.error === "string"/, "host error is read");
  assert.match(stats[1], /bridge_no_credential/, "a missing credential has its own line");
  // Both locales must define the key, or one language shows `undefined`.
  const defined = SRC.match(/bridge_no_credential:/g) || [];
  assert.equal(defined.length, 2, "en + bn both define bridge_no_credential");
});