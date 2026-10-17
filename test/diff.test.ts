import { test } from "node:test";
import assert from "node:assert/strict";
import { diff } from "../src/diff";
import type { Change, Manifest } from "../src/types";

function manifest(overrides: Partial<Manifest> = {}): Manifest {
  return {
    id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    name: "Test Extension",
    version: "1.0.0",
    manifestVersion: 3,
    permissions: [],
    optionalPermissions: [],
    hostPermissions: [],
    contentScriptMatches: [],
    externallyConnectable: [],
    hasBackground: false,
    csp: null,
    updateUrl: null,
    description: "",
    ...overrides,
  };
}

const ofKind = (changes: Change[], kind: string) => changes.filter((c) => (c.kind as string) === kind);

test("new extension when previous is null", () => {
  const changes = diff(null, manifest());
  assert.equal(changes.length, 1);
  assert.deepEqual(changes[0], {
    kind: "new_extension",
    value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    severity: "medium",
  });
});

test("removed from store when next is null", () => {
  const changes = diff(manifest(), null);
  assert.deepEqual(changes[0], {
    kind: "removed_from_store",
    value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    severity: "low",
  });
});

test("both null yields no changes", () => {
  assert.deepEqual(diff(null, null), []);
});

test("identical manifests yield no changes", () => {
  assert.deepEqual(diff(manifest({ permissions: ["tabs"] }), manifest({ permissions: ["tabs"] })), []);
});

test("permission added uses table severity", () => {
  const changes = diff(manifest(), manifest({ permissions: ["debugger"] }));
  assert.deepEqual(ofKind(changes, "permission_added"), [
    { kind: "permission_added", value: "debugger", severity: "critical" },
  ]);
});

test("permission removed is reported", () => {
  const changes = diff(manifest({ permissions: ["cookies"] }), manifest());
  assert.deepEqual(changes, [{ kind: "permission_removed", value: "cookies", severity: "high" }]);
});

test("host added is critical only when broad (H3)", () => {
  const broad = diff(manifest(), manifest({ hostPermissions: ["<all_urls>"] }));
  assert.deepEqual(ofKind(broad, "host_added"), [{ kind: "host_added", value: "<all_urls>", severity: "critical" }]);
  const narrow = diff(manifest(), manifest({ hostPermissions: ["https://api.example.com/*"] }));
  assert.deepEqual(ofKind(narrow, "host_added"), [{ kind: "host_added", value: "https://api.example.com/*", severity: "medium" }]);
});

test("host removed is low", () => {
  const removed = diff(manifest({ hostPermissions: ["https://example.com/*"] }), manifest());
  assert.deepEqual(removed, [{ kind: "host_removed", value: "https://example.com/*", severity: "low" }]);
});

test("manifest version change to MV2 is medium", () => {
  const changes = diff(manifest({ manifestVersion: 3 }), manifest({ manifestVersion: 2 }));
  assert.deepEqual(changes, [{ kind: "mv_changed", value: "3 -> 2", severity: "medium" }]);
});

test("manifest version change to MV3 is low", () => {
  const changes = diff(manifest({ manifestVersion: 2 }), manifest({ manifestVersion: 3 }));
  assert.deepEqual(changes, [{ kind: "mv_changed", value: "2 -> 3", severity: "low" }]);
});

test("permission order and duplicates are ignored", () => {
  const prev = manifest({ permissions: ["tabs", "storage", "tabs"] });
  const next = manifest({ permissions: ["storage", "tabs", "cookies"] });
  const changes = diff(prev, next);
  assert.deepEqual(ofKind(changes, "permission_added"), [
    { kind: "permission_added", value: "cookies", severity: "high" },
  ]);
});

test("multiple changes are all reported", () => {
  const prev = manifest({ permissions: ["tabs"], hostPermissions: ["https://a.example/*"] });
  const next = manifest({
    permissions: ["tabs", "debugger"],
    hostPermissions: ["https://a.example/*", "<all_urls>"],
  });
  const changes = diff(prev, next);
  assert.ok(ofKind(changes, "permission_added").some((c) => c.value === "debugger"));
  assert.ok(ofKind(changes, "host_added").some((c) => c.value === "<all_urls>"));
  assert.equal(ofKind(changes, "score_jump").length, 1);
});

test("content scripts widening to all sites is reported (H2)", () => {
  const prev = manifest({ contentScriptMatches: ["https://google.com/*"] });
  const next = manifest({ contentScriptMatches: ["<all_urls>"] });
  const changes = diff(prev, next);
  assert.deepEqual(ofKind(changes, "content_script_added"), [
    { kind: "content_script_added", value: "<all_urls>", severity: "critical" },
  ]);
  assert.deepEqual(ofKind(changes, "content_script_removed"), [
    { kind: "content_script_removed", value: "https://google.com/*", severity: "low" },
  ]);
});

test("optional permission added is one severity level lower (H2)", () => {
  const changes = diff(manifest(), manifest({ optionalPermissions: ["cookies"] }));
  assert.deepEqual(changes, [{ kind: "optional_added", value: "cookies", severity: "medium" }]);
});

test("optional broad host is high, one level below critical (H2)", () => {
  const changes = diff(manifest(), manifest({ optionalPermissions: ["*://*/*"] }));
  assert.deepEqual(ofKind(changes, "optional_added"), [
    { kind: "optional_added", value: "*://*/*", severity: "high" },
  ]);
});

test("externally connectable opened to all sites is reported (H2)", () => {
  const changes = diff(manifest(), manifest({ externallyConnectable: ["*://*/*"] }));
  assert.deepEqual(ofKind(changes, "externally_connectable_added"), [
    { kind: "externally_connectable_added", value: "*://*/*", severity: "high" },
  ]);
});

test("CSP loosening to unsafe-eval is reported (H2)", () => {
  const prev = manifest({ csp: "script-src 'self'" });
  const next = manifest({ csp: "script-src 'self' 'unsafe-eval'" });
  const changes = diff(prev, next);
  assert.deepEqual(ofKind(changes, "csp_changed"), [
    { kind: "csp_changed", value: "script-src 'self' 'unsafe-eval'", severity: "high" },
  ]);
});

test("CSP change to 'wasm-unsafe-eval' is not reported as loosening", () => {
  const prev = manifest({ csp: "script-src 'self'" });
  const next = manifest({ csp: "script-src 'self' 'wasm-unsafe-eval'" });
  const changes = diff(prev, next);
  assert.equal(ofKind(changes, "csp_changed").length, 0);
});

test("update URL moving off Google is reported (H2)", () => {
  const prev = manifest({ updateUrl: "https://clients2.google.com/service/update2/crx" });
  const next = manifest({ updateUrl: "https://updates.evil.example/x.xml" });
  const changes = diff(prev, next);
  assert.deepEqual(ofKind(changes, "update_url_changed"), [
    { kind: "update_url_changed", value: "https://updates.evil.example/x.xml", severity: "high" },
  ]);
});

test("a score rise of 15 or more is reported even without a named cause (H2)", () => {
  const changes = diff(manifest(), manifest({ permissions: ["debugger"] }));
  assert.deepEqual(ofKind(changes, "score_jump"), [
    { kind: "score_jump", value: "0 -> 30", severity: "critical" },
  ]);
});

test("scripting added while holding broad hosts is critical (H3)", () => {
  const prev = manifest({ hostPermissions: ["<all_urls>"] });
  const next = manifest({ hostPermissions: ["<all_urls>"], permissions: ["scripting"] });
  const changes = diff(prev, next);
  assert.deepEqual(ofKind(changes, "permission_added"), [
    { kind: "permission_added", value: "scripting", severity: "critical" },
  ]);
});

test("webRequest added alone is low, not high (H3)", () => {
  const changes = diff(manifest(), manifest({ permissions: ["webRequest"] }));
  assert.deepEqual(ofKind(changes, "permission_added"), [
    { kind: "permission_added", value: "webRequest", severity: "low" },
  ]);
});

test("webRequest with webRequestBlocking added together is high (H3)", () => {
  const changes = diff(manifest(), manifest({ permissions: ["webRequest", "webRequestBlocking"] }));
  assert.deepEqual(ofKind(changes, "permission_added").map((c) => c.severity), ["high", "high"]);
});
