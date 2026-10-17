import { test } from "node:test";
import assert from "node:assert/strict";
import { diff } from "../src/diff";
import type { Manifest } from "../src/types";

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
  assert.deepEqual(changes, [{ kind: "permission_added", value: "debugger", severity: "critical" }]);
});

test("permission removed is reported", () => {
  const changes = diff(manifest({ permissions: ["cookies"] }), manifest());
  assert.deepEqual(changes, [{ kind: "permission_removed", value: "cookies", severity: "high" }]);
});

test("host added is critical, host removed is low", () => {
  const changes = diff(manifest(), manifest({ hostPermissions: ["<all_urls>"] }));
  assert.deepEqual(changes, [{ kind: "host_added", value: "<all_urls>", severity: "critical" }]);

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
  assert.deepEqual(changes, [{ kind: "permission_added", value: "cookies", severity: "high" }]);
});

test("multiple changes are all reported", () => {
  const prev = manifest({ permissions: ["tabs"], hostPermissions: ["https://a.example/*"] });
  const next = manifest({
    permissions: ["tabs", "debugger"],
    hostPermissions: ["https://a.example/*", "<all_urls>"],
  });
  const changes = diff(prev, next);
  const kinds = changes.map((c) => c.kind).sort();
  assert.deepEqual(kinds, ["host_added", "permission_added"]);
});
