import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import ts from "typescript";
import { diff } from "../src/diff";
import type { Manifest } from "../src/types";

function manifest(overrides: Partial<Manifest> = {}): Manifest {
  return {
    id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    name: "Test Extension",
    version: "1.0.0",
    manifestVersion: 2,
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

// Inputs chosen so that diff() reaches every push() call site.
const prev = manifest();
const next = manifest({
  manifestVersion: 3,
  permissions: ["tabs"],
  optionalPermissions: ["history"],
  hostPermissions: ["<all_urls>"],
  contentScriptMatches: ["<all_urls>"],
  externallyConnectable: ["*"],
  csp: "script-src 'self' 'unsafe-eval'",
  updateUrl: "https://example.invalid/update.xml",
});

const emitted = [
  ...diff(null, next),
  ...diff(prev, null),
  ...diff(prev, next),
  ...diff(next, prev),
].map((c) => c.kind);

// Every kind that diff() can emit must be assignable to Change["kind"].
// Type-only, so the check compiles a fixture instead of running it.
const root = path.resolve(import.meta.dirname, "..");
const fixturePath = path.join(root, "test", "__change_kinds_fixture.ts");
const fixture = `
import type { Change } from "../src/types";
const kinds: Change["kind"][] = [
${[...new Set(emitted)].map((k) => `  ${JSON.stringify(k)},`).join("\n")}
];
export default kinds;
`;

test("diff() emits the full set of kinds the Change union must cover", () => {
  assert.deepEqual([...new Set(emitted)].sort(), [
    "content_script_added", "content_script_removed", "csp_changed", "externally_connectable_added",
    "host_added", "host_removed", "mv_changed", "new_extension", "optional_added",
    "permission_added", "permission_removed", "removed_from_store", "score_jump", "update_url_changed",
  ]);
});

test("Change kind union covers every kind diff() emits", () => {
  const options: ts.CompilerOptions = { strict: true, noEmit: true, target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, types: [] };
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile;
  host.getSourceFile = (name, languageVersion, ...rest) =>
    path.resolve(name) === fixturePath
      ? ts.createSourceFile(name, fixture, languageVersion)
      : getSourceFile(name, languageVersion, ...rest);
  const program = ts.createProgram([fixturePath], options, host);
  const messages = ts
    .getPreEmitDiagnostics(program)
    .map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
  assert.deepEqual(messages, []);
});
