import test from "node:test";
import assert from "node:assert/strict";
import { applySnapshots } from "../src/worker.js";
import type { Snapshot, Watchlist } from "../src/store.js";
import type { Manifest } from "../src/types.js";

const man = (over: Partial<Manifest> = {}): Manifest => ({ id: "a".repeat(32), name: "Calc", version: "1", manifestVersion: 3, permissions: ["storage"],
  optionalPermissions: [], hostPermissions: [], contentScriptMatches: [], externallyConnectable: [], hasBackground: false, csp: null, updateUrl: null, description: "", ...over });
const snap = (m: Manifest | null, error: string | null = null): Snapshot => ({ id: "a".repeat(32), manifest: m, assessment: null, error, checkedAt: new Date().toISOString() });
const list = (): Watchlist => ({ name: "t", ids: ["a".repeat(32)], snapshots: {}, changes: [], createdAt: "2026-01-01T00:00:00Z", lastCheck: "2026-01-01T00:00:00Z" });

test("baseline creation records no 'new extension' noise", () => {
  const wl = list();
  applySnapshots(wl, [snap(man())], true);
  assert.equal(wl.changes.length, 0);
  assert.ok(wl.snapshots["a".repeat(32)]?.manifest);
});

test("a store takedown is recorded once, high, and the last manifest is kept", () => {
  const wl = list();
  applySnapshots(wl, [snap(man())], true);
  applySnapshots(wl, [snap(null, "Not on the Chrome Web Store")], false);
  assert.deepEqual(wl.changes.map((c) => [c.kind, c.severity]), [["removed_from_store", "high"]]);
  assert.equal(wl.snapshots["a".repeat(32)]?.manifest?.name, "Calc");
});

test("a failed check does not move 'last checked' and keeps the last good snapshot", () => {
  const wl = list();
  applySnapshots(wl, [snap(man())], true);
  const before = wl.lastCheck;
  applySnapshots(wl, [snap(null, "Download failed: HTTP 503")], false);
  assert.equal(wl.lastCheck, before);
  assert.equal(wl.changes.length, 0);
  assert.equal(wl.snapshots["a".repeat(32)]?.error, "Download failed: HTTP 503");
});

test("an update that adds a permission is recorded", () => {
  const wl = list();
  applySnapshots(wl, [snap(man())], true);
  applySnapshots(wl, [snap(man({ version: "2", permissions: ["storage", "cookies"] }))], false);
  assert.ok(wl.changes.some((c) => c.kind === "permission_added" && c.value === "cookies"));
});

test("a takedown is a completed check and is recorded only once", () => {
  const wl = list();
  applySnapshots(wl, [snap(man())], true);
  wl.lastCheck = "2026-01-01T00:00:00Z";
  applySnapshots(wl, [snap(null, "Not on the Chrome Web Store")], false);
  applySnapshots(wl, [snap(null, "Not on the Chrome Web Store")], false);
  assert.equal(wl.changes.filter((c) => c.kind === "removed_from_store").length, 1);
  assert.notEqual(wl.lastCheck, "2026-01-01T00:00:00Z");
});

test("reads mask the webhook and record the view; idle lists are not re-checked", async () => {
  const mod = await import("../src/worker.js");
  const store = new Map<string, string>();
  const kv = { get: async (k: string) => store.get(k) ?? null, put: async (k: string, v: string) => { store.set(k, v); }, delete: async (k: string) => { store.delete(k); },
    list: async () => ({ keys: [...store.keys()].filter((k) => k.startsWith("wl:")).map((name) => ({ name, metadata: { lastCheck: "2026-01-01T00:00:00Z" } })), list_complete: true }) };
  const token = "A".repeat(43);
  const wl = { ...list(), webhook: "https://hooks.slack.com/services/T000/B000/secretsecret", createdAt: "2026-01-01T00:00:00Z" };
  applySnapshots(wl, [snap(man())], true);
  wl.lastCheck = "2026-01-01T00:00:00Z";
  store.set("wl:" + token, JSON.stringify(wl));
  let fetched = 0;
  const real = globalThis.fetch;
  globalThis.fetch = (async () => { fetched++; return new Response(null, { status: 204 }); }) as typeof fetch;
  try {
    const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } };
    await mod.default.scheduled({}, env as never);
    assert.equal(fetched, 0, "idle for more than 90 days: not re-checked");
    const res = await mod.default.fetch(new Request("http://x/api/watchlists/" + token), env as never);
    const body = await res.json() as { webhook: string; webhookSet: boolean };
    assert.equal(body.webhookSet, true);
    assert.ok(!body.webhook.includes("secret"));
    assert.ok(JSON.parse(store.get("wl:" + token)!).viewedAt);
  } finally { globalThis.fetch = real; }
});
