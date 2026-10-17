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
  applySnapshots(wl, [{ ...snap(null, "Download failed: HTTP 503"), transient: true }], false);
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
    const stored = JSON.parse(store.get("wl:" + token)!);
    store.set("wl:" + token, JSON.stringify({ ...stored, webhook: null }));
    await mod.default.scheduled({}, env as never);
    assert.equal(fetched, 0, "no webhook and idle for more than 90 days: not re-checked");
    store.set("wl:" + token, JSON.stringify(stored));
    const res = await mod.default.fetch(new Request("http://x/api/watchlists/" + token), env as never);
    const body = await res.json() as { webhook: string; webhookSet: boolean };
    assert.equal(body.webhookSet, true);
    assert.ok(!body.webhook.includes("secret"));
    assert.ok(JSON.parse(store.get("wl:" + token)!).viewedAt);
  } finally { globalThis.fetch = real; }
});

// In-memory KV with metadata, enough for the worker routes and the scheduler.
function memKv() {
  const store = new Map<string, { v: string; m?: unknown }>();
  const kv = {
    get: async (k: string) => store.get(k)?.v ?? null,
    put: async (k: string, v: string, o?: { metadata?: unknown }) => { store.set(k, { v, m: o?.metadata }); },
    delete: async (k: string) => { store.delete(k); },
    list: async ({ prefix }: { prefix: string }) => ({ keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name, metadata: store.get(name)?.m })), list_complete: true }),
  };
  return { store, kv };
}
const jsonReq = (url: string, method: string, body?: unknown, ct = "application/json") =>
  new Request(url, { method, headers: { "content-type": ct, "cf-connecting-ip": "7.7.7.7" }, body: body === undefined ? undefined : JSON.stringify(body) });
const seeded = (token: string, over: Partial<ReturnType<typeof list>> = {}) => {
  const base = list();
  applySnapshots(base, [snap(man())], true);
  const wl = { ...base, ...over };
  return { wl, put: (kv: { put: (k: string, v: string, o?: { metadata?: unknown }) => Promise<void> }) => kv.put("wl:" + token, JSON.stringify(wl), { metadata: { lastCheck: wl.lastCheck } }) };
};

test("N1: alerts still go out when the change log is already full", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const token = "B".repeat(43);
  const full = Array.from({ length: 200 }, () => ({ kind: "version_changed", value: "1 to 1", severity: "low" as const, id: "a".repeat(32), at: "2026-01-01T00:00:00Z" }));
  const { wl, put } = seeded(token, { webhook: "https://hooks.slack.com/services/x", lastCheck: "2026-01-01T00:00:00Z", viewedAt: new Date().toISOString() });
  wl.changes = full;
  await put(kv);
  const posts: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    if (String(url).includes("hooks.slack.com")) { posts.push(String(init?.body)); return new Response("ok"); }
    const { manifestCrxForTest } = await import("./helpers.js");
    return new Response(manifestCrxForTest({ manifest_version: 3, name: "Calc", version: "2", permissions: ["storage", "cookies"] }) as unknown as BodyInit, { status: 200 });
  }) as typeof fetch;
  try { await mod.default.scheduled({}, { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } } as never); } finally { globalThis.fetch = real; }
  assert.equal(posts.length, 1);
  assert.match(posts[0]!, /cookies/);
});

test("N2/N3: a list of removed extensions counts as checked, is cached, and cannot starve other lists", async () => {
  const mod = await import("../src/worker.js");
  const { kv, store } = memKv();
  const old = "2026-01-01T00:00:00Z";
  for (let n = 0; n < 3; n++) {
    const wl = { ...list(), ids: Array.from({ length: 50 }, (_, i) => String.fromCharCode(97 + n) + "b".repeat(29) + String.fromCharCode(97 + (i % 16)) + String.fromCharCode(97 + Math.floor(i / 16))), lastCheck: old, viewedAt: new Date().toISOString() };
    await kv.put("wl:" + String(n).repeat(43), JSON.stringify(wl), { metadata: { lastCheck: old } });
  }
  const customer = "C".repeat(43);
  await kv.put("wl:" + customer, JSON.stringify({ ...list(), ids: ["p".repeat(32)], lastCheck: "2026-01-02T00:00:00Z", viewedAt: new Date().toISOString() }), { metadata: { lastCheck: "2026-01-02T00:00:00Z" } });
  let downloads = 0;
  const real = globalThis.fetch;
  globalThis.fetch = (async () => { downloads++; return new Response(null, { status: 204 }); }) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } };
  try {
    await mod.default.scheduled({}, env as never);
    assert.ok(downloads <= 40, `budget is a hard limit, got ${downloads}`);
    for (let r = 0; r < 6; r++) await mod.default.scheduled({}, env as never);
  } finally { globalThis.fetch = real; }
  assert.notEqual(JSON.parse(store.get("wl:" + customer)!.v).lastCheck, "2026-01-02T00:00:00Z", "the customer list was checked");
  assert.notEqual(JSON.parse(store.get("wl:" + "0".repeat(43))!.v).lastCheck, old, "a list of removed extensions counts as checked");
});

test("N5: a text/plain request that mentions application/json is rejected", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const res = await mod.default.fetch(jsonReq("http://x/api/scan", "POST", { ids: "a".repeat(32) }, "text/plain; application/json"), { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } } as never);
  assert.equal(res.status, 415);
});

test("N6: the read-only link shows the list but cannot change alerts or delete it", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const admin = "D".repeat(43);
  const { put } = seeded(admin, { webhook: "https://hooks.slack.com/services/T/B/SECRET" });
  await put(kv);
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } } as never;
  const a = await (await mod.default.fetch(jsonReq("http://x/api/watchlists/" + admin, "GET"), env)).json() as { role: string; viewToken: string; webhook: string };
  assert.equal(a.role, "admin");
  assert.equal(a.webhook, "https://hooks.slack.com/...");
  const v = await (await mod.default.fetch(jsonReq("http://x/api/watchlists/" + a.viewToken, "GET"), env)).json() as { role: string; webhook: unknown; viewToken?: string };
  assert.equal(v.role, "viewer");
  assert.equal(v.webhook, null);
  assert.equal(v.viewToken, undefined);
  assert.equal((await mod.default.fetch(jsonReq("http://x/api/watchlists/" + a.viewToken, "PUT", { webhook: "https://evil.example/x" }), env)).status, 404);
  assert.equal((await mod.default.fetch(jsonReq("http://x/api/watchlists/" + a.viewToken, "DELETE"), env)).status, 404);
  assert.equal((await mod.default.fetch(jsonReq("http://x/api/watchlists/" + admin, "DELETE"), env)).status, 200);
  assert.equal((await mod.default.fetch(jsonReq("http://x/api/watchlists/" + a.viewToken, "GET"), env)).status, 404);
});

test("N7: a list with a webhook keeps being checked after 90 days without a page view", async () => {
  const mod = await import("../src/worker.js");
  const { kv, store } = memKv();
  const token = "E".repeat(43);
  const { put } = seeded(token, { webhook: "https://hooks.slack.com/services/x", lastCheck: "2026-01-01T00:00:00Z", viewedAt: new Date(Date.now() - 200 * 86400000).toISOString() });
  await put(kv);
  const real = globalThis.fetch;
  globalThis.fetch = (async (url: string) => String(url).includes("hooks.slack.com") ? new Response("ok") : new Response(null, { status: 204 })) as typeof fetch;
  try { await mod.default.scheduled({}, { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } } as never); } finally { globalThis.fetch = real; }
  assert.notEqual(JSON.parse(store.get("wl:" + token)!.v).lastCheck, "2026-01-01T00:00:00Z");
});

test("N8: the burst limit binding answers 429 on writes", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  let n = 0;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, WRITE_LIMIT: { limit: async () => ({ success: ++n <= 2 }) } } as never;
  const statuses = [];
  for (let i = 0; i < 3; i++) statuses.push((await mod.default.fetch(jsonReq("http://x/api/scan", "POST", { ids: "x" }), env)).status);
  assert.deepEqual(statuses, [400, 400, 429]);
});


test("P3: an update that can no longer be read is logged as a high-severity change", () => {
  const wl = list();
  applySnapshots(wl, [snap(man())], true);
  applySnapshots(wl, [snap(null, "Invalid ZIP central directory")], false);
  applySnapshots(wl, [snap(null, "Invalid ZIP central directory")], false);
  assert.deepEqual(wl.changes.map((c) => [c.kind, c.severity]), [["unreadable", "high"]]);
});

test("P1: a list stays due until every extension got an answer, then completes on the next run", async () => {
  const mod = await import("../src/worker.js");
  const { kv, store } = memKv();
  const token = "F".repeat(43);
  const ids = Array.from({ length: 50 }, (_, i) => "k".repeat(30) + String.fromCharCode(97 + (i % 16)) + String.fromCharCode(97 + Math.floor(i / 16)));
  const wl = { ...list(), ids, lastCheck: "2026-01-01T00:00:00Z", viewedAt: new Date().toISOString() };
  await kv.put("wl:" + token, JSON.stringify(wl), { metadata: { lastCheck: wl.lastCheck } });
  const { manifestCrxForTest } = await import("./helpers.js");
  const body = manifestCrxForTest({ manifest_version: 3, name: "X", version: "1", permissions: ["storage"] }) as unknown as BodyInit;
  let downloads = 0;
  const real = globalThis.fetch;
  globalThis.fetch = (async () => { downloads++; return new Response(body, { status: 200 }); }) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } } as never;
  try {
    await mod.default.scheduled({}, env);
    assert.equal(JSON.parse(store.get("wl:" + token)!.v).lastCheck, "2026-01-01T00:00:00Z", "40 of 50 done: still due");
    await mod.default.scheduled({}, env);
  } finally { globalThis.fetch = real; }
  const after = JSON.parse(store.get("wl:" + token)!.v);
  assert.notEqual(after.lastCheck, "2026-01-01T00:00:00Z");
  assert.equal(Object.values(after.snapshots as Record<string, { manifest: unknown }>).filter((x) => x.manifest).length, 50);
  assert.equal(downloads, 50);
});

test("P2: the test alert carries the read-only link, never the admin link", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const admin = "G".repeat(43);
  const { put } = seeded(admin, { webhook: "https://hooks.slack.com/services/x" });
  await put(kv);
  const bodies: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (_u: string, init?: RequestInit) => { bodies.push(String(init?.body)); return new Response("ok"); }) as typeof fetch;
  try {
    const res = await mod.default.fetch(jsonReq("http://x/api/test-alert", "POST", { token: admin }), { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } } as never);
    assert.equal(res.status, 200);
  } finally { globalThis.fetch = real; }
  assert.ok(!bodies[0]!.includes(admin), "admin token must not be posted to chat");
  assert.match(bodies[0]!, /\/w\/[A-Za-z0-9_-]{43}/);
});


test("P8: a list with a webhook stops being checked after 365 days without a view", async () => {
  const mod = await import("../src/worker.js");
  const { kv, store } = memKv();
  const token = "H".repeat(43);
  const { put } = seeded(token, { webhook: "https://hooks.slack.com/services/x", lastCheck: "2026-01-01T00:00:00Z", viewedAt: new Date(Date.now() - 400 * 86400000).toISOString() });
  await put(kv);
  let fetched = 0;
  const real = globalThis.fetch;
  globalThis.fetch = (async () => { fetched++; return new Response(null, { status: 204 }); }) as typeof fetch;
  try { await mod.default.scheduled({}, { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } } as never); } finally { globalThis.fetch = real; }
  assert.equal(fetched, 0);
  assert.equal(JSON.parse(store.get("wl:" + token)!.v).lastCheck, "2026-01-01T00:00:00Z");
});

test("P7: a webhook removed while a check runs stays removed", async () => {
  const mod = await import("../src/worker.js");
  const { kv, store } = memKv();
  const token = "J".repeat(43);
  const { put } = seeded(token, { webhook: "https://hooks.example.com/old", lastCheck: "2026-01-01T00:00:00Z", viewedAt: new Date().toISOString() });
  await put(kv);
  const real = globalThis.fetch;
  globalThis.fetch = (async () => {
    const wl = JSON.parse(store.get("wl:" + token)!.v); wl.webhook = null; store.set("wl:" + token, { v: JSON.stringify(wl) }); // admin turns alerts off mid-check
    return new Response(null, { status: 204 });
  }) as typeof fetch;
  try { await mod.default.scheduled({}, { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } } as never); } finally { globalThis.fetch = real; }
  assert.equal(JSON.parse(store.get("wl:" + token)!.v).webhook, null);
});
