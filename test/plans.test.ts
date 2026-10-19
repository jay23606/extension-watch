import test from "node:test";
import assert from "node:assert/strict";
import { applySnapshots } from "../src/worker.js";
import { effectivePlan, trialDaysLeft, type Snapshot, type Watchlist } from "../src/store.js";
import type { Manifest } from "../src/types.js";

const ADMIN = "M".repeat(43);
const VIEWER = "N".repeat(43);

/** Distinct 32-character extension ids from the a to p alphabet the API accepts. */
const idAt = (n: number): string => {
  let out = "";
  let value = n;
  for (let i = 0; i < 32; i++) { out = String.fromCharCode(97 + (value % 16)) + out; value = Math.floor(value / 16); }
  return out;
};

const man = (over: Partial<Manifest> = {}): Manifest => ({ id: idAt(0), name: "Calc", version: "1", manifestVersion: 3, permissions: ["storage"],
  optionalPermissions: [], hostPermissions: [], contentScriptMatches: [], externallyConnectable: [], hasBackground: false, csp: null, updateUrl: null, description: "", ...over });
const snap = (m: Manifest | null, error: string | null = null): Snapshot => ({ id: m?.id ?? idAt(0), manifest: m, assessment: null, error, checkedAt: new Date().toISOString() });
const list = (): Watchlist => ({ name: "t", ids: [idAt(0)], snapshots: {}, changes: [], createdAt: "2026-01-01T00:00:00Z", lastCheck: "2026-01-01T00:00:00Z" });

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

async function seed(over: Partial<Watchlist> = {}) {
  const { store, kv } = memKv();
  const base = list();
  applySnapshots(base, [snap(man())], true);
  const wl: Watchlist = { ...base, viewToken: VIEWER, ...over };
  await kv.put("wl:" + ADMIN, JSON.stringify(wl), { metadata: { lastCheck: wl.lastCheck } });
  await kv.put("vw:" + VIEWER, ADMIN);
  const mod = await import("../src/worker.js");
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } };
  const call = (path: string, method = "GET", body?: unknown, ct = "application/json") =>
    mod.default.fetch(jsonReq("http://x" + path, method, body, ct), env as never);
  return { store, kv, wl, call, env, mod };
}

test("a new list starts on the Team trial and the badge shows the days left", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const { manifestCrxForTest } = await import("./helpers.js");
  const body = manifestCrxForTest({ manifest_version: 3, name: "Calc", version: "1", permissions: ["storage"] }) as unknown as BodyInit;
  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response(body, { status: 200 })) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } };
  let created: { token: string } | undefined;
  try {
    const res = await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name: "Team", ids: [idAt(0)] }), env as never);
    created = await res.json() as { token: string };
  } finally { globalThis.fetch = real; }
  const data = await (await mod.default.fetch(jsonReq("http://x/api/watchlists/" + created!.token, "GET"), env as never)).json() as { plan: string; usage: { plan: string; limit: number | null; trialDaysLeft: number } };
  assert.equal(data.plan, "trial", "a new list is stored on the trial");
  assert.equal(data.usage.plan, "team", "the trial gives Team features");
  assert.equal(data.usage.limit, null, "no id limit on Team");
  assert.ok(data.usage.trialDaysLeft >= 13 && data.usage.trialDaysLeft <= 14, "about 14 days left, got " + data.usage.trialDaysLeft);
});

test("a Free list keeps the first 25 ids and reports the rest as dropped", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const { manifestCrxForTest } = await import("./helpers.js");
  const body = manifestCrxForTest({ manifest_version: 3, name: "Calc", version: "1", permissions: ["storage"] }) as unknown as BodyInit;
  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response(body, { status: 200 })) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } };
  const ids = Array.from({ length: 30 }, (_, i) => idAt(i));
  let created: { token: string; dropped: number } | undefined;
  try {
    const res = await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name: "Free", ids, plan: "free" }), env as never);
    created = await res.json() as { token: string; dropped: number };
  } finally { globalThis.fetch = real; }
  assert.equal(created!.dropped, 5, "5 ids over the Free limit are dropped");
  const data = await (await mod.default.fetch(jsonReq("http://x/api/watchlists/" + created!.token, "GET"), env as never)).json() as { ids: string[]; plan: string; usage: { plan: string; ids: number; limit: number } };
  assert.equal(data.plan, "free");
  assert.equal(data.ids.length, 25);
  assert.deepEqual(data.usage, { plan: "free", ids: 25, limit: 25, trialDaysLeft: 0 });
});

test("a Free list gets 402 on the CSV, policy and audit exports", async () => {
  const { call } = await seed({ plan: "free", trialEndsAt: undefined });
  for (const file of ["export.csv", "changes.csv", "audit.csv", "policy.json?threshold=D"]) {
    const res = await call("/api/watchlists/" + ADMIN + "/" + file);
    assert.equal(res.status, 402, file);
    const body = await res.json() as { error: string };
    assert.match(body.error, /Free plan/, file);
    assert.ok(!body.error.includes(":"), "the message has no colon");
  }
});

test("a Free list is shown without its audit log", async () => {
  const { call } = await seed({ plan: "free" });
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: "https://hooks.slack.com/services/T/B/S" });
  const data = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { role: string; audit: unknown[]; usage: { plan: string } };
  assert.equal(data.role, "admin");
  assert.equal(data.usage.plan, "free");
  assert.deepEqual(data.audit, []);
});

test("a legacy list with no plan field counts as Team and keeps every export", async () => {
  const { call } = await seed();
  const data = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { plan?: string; usage: { plan: string } };
  assert.equal(data.plan, undefined, "no plan field is stored");
  assert.equal(data.usage.plan, "team");
  assert.equal((await call("/api/watchlists/" + ADMIN + "/export.csv")).status, 200);
  assert.equal((await call("/api/watchlists/" + ADMIN + "/audit.csv")).status, 200);
  assert.equal((await call("/api/watchlists/" + ADMIN + "/policy.json?threshold=D")).status, 200);
});

test("the admin link can set a list to Team by hand and the export opens up", async () => {
  const { call } = await seed({ plan: "free" });
  const res = await call("/api/watchlists/" + ADMIN + "/plan", "PUT", { plan: "team" });
  assert.equal(res.status, 200);
  const body = await res.json() as { plan: string; usage: { plan: string; limit: number | null } };
  assert.equal(body.plan, "team");
  assert.equal(body.usage.plan, "team");
  assert.equal(body.usage.limit, null);
  assert.equal((await call("/api/watchlists/" + ADMIN + "/export.csv")).status, 200);
  const data = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { audit: { action: string }[] };
  assert.ok(data.audit.some((e) => e.action === "plan set to team"), "the upgrade is written to the audit log");
});

test("an expired trial falls back to Free with no id plan limit change", () => {
  const ended: Watchlist = { ...list(), plan: "trial", trialEndsAt: "2020-01-01T00:00:00Z" };
  assert.equal(effectivePlan(ended), "free");
  assert.equal(trialDaysLeft(ended), 0);
  const live: Watchlist = { ...list(), plan: "trial", trialEndsAt: new Date(Date.now() + 5 * 86400000).toISOString() };
  assert.equal(effectivePlan(live), "team");
  assert.equal(trialDaysLeft(live), 5);
});

test("the plan route is admin only and rejects a plan that is not free or team", async () => {
  const { call } = await seed();
  assert.equal((await call("/api/watchlists/" + VIEWER + "/plan", "PUT", { plan: "team" })).status, 404, "the read-only link cannot change a plan");
  assert.equal((await call("/api/watchlists/" + "Z".repeat(43) + "/plan", "PUT", { plan: "team" })).status, 404);
  assert.equal((await call("/api/watchlists/" + ADMIN + "/plan", "PUT", { plan: "pro" })).status, 400);
});
