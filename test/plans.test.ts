import test from "node:test";
import assert from "node:assert/strict";
import { applySnapshots } from "../src/worker.js";
import { effectivePlan, idsToCheck, trialDaysLeft, type Snapshot, type Watchlist } from "../src/store.js";
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
  const store = new Map<string, { v: string; m?: unknown; ttl?: number }>();
  const kv = {
    get: async (k: string) => store.get(k)?.v ?? null,
    put: async (k: string, v: string, o?: { expirationTtl?: number; metadata?: unknown }) => { store.set(k, { v, m: o?.metadata, ttl: o?.expirationTtl }); },
    delete: async (k: string) => { store.delete(k); },
    list: async ({ prefix }: { prefix: string }) => ({ keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name, metadata: store.get(name)?.m })), list_complete: true }),
  };
  return { store, kv };
}

const jsonReq = (url: string, method: string, body?: unknown, ct = "application/json") =>
  new Request(url, { method, headers: { "content-type": ct, "cf-connecting-ip": "7.7.7.7" }, body: body === undefined ? undefined : JSON.stringify(body) });

const OPERATOR = "operator-code-for-tests-0123456789";
const TEST_SALT = "test-address-salt-0123456789";

async function seed(over: Partial<Watchlist> = {}) {
  const { store, kv } = memKv();
  const base = list();
  applySnapshots(base, [snap(man())], true);
  const wl: Watchlist = { ...base, viewToken: VIEWER, ...over };
  await kv.put("wl:" + ADMIN, JSON.stringify(wl), { metadata: { lastCheck: wl.lastCheck } });
  await kv.put("vw:" + VIEWER, ADMIN);
  const mod = await import("../src/worker.js");
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, OPERATOR_CODE: OPERATOR, ADDRESS_SALT: TEST_SALT };
  const call = (path: string, method = "GET", body?: unknown, ct = "application/json", headers: Record<string, string> = {}) => {
    const req = jsonReq("http://x" + path, method, body, ct);
    for (const [k, v] of Object.entries(headers)) req.headers.set(k, v);
    return mod.default.fetch(req, env as never);
  };
  return { store, kv, wl, call, env, mod };
}

test("a new list starts on the Team trial and the badge shows the days left", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const { manifestCrxForTest } = await import("./helpers.js");
  const body = manifestCrxForTest({ manifest_version: 3, name: "Calc", version: "1", permissions: ["storage"] }) as unknown as BodyInit;
  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response(body, { status: 200 })) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, ADDRESS_SALT: TEST_SALT };
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
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, ADDRESS_SALT: TEST_SALT };
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
    assert.match(body.error, /github\.com\/theluckystrike/, "the operator address is in the 402 body");
    assert.match(body.error, /https:\/\/github\.com\/theluckystrike\/extension-watch\/issues/, "the issues link is in the 402 body");
    assert.match(body.error, /Never post your admin link in a public issue\./, "the 402 body warns about posting the admin link");
    assert.ok(!body.error.replace(/https?:\/\/\S+/g, "").includes(":"), "the message has no colon outside a URL");
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
  const res = await call("/api/watchlists/" + ADMIN + "/plan", "PUT", { plan: "team" }, "application/json", { "x-operator-code": OPERATOR });
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
  const op = { "x-operator-code": OPERATOR };
  assert.equal((await call("/api/watchlists/" + VIEWER + "/plan", "PUT", { plan: "team" }, "application/json", op)).status, 404, "the read-only link cannot change a plan");
  assert.equal((await call("/api/watchlists/" + "Z".repeat(43) + "/plan", "PUT", { plan: "team" }, "application/json", op)).status, 404);
  assert.equal((await call("/api/watchlists/" + ADMIN + "/plan", "PUT", { plan: "pro" }, "application/json", op)).status, 400);
  assert.equal((await call("/api/watchlists/" + ADMIN + "/plan", "PUT", { plan: ["team"] }, "application/json", op)).status, 400, "a plan that is not text is refused");
});

test("the admin link alone cannot upgrade its own list", async () => {
  const { call } = await seed({ plan: "free" });
  assert.equal((await call("/api/watchlists/" + ADMIN + "/plan", "PUT", { plan: "team" })).status, 403);
  assert.equal((await call("/api/watchlists/" + ADMIN + "/plan", "PUT", { plan: "team" }, "application/json", { "x-operator-code": "wrong" })).status, 403);
  const data = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { usage: { plan: string } };
  assert.equal(data.usage.plan, "free");
});

test("a Free list that held more ids on the trial is checked for 25 of them", () => {
  const ids = Array.from({ length: 30 }, (_, i) => String.fromCharCode(97 + (i % 16)).repeat(31) + String.fromCharCode(97 + (i % 16)));
  const free: Watchlist = { ...list(), ids, plan: "free" };
  assert.equal(idsToCheck(free).length, 25);
  const team: Watchlist = { ...list(), ids, plan: "team" };
  assert.equal(idsToCheck(team).length, 30);
});

const crxOk = async (): Promise<Response> => {
  const { manifestCrxForTest } = await import("./helpers.js");
  const body = manifestCrxForTest({ manifest_version: 3, name: "Calc", version: "1", permissions: ["storage"] }) as unknown as BodyInit;
  return new Response(body, { status: 200 });
};

test("three trials per address, a fourth new list inside the window starts Free with a plain note", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const real = globalThis.fetch;
  globalThis.fetch = (async () => crxOk()) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, ADDRESS_SALT: TEST_SALT };
  const create = async (name: string, i: number) =>
    await (await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name, ids: [idAt(i)] }), env as never)).json() as { token: string; plan: string; note?: string };
  try {
    for (let i = 0; i < 3; i++) {
      const list = await create("T" + i, i);
      assert.equal(list.plan, "trial", "list " + (i + 1) + " gets the trial");
      assert.equal(list.note, undefined, "no note while trials remain");
    }
    const fourth = await create("D", 3);
    assert.equal(fourth.plan, "free", "a fourth list from the same address starts Free");
    assert.match(fourth.note ?? "", /trial/i, "the response carries a plain note about the trial");
    assert.ok(!(fourth.note ?? "").includes(":"), "the note has no colon");
    const data = await (await mod.default.fetch(jsonReq("http://x/api/watchlists/" + fourth.token, "GET"), env as never)).json() as { usage: { plan: string } };
    assert.equal(data.usage.plan, "free", "the fourth list is on Free");
  } finally { globalThis.fetch = real; }
});

test("the trial marker stores a SHA-256 hash of the address with a 30 day TTL", async () => {
  const mod = await import("../src/worker.js");
  const { kv, store } = memKv();
  const real = globalThis.fetch;
  globalThis.fetch = (async () => crxOk()) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, ADDRESS_SALT: TEST_SALT };
  try {
    await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name: "A", ids: [idAt(0)] }), env as never);
  } finally { globalThis.fetch = real; }
  const marker = [...store.keys()].find((k) => k.startsWith("tri:"));
  assert.ok(marker, "a trial marker is written");
  assert.ok(!marker!.includes("7.7.7.7"), "the raw address is never stored in the key");
  assert.match(marker!.slice(4).split(":")[0]!, /^[0-9a-f]{64}$/, "the key holds a hex SHA-256 of the address");
  assert.equal(store.get(marker!)?.ttl, 30 * 86400, "the marker expires in 30 days");
});

test("an explicit Free list does not consume the trial, and an expired marker grants a new one", async () => {
  const mod = await import("../src/worker.js");
  const { kv, store } = memKv();
  const real = globalThis.fetch;
  globalThis.fetch = (async () => crxOk()) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, ADDRESS_SALT: TEST_SALT };
  try {
    const free = await (await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name: "F", ids: [idAt(0)], plan: "free" }), env as never)).json() as { plan: string };
    assert.equal(free.plan, "free");
    assert.equal([...store.keys()].some((k) => k.startsWith("tri:")), false, "asking for Free does not spend the trial");
    const trial = await (await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name: "T", ids: [idAt(1)] }), env as never)).json() as { plan: string };
    assert.equal(trial.plan, "trial", "the trial is still available");
    for (const key of [...store.keys()]) if (key.startsWith("tri:")) store.delete(key);
    const again = await (await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name: "T2", ids: [idAt(2)] }), env as never)).json() as { plan: string };
    assert.equal(again.plan, "trial", "after the marker expires a new trial is granted");
  } finally { globalThis.fetch = real; }
});

test("address hashes are salted and rate limit keys never hold the raw address", async () => {
  const store = await import("../src/store.js");
  store.setAddressSalt("salt-a-0123456789");
  const a = await store.addressHash("203.0.113.7");
  store.setAddressSalt("salt-b-0123456789");
  const b = await store.addressHash("203.0.113.7");
  assert.notEqual(a, b, "a different salt gives a different hash");
  const { kv, store: raw } = memKv();
  assert.equal(await store.allow(kv, "203.0.113.7", "scan", 5, "2026-10-19"), true);
  const keys = [...raw.keys()].filter((k) => k.startsWith("rl:"));
  assert.equal(keys.length, 1);
  assert.ok(!keys[0]!.includes("203.0.113.7"), keys[0]);
  store.setAddressSalt(undefined);
});

test("IPv6 addresses hash by their /64 prefix, compressed and full forms agree, IPv4 stays whole", async () => {
  const store = await import("../src/store.js");
  store.setAddressSalt(TEST_SALT);
  try {
    const compressed = await store.addressHash("2001:db8:85a3::8a2e:370:7334");
    const full = await store.addressHash("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    assert.equal(compressed, full, "the same /64 hashes the same in both forms");
    const next = await store.addressHash("2001:db8:85a3:1::1");
    assert.notEqual(compressed, next, "a different /64 hashes differently");
    const v4a = await store.addressHash("203.0.113.7");
    const v4b = await store.addressHash("203.0.113.8");
    assert.notEqual(v4a, v4b, "IPv4 addresses are hashed whole, not by a prefix");
  } finally {
    store.setAddressSalt(undefined);
  }
});

test("an IPv4 mapped IPv6 address is hashed as the embedded IPv4 address", async () => {
  const store = await import("../src/store.js");
  store.setAddressSalt(TEST_SALT);
  try {
    const mapped = await store.addressHash("::ffff:203.0.113.7");
    const v4 = await store.addressHash("203.0.113.7");
    assert.equal(mapped, v4, "the mapped form hashes like the IPv4 it stands for");
    assert.equal(store.normalizedAddress("::ffff:203.0.113.7"), "203.0.113.7");
    assert.equal(store.normalizedAddress("[::ffff:198.51.100.9]"), "198.51.100.9");
    assert.notEqual(mapped, await store.addressHash("::ffff:198.51.100.9"), "distinct clients do not share one bucket");
    assert.notEqual(store.normalizedAddress("::1"), store.normalizedAddress("::ffff:203.0.113.7"), "the loopback form stays IPv6");
  } finally {
    store.setAddressSalt(undefined);
  }
});

test("five simultaneous trial claims for one address grant exactly three", async () => {
  const store = await import("../src/store.js");
  store.setAddressSalt(TEST_SALT);
  const { kv, store: raw } = memKv();
  try {
    const results = await Promise.all(Array.from({ length: 5 }, () => store.claimTrial(kv, "198.51.100.9")));
    const granted = results.filter(Boolean).length;
    assert.equal(granted, 3, "exactly 3 claims succeed, got " + granted);
    const markers = [...raw.keys()].filter((k) => k.startsWith("tri:"));
    assert.equal(markers.length, granted, "a refused claim removes its own marker");
  } finally {
    store.setAddressSalt(undefined);
  }
});

test("an old-format trial record counts as its stored attempts and the next claim is the last one", async () => {
  const store = await import("../src/store.js");
  store.setAddressSalt(TEST_SALT);
  const { kv, store: raw } = memKv();
  try {
    const hash = await store.addressHash("198.51.100.10");
    const first = Date.now() - 2 * 86_400_000;
    await kv.put("tri:" + hash, JSON.stringify({ count: 2, first }));
    assert.equal(await store.claimTrial(kv, "198.51.100.10"), true, "the third attempt inside the window is granted");
    assert.equal(await store.claimTrial(kv, "198.51.100.10"), false, "a fourth attempt is refused");
    assert.equal([...raw.keys()].filter((k) => k.startsWith("tri:")).length, 2, "the old counter key and the one granted marker remain");
  } finally {
    store.setAddressSalt(undefined);
  }
});

test("an old-format trial record that is a plain date string still counts as one attempt", async () => {
  const store = await import("../src/store.js");
  store.setAddressSalt(TEST_SALT);
  const { kv, store: raw } = memKv();
  try {
    const hash = await store.addressHash("198.51.100.11");
    await kv.put("tri:" + hash, new Date(Date.now() - 86_400_000).toISOString());
    assert.equal(await store.claimTrial(kv, "198.51.100.11"), true);
    assert.equal(await store.claimTrial(kv, "198.51.100.11"), true);
    assert.equal(await store.claimTrial(kv, "198.51.100.11"), false, "the old record counts, so only two more fit");
    assert.equal([...raw.keys()].filter((k) => k.startsWith("tri:")).length, 3);
  } finally {
    store.setAddressSalt(undefined);
  }
});

test("a missing or short ADDRESS_SALT returns 503 on the trial and rate limit paths and logs one line", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const logs: string[] = [];
  const real = console.error;
  console.error = (...args: unknown[]) => { logs.push(args.map(String).join(" ")); };
  try {
    for (const salt of [undefined, "short"]) {
      const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, ADDRESS_SALT: salt };
      const scan = await mod.default.fetch(jsonReq("http://x/api/scan", "POST", { ids: [idAt(0)] }), env as never);
      assert.equal(scan.status, 503);
      assert.deepEqual(await scan.json(), { error: "server misconfigured, address salt missing" });
      const create = await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name: "A", ids: [idAt(1)] }), env as never);
      assert.equal(create.status, 503);
      assert.deepEqual(await create.json(), { error: "server misconfigured, address salt missing" });
    }
    assert.equal(logs.length, 4, "one log line for each refused request");
    assert.match(logs[0]!, /server misconfigured, address salt missing/);
  } finally {
    console.error = real;
  }
});
