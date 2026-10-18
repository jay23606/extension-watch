import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { applySnapshots } from "../src/worker.js";
import { appendAudit, logAudit, MAX_AUDIT, readAudit, type Snapshot, type Watchlist } from "../src/store.js";
import type { Manifest } from "../src/types.js";

const ID_A = "a".repeat(32);
const ADMIN = "K".repeat(43);
const VIEWER = "V".repeat(43);
const WEBHOOK = "https://hooks.slack.com/services/T000/B000/secretsecret";

const man = (over: Partial<Manifest> = {}): Manifest => ({ id: ID_A, name: "Calc", version: "1", manifestVersion: 3, permissions: ["storage"],
  optionalPermissions: [], hostPermissions: [], contentScriptMatches: [], externallyConnectable: [], hasBackground: false, csp: null, updateUrl: null, description: "", ...over });
const snap = (m: Manifest | null, error: string | null = null): Snapshot => ({ id: ID_A, manifest: m, assessment: null, error, checkedAt: new Date().toISOString() });
const list = (): Watchlist => ({ name: "t", ids: [ID_A], snapshots: {}, changes: [], audit: [], createdAt: "2026-01-01T00:00:00Z", lastCheck: "2026-01-01T00:00:00Z" });

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
  return { store, kv, wl, call };
}

test("rotate issues a new admin token and read-only token and retires the old keys", async () => {
  const { store, kv, call } = await seed({ webhook: WEBHOOK });
  const res = await call("/api/watchlists/" + ADMIN + "/rotate", "POST");
  assert.equal(res.status, 200);
  const body = await res.json() as { token: string; viewToken: string; url: string; viewUrl: string };
  assert.match(body.token, /^[A-Za-z0-9_-]{43}$/);
  assert.match(body.viewToken, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(body.token, ADMIN);
  assert.notEqual(body.viewToken, VIEWER);
  assert.equal(body.url, "/w/" + body.token);
  assert.equal(body.viewUrl, "/w/" + body.viewToken);
  assert.equal(store.has("wl:" + ADMIN), false, "old admin key is deleted");
  assert.equal(store.has("vw:" + VIEWER), false, "old read-only key is deleted");
  assert.ok(store.has("wl:" + body.token), "the list moved to the new key");
  assert.equal(store.get("vw:" + body.viewToken)?.v, body.token, "the new read-only link points at the new admin token");
  assert.equal((await call("/api/watchlists/" + ADMIN, "GET")).status, 404, "old admin link 404");
  assert.equal((await call("/api/watchlists/" + VIEWER, "GET")).status, 404, "old read-only link 404");
  const admin = await (await call("/api/watchlists/" + body.token, "GET")).json() as { role: string; name: string };
  assert.equal(admin.role, "admin");
  assert.equal(admin.name, "t");
  const viewer = await (await call("/api/watchlists/" + body.viewToken, "GET")).json() as { role: string };
  assert.equal(viewer.role, "viewer");
});

test("rotate is admin only and only the admin token works", async () => {
  const { call } = await seed();
  assert.equal((await call("/api/watchlists/" + VIEWER + "/rotate", "POST")).status, 404);
  assert.equal((await call("/api/watchlists/" + "Z".repeat(43) + "/rotate", "POST")).status, 404);
  assert.equal((await call("/api/watchlists/" + ADMIN + "/rotate", "POST")).status, 200);
});

test("the audit log records each admin action with time and action only", async () => {
  const { call } = await seed();
  const before = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { audit: { at: string; action: string }[] };
  assert.deepEqual(before.audit.map((e) => e.action), []);
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: WEBHOOK });
  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response("ok")) as typeof fetch;
  try { await call("/api/test-alert", "POST", { token: ADMIN }); } finally { globalThis.fetch = real; }
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: "" });
  await call("/api/watchlists/" + ADMIN, "PUT", { name: "Renamed team", webhook: "" });
  await call("/api/watchlists/" + ADMIN + "/policy.json?threshold=D&mode=threshold");
  const after = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { name: string; audit: { at: string; action: string }[] };
  const actions = after.audit.map((e) => e.action);
  assert.deepEqual(actions, ["webhook set", "test alert sent", "webhook removed", "renamed", "policy exported"]);
  for (const entry of after.audit) assert.ok(entry.at && !Number.isNaN(Date.parse(entry.at)), "each entry has a real time");
  assert.equal(after.name, "Renamed team");
});

test("the audit log never stores a token or a webhook URL", async () => {
  const { call } = await seed();
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: WEBHOOK });
  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response("ok")) as typeof fetch;
  try { await call("/api/test-alert", "POST", { token: ADMIN }); } finally { globalThis.fetch = real; }
  const { audit } = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { audit: unknown };
  const text = JSON.stringify(audit);
  assert.ok(!text.includes(ADMIN) && !text.includes(VIEWER), "no token in the audit log");
  assert.ok(!text.includes("hooks.slack.com") && !text.includes("secretsecret"), "no webhook URL in the audit log");
});

test("the audit log keeps at most the newest 100 entries", () => {
  const wl = list();
  for (let i = 0; i < MAX_AUDIT + 25; i++) logAudit(wl, "action " + i);
  assert.equal(wl.audit?.length, MAX_AUDIT);
  assert.equal(wl.audit?.[MAX_AUDIT - 1]?.action, "action " + (MAX_AUDIT + 24));
});

test("the audit log survives rotate and starts with the rotate entry on the new list", async () => {
  const { call } = await seed();
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: WEBHOOK });
  const res = await call("/api/watchlists/" + ADMIN + "/rotate", "POST");
  const { token } = await res.json() as { token: string };
  const { audit } = await (await call("/api/watchlists/" + token, "GET")).json() as { audit: { action: string }[] };
  assert.deepEqual(audit.map((e) => e.action), ["webhook set", "rotate"]);
});

test("the audit CSV is served to the admin link only", async () => {
  const { call } = await seed();
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: WEBHOOK });
  const admin = await call("/api/watchlists/" + ADMIN + "/audit.csv");
  assert.equal(admin.status, 200);
  assert.match(admin.headers.get("content-type") ?? "", /text\/csv/);
  assert.match(admin.headers.get("content-disposition") ?? "", /watchlist-audit\.csv/);
  const csv = await admin.text();
  assert.match(csv, /^at,action\r\n/);
  assert.match(csv, /webhook set/);
  assert.ok(!csv.includes("hooks.slack.com"), "no webhook URL in the CSV");
  assert.equal((await call("/api/watchlists/" + VIEWER + "/audit.csv")).status, 403);
});

test("a viewer never receives the audit log", async () => {
  const { call } = await seed();
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: WEBHOOK });
  const viewer = await (await call("/api/watchlists/" + VIEWER, "GET")).json() as { audit?: unknown; role: string };
  assert.equal(viewer.role, "viewer");
  assert.equal(viewer.audit, undefined);
});

test("creating a watchlist logs a created action", async () => {
  const mod = await import("../src/worker.js");
  const { kv } = memKv();
  const { manifestCrxForTest } = await import("./helpers.js");
  const body = manifestCrxForTest({ manifest_version: 3, name: "Calc", version: "1", permissions: ["storage"] }) as unknown as BodyInit;
  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response(body, { status: 200 })) as typeof fetch;
  let created: { token: string } | undefined;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") } };
  try {
    const res = await mod.default.fetch(jsonReq("http://x/api/watchlists", "POST", { name: "Team", ids: [ID_A] }), env as never);
    created = await res.json() as { token: string };
  } finally { globalThis.fetch = real; }
  assert.ok(created?.token);
  const wl = await (await mod.default.fetch(jsonReq("http://x/api/watchlists/" + created!.token, "GET"), env as never)).json() as { audit: { action: string }[]; name: string };
  assert.deepEqual(wl.audit.map((e) => e.action), ["created"]);
  assert.equal(wl.name, "Team");
});

test("a rename keeps the webhook and logs only the rename", async () => {
  const { call } = await seed();
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: WEBHOOK });
  const res = await call("/api/watchlists/" + ADMIN, "PUT", { name: "New name" });
  assert.equal(res.status, 200);
  const body = await res.json() as { name: string; webhook: boolean };
  assert.equal(body.name, "New name");
  assert.equal(body.webhook, true, "a rename does not clear the webhook");
  const { name, webhook, audit } = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { name: string; webhook: string; audit: { action: string }[] };
  assert.equal(name, "New name");
  assert.match(webhook, /hooks\.slack\.com/);
  assert.deepEqual(audit.map((e) => e.action), ["webhook set", "renamed"]);
});

test("concurrent admin actions each keep their own audit entry", async () => {
  const { call } = await seed();
  const names = Array.from({ length: 12 }, (_, i) => "Team " + i);
  await Promise.all(names.map((name) => call("/api/watchlists/" + ADMIN, "PUT", { name })));
  const { audit } = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { audit: { action: string }[] };
  assert.equal(audit.filter((e) => e.action === "renamed").length, 12, "12 rapid actions keep 12 entries");
});

test("the per-key audit log keeps the newest 100 entries", async () => {
  const { kv } = memKv();
  for (let i = 0; i < MAX_AUDIT + 25; i++) await appendAudit(kv, ADMIN, "action " + i);
  const entries = await readAudit(kv, ADMIN);
  assert.equal(entries.length, MAX_AUDIT);
  assert.equal(entries[entries.length - 1]!.action, "action " + (MAX_AUDIT + 24));
});

test("rotate keeps every audit entry and adds the rotate entry on the new list", async () => {
  const { call } = await seed();
  for (let i = 0; i < 5; i++) await call("/api/watchlists/" + ADMIN, "PUT", { name: "Team " + i });
  const { token } = await (await call("/api/watchlists/" + ADMIN + "/rotate", "POST")).json() as { token: string };
  const { audit } = await (await call("/api/watchlists/" + token, "GET")).json() as { audit: { action: string }[] };
  assert.equal(audit.length, 6);
  assert.equal(audit.filter((e) => e.action === "renamed").length, 5);
  assert.equal(audit[audit.length - 1]!.action, "rotate");
});

test("every CSV download is written to the audit log", async () => {
  const { call } = await seed();
  await call("/api/watchlists/" + ADMIN + "/export.csv");
  await call("/api/watchlists/" + ADMIN + "/changes.csv");
  await call("/api/watchlists/" + ADMIN + "/audit.csv");
  const { audit } = await (await call("/api/watchlists/" + ADMIN, "GET")).json() as { audit: { action: string }[] };
  const actions = audit.map((e) => e.action);
  assert.ok(actions.includes("inventory exported"));
  assert.ok(actions.includes("change log exported"));
  assert.ok(actions.includes("audit exported"));
});

test("deleting a list removes its audit keys", async () => {
  const { store, call } = await seed();
  await call("/api/watchlists/" + ADMIN, "PUT", { webhook: WEBHOOK });
  assert.ok([...store.keys()].some((k) => k.startsWith("au:" + ADMIN + ":")), "the action is stored under its own key");
  assert.equal((await call("/api/watchlists/" + ADMIN, "DELETE")).status, 200);
  assert.equal([...store.keys()].some((k) => k.startsWith("au:" + ADMIN + ":")), false, "the audit keys are removed with the list");
});

test("POST /privacy serves the static privacy page", async () => {
  const mod = await import("../src/worker.js");
  const body = readFileSync(new URL("../web/privacy.html", import.meta.url), "utf8");
  let asked = "";
  const env = { WATCHLISTS: memKv().kv, ASSETS: { fetch: async (req: Request) => { asked = new URL(req.url).pathname; return new Response(body, { headers: { "content-type": "text/html" } }); } } };
  for (const path of ["/privacy", "/privacy/"]) {
    const res = await mod.default.fetch(new Request("http://x" + path), env as never);
    assert.equal(res.status, 200);
    assert.equal(asked, "/privacy.html");
    assert.match(await res.text(), /Privacy and terms/);
  }
});
