import { test } from "node:test";
import assert from "node:assert/strict";
import { assess } from "../src/risk";
import { csvCell, inventoryCsv, modeFrom, policyFor } from "../src/export";
import type { Snapshot, Watchlist } from "../src/store";
import type { Manifest } from "../src/types";

const ADMIN = "K".repeat(43);
const VIEWER = "V".repeat(43);
const TEST_SALT = "test-address-salt-0123456789";
const ID_A = "a".repeat(32);
const ID_D = "d".repeat(32);
const ID_F = "f".repeat(32);
const ID_X = "x".repeat(32);

function manifest(id: string, overrides: Partial<Manifest> = {}): Manifest {
  return {
    id,
    name: "Test",
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

function snapshot(m: Manifest): Snapshot {
  return { id: m.id, manifest: m, assessment: assess(m), error: null, checkedAt: "2026-10-18T00:00:00Z" };
}

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

type PolicyEntry = { installation_mode: string; blocked_permissions?: string[]; runtime_blocked_hosts?: string[]; runtime_allowed_hosts?: string[] };
type Policy = { ExtensionSettings: Record<string, PolicyEntry> };

// Scheme, then ://, then an optional wildcard label and a host. No path and no port.
const HOST_PATTERN = /^(?:https?|\*):\/\/(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

const seedList = async () => {
  const { store, kv } = memKv();
  const a = snapshot(manifest(ID_A, { name: 'Calc, "Pro"', version: "1.0.0" }));
  const d = snapshot(manifest(ID_D, { name: "Dash", version: "2.0.0", permissions: ["debugger", "cookies", "management"] }));
  const f = snapshot(manifest(ID_F, { name: "Fab", version: "3.0.0", permissions: ["debugger", "cookies", "management", "proxy", "privacy"] }));
  const x: Snapshot = { id: ID_X, manifest: null, assessment: null, error: "Not on the Chrome Web Store", checkedAt: "2026-10-18T00:00:00Z" };
  const wl: Watchlist = {
    name: "Team",
    ids: [ID_A, ID_D, ID_F, ID_X],
    snapshots: { [ID_A]: a, [ID_D]: d, [ID_F]: f, [ID_X]: x },
    changes: [{ kind: "permission_added", value: "debugger", severity: "high", id: ID_D, at: "2026-10-18T01:00:00Z" }],
    createdAt: "2026-10-18T00:00:00Z",
    lastCheck: "2026-10-18T00:00:00Z",
    viewToken: VIEWER,
  };
  await kv.put(`wl:${ADMIN}`, JSON.stringify(wl), { metadata: { lastCheck: wl.lastCheck } });
  await kv.put(`vw:${VIEWER}`, ADMIN);
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, ADDRESS_SALT: TEST_SALT };
  const mod = await import("../src/worker.js");
  const get = (path: string) => mod.default.fetch(new Request("http://x" + path), env as never);
  return { store, kv, wl, get };
};

test("CSV cells quote commas, quotes and newlines", () => {
  assert.equal(csvCell("plain"), "plain");
  assert.equal(csvCell("a,b"), '"a,b"');
  assert.equal(csvCell('a"b'), '"a""b"');
  assert.equal(csvCell("a\nb"), '"a\nb"');
  assert.equal(csvCell(null), "");
});

test("inventory export is CSV with the agreed columns and correct escaping", async () => {
  const { get } = await seedList();
  const res = await get(`/api/watchlists/${ADMIN}/export.csv`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /^text\/csv/);
  assert.match(res.headers.get("content-disposition") ?? "", /watchlist-inventory\.csv/);
  const lines = (await res.text()).trimEnd().split("\r\n");
  assert.equal(lines[0], "id,name,version,grade,score,top findings,last checked");
  assert.equal(lines[1], `${ID_A},"Calc, ""Pro""",1.0.0,A,0,,2026-10-18T00:00:00Z`);
  assert.equal(lines[2], `${ID_D},Dash,2.0.0,D,60,Debugger access; Cookies; Extension management,2026-10-18T00:00:00Z`);
  assert.equal(lines[3], `${ID_F},Fab,3.0.0,F,87,Debugger access; Cookies; Extension management,2026-10-18T00:00:00Z`);
  assert.ok(lines[4]!.startsWith(`${ID_X},`));
  assert.equal(lines.length, 5);
});

test("change log export is CSV and names the extension", async () => {
  const { get } = await seedList();
  const res = await get(`/api/watchlists/${ADMIN}/changes.csv`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-disposition") ?? "", /watchlist-changes\.csv/);
  const lines = (await res.text()).trimEnd().split("\r\n");
  assert.equal(lines[0], "at,extension id,extension name,kind,value,severity");
  assert.equal(lines[1], `2026-10-18T01:00:00Z,${ID_D},Dash,permission_added,debugger,high`);
});

test("policy JSON blocks grades at or below the threshold and includes the sensitive hosts", async () => {
  const { get } = await seedList();
  const res = await get(`/api/watchlists/${ADMIN}/policy.json?threshold=D&mode=default-deny`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /application\/json/);
  const policy = await res.json() as Policy;
  const all = policy.ExtensionSettings["*"]!;
  assert.equal(all.installation_mode, "blocked");
  assert.ok(all.blocked_permissions!.includes("debugger"));
  assert.ok(all.runtime_blocked_hosts!.includes("*://*.okta.com"));
  assert.ok(all.runtime_blocked_hosts!.includes("*://*.salesforce.com"));
  assert.ok(all.runtime_blocked_hosts!.includes("*://*.aws.amazon.com"));
  assert.equal(policy.ExtensionSettings[ID_A]!.installation_mode, "allowed");
  assert.equal(policy.ExtensionSettings[ID_D]!.installation_mode, "blocked");
  assert.equal(policy.ExtensionSettings[ID_F]!.installation_mode, "blocked");
  assert.equal(policy.ExtensionSettings[ID_X]!.installation_mode, "blocked");
});

test("every runtime_blocked_hosts entry is a Chrome host pattern with no path or port", async () => {
  const { get } = await seedList();
  const policy = await (await get(`/api/watchlists/${ADMIN}/policy.json?threshold=D&mode=default-deny`)).json() as Policy;
  const hosts = policy.ExtensionSettings["*"]!.runtime_blocked_hosts!;
  assert.ok(hosts.length > 0);
  assert.equal(new Set(hosts).size, hosts.length);
  for (const host of hosts) {
    assert.match(host, HOST_PATTERN, host);
    assert.ok(!host.includes("/", host.indexOf("://") + 3), host);
  }
  assert.ok(!hosts.some((host) => host.includes("console.aws.amazon.com")));
  for (const [id, entry] of Object.entries(policy.ExtensionSettings)) {
    for (const host of entry.runtime_blocked_hosts ?? []) assert.match(host, HOST_PATTERN, `${id} ${host}`);
  }
});

test("an allowed extension repeats the permission and host blocks from the star entry", async () => {
  const { get } = await seedList();
  const policy = await (await get(`/api/watchlists/${ADMIN}/policy.json?mode=default-deny`)).json() as Policy;
  const all = policy.ExtensionSettings["*"]!;
  const allowed = Object.entries(policy.ExtensionSettings).filter(([id, entry]) => id !== "*" && entry.installation_mode === "allowed");
  assert.deepEqual(allowed.map(([id]) => id).sort(), [ID_A, ID_D].sort());
  for (const [id, entry] of allowed) {
    assert.deepEqual(entry.blocked_permissions, all.blocked_permissions, id);
    assert.deepEqual(entry.runtime_blocked_hosts, all.runtime_blocked_hosts, id);
  }
  for (const [id, entry] of Object.entries(policy.ExtensionSettings)) {
    if (id !== "*" && entry.installation_mode === "blocked") {
      assert.deepEqual(Object.keys(entry), ["installation_mode"], id);
    }
  }
});

test("policy threshold defaults to F and rejects a value that is not a grade", async () => {
  const { get } = await seedList();
  const byDefault = await (await get(`/api/watchlists/${ADMIN}/policy.json`)).json() as { ExtensionSettings: Record<string, { installation_mode: string }> };
  assert.equal(byDefault.ExtensionSettings[ID_D]!.installation_mode, "allowed");
  assert.equal(byDefault.ExtensionSettings[ID_F]!.installation_mode, "blocked");
  const bad = await get(`/api/watchlists/${ADMIN}/policy.json?threshold=Z`);
  assert.equal(bad.status, 400);
});

test("a read-only link may download CSV but never the policy", async () => {
  const { get } = await seedList();
  assert.equal((await get(`/api/watchlists/${VIEWER}/export.csv`)).status, 200);
  assert.equal((await get(`/api/watchlists/${VIEWER}/changes.csv`)).status, 200);
  assert.equal((await get(`/api/watchlists/${VIEWER}/policy.json?threshold=D`)).status, 403);
});

test("an unknown watchlist token gets 404 for every export", async () => {
  const { get } = await seedList();
  for (const file of ["export.csv", "changes.csv", "policy.json"]) {
    assert.equal((await get(`/api/watchlists/${"Q".repeat(43)}/${file}`)).status, 404, file);
  }
});

// R6: CSV injection. A cell that starts with a formula character is prefixed with a single quote.
test("CSV cells that start with a formula character get a single quote prefix", () => {
  assert.equal(csvCell("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"");
  assert.equal(csvCell("=1+1"), "'=1+1");
  assert.equal(csvCell("+1+1"), "'+1+1");
  assert.equal(csvCell("-1+1"), "'-1+1");
  assert.equal(csvCell("@SUM(A1)"), "'@SUM(A1)");
  assert.equal(csvCell("\tcmd"), "'\tcmd");
  assert.equal(csvCell("\rcmd"), "\"'\rcmd\"");
  assert.equal(csvCell("plain"), "plain");
});

test("a hostile extension name is neutralised in the inventory export", () => {
  const hostile = manifest(ID_A, { name: '=HYPERLINK("http://x")' });
  const wl: Watchlist = {
    name: "Team",
    ids: [ID_A],
    snapshots: { [ID_A]: snapshot(hostile) },
    changes: [],
    createdAt: "2026-10-18T00:00:00Z",
    lastCheck: "2026-10-18T00:00:00Z",
  };
  const out = inventoryCsv(wl);
  assert.ok(out.includes("\"'=HYPERLINK"), out);
  assert.ok(!out.includes(",=HYPERLINK"), out);
});

test("exports and token responses are not cached", async () => {
  const { get } = await seedList();
  for (const path of [`/api/watchlists/${ADMIN}/export.csv`, `/api/watchlists/${ADMIN}/changes.csv`, `/api/watchlists/${ADMIN}/policy.json`, `/api/watchlists/${ADMIN}`, `/api/watchlists/${VIEWER}`]) {
    assert.equal((await get(path)).headers.get("cache-control"), "no-store", path);
  }
});

// R6: two policy modes. Threshold is the default; default deny keeps the old catch-all block.
test("modeFrom defaults to threshold and rejects an unknown mode", () => {
  assert.equal(modeFrom(null), "threshold");
  assert.equal(modeFrom(""), "threshold");
  assert.equal(modeFrom("threshold"), "threshold");
  assert.equal(modeFrom("DEFAULT-DENY"), "default-deny");
  assert.equal(modeFrom("nope"), null);
});

test("threshold mode keeps the catch-all installable and still blocks the debugger and sensitive hosts", async () => {
  const { get } = await seedList();
  const res = await get(`/api/watchlists/${ADMIN}/policy.json`);
  assert.equal(res.status, 200);
  const policy = await res.json() as Policy;
  const all = policy.ExtensionSettings["*"]!;
  assert.equal(all.installation_mode, undefined);
  assert.deepEqual(all.blocked_permissions, ["debugger"]);
  assert.ok(all.runtime_blocked_hosts!.includes("*://*.okta.com"));
  assert.ok(all.runtime_blocked_hosts!.includes("*://*.aws.amazon.com"));
  // Default threshold is F, so only the F extension is blocked. D and A are allowed, the unreadable X is allowed.
  assert.equal(policy.ExtensionSettings[ID_A]!.installation_mode, "allowed");
  assert.equal(policy.ExtensionSettings[ID_D]!.installation_mode, "allowed");
  assert.equal(policy.ExtensionSettings[ID_F]!.installation_mode, "blocked");
  assert.equal(policy.ExtensionSettings[ID_X]!.installation_mode, "allowed");
});

test("threshold mode allows only at or below the threshold and rejects an unknown mode", async () => {
  const { get } = await seedList();
  const policy = await (await get(`/api/watchlists/${ADMIN}/policy.json?threshold=D&mode=threshold`)).json() as Policy;
  assert.equal(policy.ExtensionSettings[ID_A]!.installation_mode, "allowed");
  assert.equal(policy.ExtensionSettings[ID_D]!.installation_mode, "blocked");
  assert.equal(policy.ExtensionSettings[ID_F]!.installation_mode, "blocked");
  assert.equal((await get(`/api/watchlists/${ADMIN}/policy.json?mode=nope`)).status, 400);
});

test("an allowed password manager keeps its vendor domain and gets its sign-in hosts", () => {
  const bitwarden = snapshot(manifest("nngceckbapebfimnlniiiahkandclblb", { name: "Bitwarden Password Manager" }));
  const onepassword = snapshot(manifest("aeblfdkhhhdcdjpifhhbdiojplfjncoa", { name: "1Password" }));
  const wl: Watchlist = {
    name: "Team",
    ids: [bitwarden.id, onepassword.id],
    snapshots: { [bitwarden.id]: bitwarden, [onepassword.id]: onepassword },
    changes: [],
    createdAt: "2026-10-18T00:00:00Z",
    lastCheck: "2026-10-18T00:00:00Z",
  };
  const policy = policyFor(wl, "D", "default-deny");
  const bw = policy.ExtensionSettings[bitwarden.id] as PolicyEntry;
  assert.equal(bw.installation_mode, "allowed");
  assert.ok(!bw.runtime_blocked_hosts!.includes("*://*.bitwarden.com"));
  assert.deepEqual(bw.runtime_blocked_hosts!.filter((h) => h.includes("bitwarden")), []);
  assert.deepEqual(bw.runtime_allowed_hosts, ["*://*.accounts.google.com", "*://*.login.microsoftonline.com", "*://*.okta.com", "*://*.vault.bitwarden.com"]);
  const op = policy.ExtensionSettings[onepassword.id] as PolicyEntry;
  assert.equal(op.installation_mode, "allowed");
  assert.deepEqual(op.runtime_blocked_hosts!.filter((h) => h.includes("1password")), []);
  assert.deepEqual(op.runtime_allowed_hosts, ["*://*.accounts.google.com", "*://*.login.microsoftonline.com", "*://*.okta.com", "*://*.my.1password.com", "*://*.start.1password.com"]);
  // The shared sign-in hosts are reachable, so they are no longer blocked for this tool.
  for (const host of ["*://*.accounts.google.com", "*://*.login.microsoftonline.com", "*://*.okta.com"]) {
    assert.ok(!bw.runtime_blocked_hosts!.includes(host), host);
  }
  // The rest of the sensitive hosts still stand.
  assert.ok(bw.runtime_blocked_hosts!.includes("*://*.salesforce.com"));
});

test("an allowed sign-on tool reaches the shared sign-in hosts in both modes", () => {
  const okta = snapshot(manifest("glnpjglilkicbckjpbgcfkogebgllemb", { name: "Okta" }));
  const wl: Watchlist = {
    name: "Team",
    ids: [okta.id],
    snapshots: { [okta.id]: okta },
    changes: [],
    createdAt: "2026-10-18T00:00:00Z",
    lastCheck: "2026-10-18T00:00:00Z",
  };
  for (const mode of ["threshold", "default-deny"] as const) {
    const policy = policyFor(wl, "F", mode);
    const entry = policy.ExtensionSettings[okta.id] as PolicyEntry;
    assert.equal(entry.installation_mode, "allowed", mode);
    assert.deepEqual(entry.runtime_allowed_hosts, ["*://*.accounts.google.com", "*://*.login.microsoftonline.com", "*://*.okta.com"], mode);
    for (const host of ["*://*.accounts.google.com", "*://*.login.microsoftonline.com", "*://*.okta.com"]) {
      assert.ok(!entry.runtime_blocked_hosts!.includes(host), mode + " " + host);
    }
  }
});

test("a tool exception matches the extension id, never the publisher-controlled name", () => {
  const impostor = snapshot(manifest("b".repeat(32), { name: "Bitwarden Password Manager" }));
  const wl: Watchlist = {
    name: "Team",
    ids: [impostor.id],
    snapshots: { [impostor.id]: impostor },
    changes: [],
    createdAt: "2026-10-18T00:00:00Z",
    lastCheck: "2026-10-18T00:00:00Z",
  };
  const policy = policyFor(wl, "D", "default-deny");
  const entry = policy.ExtensionSettings[impostor.id] as PolicyEntry;
  assert.equal(entry.installation_mode, "allowed");
  assert.equal(entry.runtime_allowed_hosts, undefined);
  assert.ok(entry.runtime_blocked_hosts!.includes("*://*.bitwarden.com"));
});
