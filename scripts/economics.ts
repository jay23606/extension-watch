// Unit economics check for Extension Watch. Runs the real Cron Trigger handler (src/worker.ts,
// default.scheduled) against an in-memory fake Workers KV and a fake Google update service, over
// 300 watchlists that hold 20 extensions each, and prints the KV reads, KV writes, KV list calls
// and outbound subrequests for the first run and for one simulated day of 144 runs. This is a local simulation with a fake KV, not a
// measurement on Cloudflare. The numbers feed docs/ECONOMICS.md.
//
// Run it with the project tooling: npx tsx scripts/economics.ts

import worker from "../src/worker.js";
import { manifestCrxForTest } from "../test/helpers.js";

const LISTS = 300;
const IDS_PER_LIST = 20;

interface Counts { gets: number; puts: number; deletes: number; lists: number; subrequests: number }

function idAt(n: number): string {
  let out = "";
  let value = n;
  for (let i = 0; i < 32; i++) { out = String.fromCharCode(97 + (value % 16)) + out; value = Math.floor(value / 16); }
  return out;
}

function tokenAt(n: number, tag: string): string {
  const seed = n.toString(36) + tag;
  return (seed + "-".repeat(43)).slice(0, 43);
}

/** In-memory Workers KV with the same get, put, delete and list surface the worker uses, counting each call. */
function fakeKv(counts: Counts) {
  const store = new Map<string, { v: string; m?: unknown }>();
  const kv = {
    get: async (k: string) => { counts.gets++; return store.get(k)?.v ?? null; },
    put: async (k: string, v: string, o?: { metadata?: unknown }) => { counts.puts++; store.set(k, { v, m: o?.metadata }); },
    delete: async (k: string) => { counts.deletes++; store.delete(k); },
    list: async ({ prefix }: { prefix: string }) => {
      counts.lists++;
      return { keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name, metadata: store.get(name)?.m })), list_complete: true };
    },
  };
  return { store, kv };
}

const pool = Array.from({ length: IDS_PER_LIST }, (_, i) => idAt(i));
const manifests = new Map(pool.map((id, i) => [id, { manifest_version: 3, name: "Extension " + i, version: "1.0.0", permissions: ["storage"] }]));
const packages = new Map(pool.map((id, i) => [id, manifestCrxForTest(manifests.get(id)!) as unknown as BodyInit]));
const OLD = new Date(Date.now() - 25 * 3_600_000).toISOString();
const ACTIVE = new Date().toISOString();
const ID_IN_URL = /id%3D([a-p]{32})/;

/** A steady-state list: every snapshot is present, so a run records no change and sends no alert. */
function snapshotFor(id: string): Record<string, unknown> {
  const raw = manifests.get(id)!;
  const manifest = { id, name: raw.name, version: raw.version, manifestVersion: 3, permissions: ["storage"], optionalPermissions: [], hostPermissions: [], contentScriptMatches: [], externallyConnectable: [], hasBackground: false, csp: null, updateUrl: null, description: "" };
  return { id, manifest, assessment: { score: 0, grade: "A", findings: [], summary: "" }, error: null, checkedAt: OLD };
}

function seed(store: Map<string, { v: string; m?: unknown }>): void {
  for (let n = 0; n < LISTS; n++) {
    const token = tokenAt(n, "k");
    const view = tokenAt(n, "v");
    const snapshots: Record<string, unknown> = {};
    for (const id of pool) snapshots[id] = snapshotFor(id);
    const wl = { name: "Team " + n, ids: pool, snapshots, changes: [], createdAt: OLD, lastCheck: OLD, viewedAt: ACTIVE, viewToken: view, plan: "team" };
    store.set("wl:" + token, { v: JSON.stringify(wl), m: { lastCheck: OLD } });
    store.set("vw:" + view, { v: token });
  }
}

async function main(): Promise<void> {
  const counts: Counts = { gets: 0, puts: 0, deletes: 0, lists: 0, subrequests: 0 };
  const { store, kv } = fakeKv(counts);
  seed(store);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    counts.subrequests++;
    const id = ID_IN_URL.exec(String(input))?.[1] ?? pool[0]!;
    return new Response(packages.get(id)!, { status: 200 });
  }) as typeof fetch;
  const env = { WATCHLISTS: kv, ASSETS: { fetch: async () => new Response("") }, ORIGIN: "https://extension-watch.lipmichal.workers.dev" };
  const RUNS_PER_DAY = 144; // a Cron Trigger every 10 minutes
  const perRun: Counts[] = [];
  try {
    for (let run = 0; run < RUNS_PER_DAY; run++) {
      const before = { ...counts };
      await worker.scheduled({}, env as never);
      perRun.push({ gets: counts.gets - before.gets, puts: counts.puts - before.puts, deletes: counts.deletes - before.deletes, lists: counts.lists - before.lists, subrequests: counts.subrequests - before.subrequests });
    }
  } finally {
    globalThis.fetch = realFetch;
  }
  const busy = perRun.filter((c) => c.puts > 0).length;
  const first = perRun[0]!;
  console.log("Extension Watch unit economics, local simulation with a fake KV");
  console.log("lists seeded " + LISTS + ", ids per list " + IDS_PER_LIST + ", all due for their daily check");
  console.log("first scheduled run (the real Cron Trigger handler)");
  console.log("KV reads " + first.gets + ", KV writes " + first.puts + ", KV deletes " + first.deletes + ", KV list calls " + first.lists + ", subrequests " + first.subrequests);
  console.log("one simulated day of " + RUNS_PER_DAY + " runs, of which " + busy + " checked lists");
  console.log("KV reads " + counts.gets + ", KV writes " + counts.puts + ", KV deletes " + counts.deletes + ", KV list calls " + counts.lists + ", subrequests " + counts.subrequests);
}

await main();
