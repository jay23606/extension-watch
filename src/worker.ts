import { fetchManifest, normalizeId } from "./crx.js";
import { diff } from "./diff.js";
import { assess, RULES } from "./risk.js";
import { allow, cachedSnapshot, cacheSnapshot, dueTokens, IDLE_TTL, load, MAX_IDS, newToken, remove, save, type Kv, type Snapshot, type Watchlist } from "./store.js";
import { FetchError } from "./types.js";
import { alertable, sendAlert, webhookProblem } from "./alert.js";

interface Env { ASSETS: { fetch: (r: Request) => Promise<Response> }; WATCHLISTS: Kv }

const MAX_SCAN = 25;
const NOT_LISTED = "Not on the Chrome Web Store";
const DAY_MS = 86_400_000;
/** One cron run (every 10 minutes) downloads at most this many packages: about 17,000 a day, inside Worker limits. */
const FETCH_BUDGET = 120;

const today = () => new Date().toISOString().slice(0, 10);

async function fresh(id: string): Promise<Snapshot> {
  const checkedAt = new Date().toISOString();
  try {
    const manifest = await fetchManifest(id);
    return { id, manifest, assessment: assess(manifest), error: null, checkedAt };
  } catch (err) {
    const error = err instanceof FetchError ? err.message : "Could not read this extension right now.";
    return { id, manifest: null, assessment: null, error, checkedAt };
  }
}

/** Each extension is downloaded at most once a day, shared by every watchlist (KV cache) and within one run (memo). */
function snapshotter(kv: Kv | null, memo: Map<string, Promise<Snapshot>>, budget: { left: number }) {
  return (id: string): Promise<Snapshot> => {
    const known = memo.get(id);
    if (known) return known;
    const job = (async () => {
      const hit = kv ? await cachedSnapshot(kv, id, today()) : null;
      if (hit) return hit;
      budget.left--;
      const snap = await fresh(id);
      if (kv) await cacheSnapshot(kv, snap, today());
      return snap;
    })();
    memo.set(id, job);
    return job;
  };
}

async function scanMany(ids: string[], get: (id: string) => Promise<Snapshot>): Promise<Snapshot[]> {
  const out: Snapshot[] = [];
  for (let i = 0; i < ids.length; i += 5) out.push(...(await Promise.all(ids.slice(i, i + 5).map(get))));
  return out;
}

function parseIds(input: unknown, max: number): { ids: string[]; invalid: string[]; dropped: number } {
  const lines = Array.isArray(input) ? input.map(String) : String(input ?? "").split(/[\s,]+/);
  const ids: string[] = []; const invalid: string[] = [];
  for (const line of lines.map((l) => l.trim()).filter(Boolean).slice(0, 200)) {
    const id = normalizeId(line);
    if (id && !ids.includes(id)) ids.push(id); else if (!id) invalid.push(line.slice(0, 80));
  }
  return { ids: ids.slice(0, max), invalid, dropped: Math.max(0, ids.length - max) };
}

/** Apply one round of snapshots to a watchlist: record changes, keep the last good manifest, never fake a check. */
function apply(wl: Watchlist, snaps: Snapshot[], initial: boolean): void {
  const now = new Date().toISOString();
  let ok = 0;
  for (const snap of snaps) {
    const prev = wl.snapshots[snap.id];
    if (snap.manifest) {
      ok++;
      if (!initial) {
        for (const c of diff(prev?.manifest ?? null, snap.manifest)) wl.changes.push({ ...c, id: snap.id, at: now });
        const before = prev?.manifest?.version;
        if (before && before !== snap.manifest.version) wl.changes.push({ kind: "version_changed", value: `${before} to ${snap.manifest.version}`, severity: "low", id: snap.id, at: now });
      }
      wl.snapshots[snap.id] = snap;
    } else if (snap.error === NOT_LISTED && prev?.manifest) {
      // A store takedown is the strongest signal there is: record it once, keep the last known manifest for reference.
      // Google answered definitively, so this counts as a completed check.
      ok++;
      if (prev.error !== NOT_LISTED) wl.changes.push({ kind: "removed_from_store", value: prev.manifest.name, severity: "high", id: snap.id, at: now });
      wl.snapshots[snap.id] = { ...prev, error: NOT_LISTED, checkedAt: now };
    } else {
      wl.snapshots[snap.id] = prev ? { ...prev, error: snap.error, checkedAt: prev.checkedAt } : snap;
    }
  }
  if (ok > 0 || initial) wl.lastCheck = now;
}

async function recheck(kv: Kv, token: string, get: (id: string) => Promise<Snapshot>, origin: string): Promise<void> {
  const wl = await load(kv, token);
  if (!wl) return;
  // Not opened for 90 days: stop checking, so the KV expiry (renewed only by saves) removes it.
  if (Date.now() - Date.parse(wl.viewedAt ?? wl.createdAt) > IDLE_TTL * 1000) return;
  const seen = wl.changes.length;
  apply(wl, await scanMany(wl.ids, get), false);
  await save(kv, token, wl);
  const fresh = alertable(wl.changes.slice(seen));
  if (fresh.length) await sendAlert(wl, fresh, `${origin}/w/${token}`);
}

async function json<T>(request: Request): Promise<T> {
  // JSON only: a plain form post from another site cannot start work here.
  if (!(request.headers.get("content-type") ?? "").includes("application/json")) throw new FetchError(415, "Send JSON with content-type application/json.");
  const text = await request.text();
  if (text.length > 50_000) throw new FetchError(413, "The request is too large.");
  try { return JSON.parse(text) as T; } catch { throw new FetchError(400, "Send JSON."); }
}

const ipOf = (req: Request) => req.headers.get("cf-connecting-ip") ?? "local";

type Handler = (req: Request, env: Env, rest: string) => Promise<Response>;
const routes: Record<string, Handler> = {
  "POST /api/scan": async (req, env) => {
    if (!(await allow(env.WATCHLISTS, ipOf(req), "scan", 200, today()))) throw new FetchError(429, "Daily scan limit reached for this address. Try again tomorrow.");
    const { ids, invalid, dropped } = parseIds((await json<{ ids?: unknown }>(req)).ids, MAX_SCAN);
    if (ids.length === 0) throw new FetchError(400, "Paste at least one Chrome extension ID or Web Store link.");
    const get = snapshotter(env.WATCHLISTS, new Map(), { left: MAX_SCAN });
    return Response.json({ results: await scanMany(ids, get), invalid, dropped });
  },
  "POST /api/watchlists": async (req, env) => {
    if (!(await allow(env.WATCHLISTS, ipOf(req), "watch", 20, today()))) throw new FetchError(429, "Daily watchlist limit reached for this address.");
    const body = await json<{ name?: unknown; ids?: unknown }>(req);
    const { ids, dropped } = parseIds(body.ids, MAX_IDS);
    if (ids.length === 0) throw new FetchError(400, "Add at least one extension.");
    const token = newToken(); const now = new Date().toISOString();
    const wl: Watchlist = { name: String(body.name ?? "My team").trim().slice(0, 60) || "My team", ids, snapshots: {}, changes: [], createdAt: now, lastCheck: now };
    apply(wl, await scanMany(ids, snapshotter(env.WATCHLISTS, new Map(), { left: MAX_IDS })), true); // baseline: no "new" noise
    await save(env.WATCHLISTS, token, wl);
    return Response.json({ token, url: `/w/${token}`, dropped });
  },
  "GET /api/watchlists": async (_req, env, rest) => {
    const wl = await load(env.WATCHLISTS, rest);
    if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
    const today0 = today();
    if ((wl.viewedAt ?? "").slice(0, 10) !== today0) { wl.viewedAt = new Date().toISOString(); await save(env.WATCHLISTS, rest, wl); }
    const { webhook, ...rest2 } = wl;
    return Response.json({ ...rest2, webhook: webhook ? webhook.replace(/^(https:\/\/[^/]+\/).{4,}$/, "$1...") : null, webhookSet: Boolean(webhook) });
  },
  "DELETE /api/watchlists": async (_req, env, rest) =>
    (await remove(env.WATCHLISTS, rest)) ? Response.json({ deleted: true }) : Response.json({ error: "This watchlist does not exist." }, { status: 404 }),
  "PUT /api/watchlists": async (req, env, rest) => {
    const wl = await load(env.WATCHLISTS, rest);
    if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
    const raw = String((await json<{ webhook?: unknown }>(req)).webhook ?? "").trim();
    const problem = raw ? webhookProblem(raw) : null;
    if (problem) throw new FetchError(400, problem);
    wl.webhook = raw || null;
    await save(env.WATCHLISTS, rest, wl);
    return Response.json({ webhook: Boolean(wl.webhook) });
  },
  "POST /api/test-alert": async (req, env) => {
    const token = String((await json<{ token?: unknown }>(req)).token ?? "");
    if (!(await allow(env.WATCHLISTS, ipOf(req), "test-alert", 10, today()))) throw new FetchError(429, "Test alert limit reached for today.");
    const wl = await load(env.WATCHLISTS, token);
    if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
    if (!wl.webhook) throw new FetchError(400, "Save a webhook URL first.");
    const id = wl.ids[0] ?? "";
    const sample = [{ kind: "permission_added", value: "cookies (test alert, not a real change)", severity: "high" as const, id, at: new Date().toISOString() }];
    const res = await sendAlert(wl, sample, `${new URL(req.url).origin}/w/${token}`);
    return Response.json({ sent: res.ok, status: res.status });
  },
  "GET /api/rules": async () => Response.json({ rules: RULES }),
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return secure(await route(request, env));
  },
  async scheduled(_event: unknown, env: Env & { ORIGIN?: string }): Promise<void> {
    const budget = { left: FETCH_BUDGET };
    const get = snapshotter(env.WATCHLISTS, new Map(), budget);
    const origin = env.ORIGIN ?? "https://extension-watch.lipmichal.workers.dev";
    for (const token of await dueTokens(env.WATCHLISTS, DAY_MS - 3_600_000)) {
      if (budget.left <= 0) break;
      await recheck(env.WATCHLISTS, token, get, origin);
    }
  },
};

const HEADERS: Record<string, string> = {
  "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

function secure(res: Response): Response {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(HEADERS)) out.headers.set(k, v);
  return out;
}

async function route(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/w/")) return env.ASSETS.fetch(new Request(new URL("/", url), request));
    const [, , a = "", rest = ""] = url.pathname.split("/");
    const handler = routes[`${request.method} /api/${a}`];
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    if (!handler) return Response.json({ error: "Not found." }, { status: 404 });
    try { return await handler(request, env, rest); } catch (err) {
      const status = err instanceof FetchError ? err.status : 500;
      return Response.json({ error: err instanceof FetchError ? err.message : "Something went wrong." }, { status: status >= 400 && status < 600 ? status : 500 });
    }
}

export { apply as applySnapshots };
