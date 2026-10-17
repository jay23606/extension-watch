import { fetchManifest, normalizeId } from "./crx.js";
import { diff } from "./diff.js";
import { assess, RULES } from "./risk.js";
import { allTokens, load, MAX_IDS, newToken, save, type Kv, type Snapshot, type Watchlist } from "./store.js";
import { FetchError } from "./types.js";

interface Env { ASSETS: { fetch: (r: Request) => Promise<Response> }; WATCHLISTS: Kv }

const MAX_SCAN = 25;

async function snapshot(id: string): Promise<Snapshot> {
  const checkedAt = new Date().toISOString();
  try {
    const manifest = await fetchManifest(id);
    return { id, manifest, assessment: assess(manifest), error: null, checkedAt };
  } catch (err) {
    const error = err instanceof FetchError ? err.message : "Could not read this extension right now.";
    return { id, manifest: null, assessment: null, error, checkedAt };
  }
}

/** Parse pasted IDs or Web Store URLs; report the lines that are not extensions. */
function parseIds(input: unknown, max: number): { ids: string[]; invalid: string[] } {
  const lines = Array.isArray(input) ? input.map(String) : String(input ?? "").split(/[\s,]+/);
  const ids: string[] = []; const invalid: string[] = [];
  for (const line of lines.map((l) => l.trim()).filter(Boolean).slice(0, 200)) {
    const id = normalizeId(line);
    if (id && !ids.includes(id)) ids.push(id); else if (!id) invalid.push(line.slice(0, 80));
  }
  return { ids: ids.slice(0, max), invalid };
}

async function scanMany(ids: string[]): Promise<Snapshot[]> {
  const out: Snapshot[] = [];
  for (let i = 0; i < ids.length; i += 5) out.push(...(await Promise.all(ids.slice(i, i + 5).map(snapshot))));
  return out;
}

/** Re-check one watchlist and record every change since the last snapshot. */
async function recheck(kv: Kv, token: string): Promise<number> {
  const wl = await load(kv, token);
  if (!wl) return 0;
  const now = new Date().toISOString();
  const fresh = await scanMany(wl.ids);
  let changes = 0;
  for (const snap of fresh) {
    const prev = wl.snapshots[snap.id];
    if (snap.error && prev?.manifest) continue; // a temporary failure is not a removal; keep the last good snapshot
    for (const c of diff(prev?.manifest ?? null, snap.manifest)) { wl.changes.push({ ...c, id: snap.id, at: now }); changes++; }
    wl.snapshots[snap.id] = snap;
  }
  wl.lastCheck = now;
  await save(kv, token, wl);
  return changes;
}

async function json<T>(request: Request): Promise<T> {
  const text = await request.text();
  if (text.length > 50_000) throw new FetchError(413, "The request is too large.");
  try { return JSON.parse(text) as T; } catch { throw new FetchError(400, "Send JSON."); }
}

type Handler = (req: Request, env: Env, rest: string) => Promise<Response>;
const routes: Record<string, Handler> = {
  "POST /api/scan": async (req) => {
    const { ids, invalid } = parseIds((await json<{ ids?: unknown }>(req)).ids, MAX_SCAN);
    if (ids.length === 0) throw new FetchError(400, "Paste at least one Chrome extension ID or Web Store link.");
    return Response.json({ results: await scanMany(ids), invalid });
  },
  "POST /api/watchlists": async (req, env) => {
    const body = await json<{ name?: unknown; ids?: unknown }>(req);
    const { ids } = parseIds(body.ids, MAX_IDS);
    if (ids.length === 0) throw new FetchError(400, "Add at least one extension.");
    const token = newToken(); const now = new Date().toISOString();
    const wl: Watchlist = { name: String(body.name ?? "My team").slice(0, 60), ids, snapshots: {}, changes: [], createdAt: now, lastCheck: now };
    await save(env.WATCHLISTS, token, wl);
    await recheck(env.WATCHLISTS, token);
    return Response.json({ token, url: `/w/${token}` });
  },
  "GET /api/watchlists": async (_req, env, rest) => {
    const wl = await load(env.WATCHLISTS, rest);
    return wl ? Response.json(wl) : Response.json({ error: "This watchlist does not exist." }, { status: 404 });
  },
  "GET /api/rules": async () => Response.json({ rules: RULES }),
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/w/")) return env.ASSETS.fetch(new Request(new URL("/", url), request));
    const [, , a = "", rest = ""] = url.pathname.split("/");
    const handler = routes[`${request.method} /api/${a}`];
    if (!url.pathname.startsWith("/api/") || !handler) return url.pathname.startsWith("/api/") ? Response.json({ error: "Not found." }, { status: 404 }) : env.ASSETS.fetch(request);
    try { return await handler(request, env, rest); } catch (err) {
      const status = err instanceof FetchError ? err.status : 500;
      return Response.json({ error: err instanceof FetchError ? err.message : "Something went wrong." }, { status: status >= 400 && status < 600 ? status : 500 });
    }
  },
  /** Daily: re-check every watchlist and record changes. */
  async scheduled(_event: unknown, env: Env): Promise<void> {
    for (const token of (await allTokens(env.WATCHLISTS)).slice(0, 500)) await recheck(env.WATCHLISTS, token);
  },
};
