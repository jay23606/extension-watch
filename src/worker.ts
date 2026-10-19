import { fetchManifest, normalizeId } from "./crx.js";
import { diff } from "./diff.js";
import { assess, RULES } from "./risk.js";
import { AddressSaltMissing, allow, appendAudit, cachedSnapshot, cacheSnapshot, claimTrial, setAddressSalt, dueTokens, effectivePlan, ensureViewToken, FREE_MAX_IDS, idsToCheck, IDLE_TTL, load, MAX_IDS, newToken, planUsage, readAudit, remove, resolveView, rotate, save, trialEndFrom, type Kv, type Plan, type Snapshot, type Watchlist } from "./store.js";
import { auditCsv, changesCsv, inventoryCsv, modeFrom, policyFor, thresholdFrom } from "./export.js";
import { FetchError } from "./types.js";
import { alertable, maskWebhook, sendAlert, webhookProblem } from "./alert.js";

interface RateLimit { limit(o: { key: string }): Promise<{ success: boolean }> }
interface Env { ASSETS: { fetch: (r: Request) => Promise<Response> }; WATCHLISTS: Kv; WRITE_LIMIT?: RateLimit; OPERATOR_CODE?: string; ADDRESS_SALT?: string }

const MAX_SCAN = 25;
const NOT_LISTED = "Not on the Chrome Web Store";
const DAY_MS = 86_400_000;
/** One cron run (every 10 minutes) downloads at most this many packages: about 5,700 a day, a few seconds of CPU per run. */
const FETCH_BUDGET = 40;
/** One run touches at most this many lists. */
const MAX_LISTS_PER_RUN = 150;
/** KV operations one run may spend (Cloudflare allows 1,000 per invocation); the rest wait for the next run. */
const KV_BUDGET = 800;
const POSTPONED = "Check postponed to the next run.";
/** A Free list keeps the risk report but not the Team exports. Billing is not live yet, so upgrades are by hand. */
const FREE_PLAN_MESSAGE = "This list is on the Free plan. The CSV exports, the policy export and the audit log are part of Team. Billing is not live yet, so ask the operator to upgrade this list. Contact the operator at github.com/theluckystrike or open an issue at https://github.com/theluckystrike/extension-watch/issues.";
/** Shown when one address tries a second new list inside the trial window. */
const TRIAL_USED_MESSAGE = "This address already started 3 trials in the last 30 days, so this new list starts on the Free plan.";

/**
 * Compare the operator code through fixed length SHA-256 digests of both strings, so the
 * comparison takes the same time for every input and never leaks the length of the secret.
 */
async function sameSecret(given: string, expected: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(given)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  const av = new Uint8Array(a);
  const bv = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < av.length; i++) diff |= av[i]! ^ bv[i]!;
  return diff === 0;
}

function freePlanResponse(): Response {
  return Response.json({ error: FREE_PLAN_MESSAGE }, { status: 402 });
}

/** The exports that belong to the Team plan. */
const TEAM_EXPORTS = new Set(["export.csv", "changes.csv", "audit.csv", "policy.json"]);

const today = () => new Date().toISOString().slice(0, 10);

async function fresh(id: string): Promise<Snapshot> {
  const checkedAt = new Date().toISOString();
  try {
    const manifest = await fetchManifest(id);
    return { id, manifest, assessment: assess(manifest), error: null, checkedAt };
  } catch (err) {
    const error = err instanceof FetchError ? err.message : "Could not read this extension right now.";
    const transient = !(err instanceof FetchError) || err.status >= 500 || err.status === 429;
    return { id, manifest: null, assessment: null, error, checkedAt, transient };
  }
}

/** Each extension is downloaded at most once a day, shared by every watchlist (KV cache) and within one run (memo). */
type Budget = { left: number; kv: number };

function snapshotter(kv: Kv | null, memo: Map<string, Promise<Snapshot>>, budget: Budget) {
  return (id: string): Promise<Snapshot> => {
    const known = memo.get(id);
    if (known) return known;
    const job = (async () => {
      if (budget.kv <= 2) return { id, manifest: null, assessment: null, error: POSTPONED, checkedAt: new Date().toISOString(), transient: true };
      budget.kv -= 1;
      const hit = kv ? await cachedSnapshot(kv, id, today()) : null;
      // Grades are recomputed from the cached manifest, so a rule change applies right away.
      if (hit) return hit.manifest ? { ...hit, assessment: assess(hit.manifest) } : hit;
      if (budget.left <= 0) return { id, manifest: null, assessment: null, error: POSTPONED, checkedAt: new Date().toISOString(), transient: true };
      budget.left--;
      budget.kv -= 1;
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
      if (!snap.transient) ok++; // a definitive answer (404, unreadable package) is a completed check
      // A package that could be read before and cannot be read now is itself a signal: log it and alert.
      if (!initial && !snap.transient && prev?.manifest && prev.error !== snap.error) {
        wl.changes.push({ kind: "unreadable", value: snap.error ?? "unreadable", severity: "high", id: snap.id, at: now });
      }
      wl.snapshots[snap.id] = prev ? { ...prev, error: snap.error, checkedAt: snap.transient ? prev.checkedAt : now } : snap;
    }
  }
  // A list stays due until every extension in it got an answer this round (P1: no extension is skipped day after day).
  const postponed = snaps.some((s) => s.error === POSTPONED);
  if ((ok > 0 || initial) && !postponed) wl.lastCheck = now;
}

async function recheck(kv: Kv, token: string, get: (id: string) => Promise<Snapshot>, origin: string): Promise<void> {
  const wl = await load(kv, token);
  if (!wl) return;
  // Not opened for 90 days (365 with a webhook, since that team reads it in chat): stop checking, so the KV expiry
  // (renewed only by saves) removes it.
  const idleLimit = (wl.webhook ? 365 * 86400 : IDLE_TTL) * 1000;
  if (Date.now() - Date.parse(wl.viewedAt ?? wl.createdAt) > idleLimit) return;
  const seen = wl.changes.length;
  apply(wl, await scanMany(idsToCheck(wl), get), false);
  // Take the new changes before save() trims the log to its last 200 entries.
  const fresh = alertable(wl.changes.slice(seen));
  if (fresh.length) {
    const viewToken = await ensureViewToken(kv, token, wl);
    const sent = await sendAlert(wl, fresh, `${origin}/w/${viewToken}`); // never the admin link: chat channels are shared
    if (sent.ok) wl.viewedAt = new Date().toISOString(); // a team that reads alerts in Slack is an active team
  }
  // The admin may have deleted the list or changed its webhook while this check ran (P7): honour that.
  const current = await load(kv, token);
  if (!current) return;
  wl.webhook = current.webhook;
  wl.name = current.name;
  await save(kv, token, wl);
}

async function json<T>(request: Request): Promise<T> {
  // JSON only: a plain form post from another site cannot start work here.
  const essence = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (essence !== "application/json") throw new FetchError(415, "Send JSON with content-type application/json.");
  const text = await request.text();
  if (text.length > 50_000) throw new FetchError(413, "The request is too large.");
  try { return JSON.parse(text) as T; } catch { throw new FetchError(400, "Send JSON."); }
}

const ipOf = (req: Request) => req.headers.get("cf-connecting-ip") ?? "local";

function csvResponse(body: string, filename: string): Response {
  return new Response(body, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="${filename}"` } });
}

/** Exports accept the admin link and the read-only link. The policy is admin only. */
async function exportResponse(req: Request, env: Env, rest: string): Promise<Response> {
  const [token = "", file = ""] = rest.split("/");
  const direct = await load(env.WATCHLISTS, token);
  const adminToken = direct ? token : (await resolveView(env.WATCHLISTS, token)) ?? "";
  const wl = direct ?? (adminToken ? await load(env.WATCHLISTS, adminToken) : null);
  if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
  // Every export is a Team feature. A list past its trial on Free gets a plain 402, not a redirect to a pay page.
  if (effectivePlan(wl) === "free" && TEAM_EXPORTS.has(file)) return freePlanResponse();
  if (file === "export.csv") {
    await appendAudit(env.WATCHLISTS, adminToken, "inventory exported");
    return csvResponse(inventoryCsv(wl), "watchlist-inventory.csv");
  }
  if (file === "changes.csv") {
    await appendAudit(env.WATCHLISTS, adminToken, "change log exported");
    return csvResponse(changesCsv(wl), "watchlist-changes.csv");
  }
  if (file === "audit.csv") {
    if (!direct) return Response.json({ error: "Only the admin link can export the audit log." }, { status: 403 });
    await appendAudit(env.WATCHLISTS, adminToken, "audit exported");
    return csvResponse(auditCsv(await readAudit(env.WATCHLISTS, adminToken)), "watchlist-audit.csv");
  }
  if (file === "policy.json") {
    if (!direct) return Response.json({ error: "Only the admin link can export a policy." }, { status: 403 });
    const query = new URL(req.url).searchParams;
    const threshold = thresholdFrom(query.get("threshold") ?? query.get("grade"));
    if (!threshold) throw new FetchError(400, "Use a grade threshold from A to F.");
    const mode = modeFrom(query.get("mode"));
    if (!mode) throw new FetchError(400, "Use a policy mode of threshold or default-deny.");
    await appendAudit(env.WATCHLISTS, adminToken, "policy exported");
    return new Response(JSON.stringify(policyFor(wl, threshold, mode), null, 2), {
      headers: { "content-type": "application/json", "content-disposition": 'attachment; filename="chrome-extension-policy.json"' },
    });
  }
  return Response.json({ error: "Not found." }, { status: 404 });
}

type Handler = (req: Request, env: Env, rest: string) => Promise<Response>;
const routes: Record<string, Handler> = {
  "POST /api/scan": async (req, env) => {
    if (!(await allow(env.WATCHLISTS, ipOf(req), "scan", 200, today()))) throw new FetchError(429, "Daily scan limit reached for this address. Try again tomorrow.");
    const { ids, invalid, dropped } = parseIds((await json<{ ids?: unknown }>(req)).ids, MAX_SCAN);
    if (ids.length === 0) throw new FetchError(400, "Paste at least one Chrome extension ID or Web Store link.");
    const get = snapshotter(env.WATCHLISTS, new Map(), { left: MAX_SCAN, kv: 4 * MAX_SCAN });
    return Response.json({ results: await scanMany(ids, get), invalid, dropped });
  },
  "POST /api/watchlists": async (req, env, rest) => {
    // Admin only: issue fresh links and retire the old pair. The old tokens 404 within about a minute, once Workers KV drops its cached reads.
    if (rest.endsWith("/rotate")) {
      const token = rest.slice(0, -"/rotate".length);
      const result = await rotate(env.WATCHLISTS, token);
      if (!result) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
      return Response.json({ token: result.token, viewToken: result.viewToken, url: `/w/${result.token}`, viewUrl: `/w/${result.viewToken}` });
    }
    if (rest) return Response.json({ error: "Not found." }, { status: 404 });
    if (!(await allow(env.WATCHLISTS, ipOf(req), "watch", 20, today()))) throw new FetchError(429, "Daily watchlist limit reached for this address.");
    const body = await json<{ name?: unknown; ids?: unknown; plan?: unknown }>(req);
    // A new list starts on the Team trial unless the caller asks for Free directly, or this address
    // already used its 3 trials inside the window. Team is granted later by the operator route.
    const wantsFree = String(body.plan ?? "").trim().toLowerCase() === "free";
    const allIds = parseIds(body.ids, MAX_IDS).ids;
    if (allIds.length === 0) throw new FetchError(400, "Add at least one extension.");
    const trialUsed = wantsFree ? false : !(await claimTrial(env.WATCHLISTS, ipOf(req)));
    const startPlan: Plan = wantsFree || trialUsed ? "free" : "trial";
    const limit = startPlan === "free" ? FREE_MAX_IDS : MAX_IDS;
    const ids = allIds.slice(0, limit);
    const dropped = Math.max(0, allIds.length - limit);
    const token = newToken(); const now = new Date().toISOString();
    const wl: Watchlist = { name: String(body.name ?? "My team").trim().slice(0, 60) || "My team", ids, snapshots: {}, changes: [], createdAt: now, lastCheck: now, plan: startPlan, trialEndsAt: startPlan === "trial" ? trialEndFrom() : undefined };
    apply(wl, await scanMany(ids, snapshotter(env.WATCHLISTS, new Map(), { left: MAX_IDS, kv: 4 * MAX_IDS })), true); // baseline: no "new" noise
    await ensureViewToken(env.WATCHLISTS, token, wl);
    await save(env.WATCHLISTS, token, wl);
    await appendAudit(env.WATCHLISTS, token, "created");
    return Response.json({ token, url: `/w/${token}`, dropped, plan: startPlan, note: trialUsed ? TRIAL_USED_MESSAGE : undefined });
  },
  "GET /api/watchlists": async (req, env, rest) => {
    if (rest.includes("/")) return exportResponse(req, env, rest);
    let token = rest;
    let wl = await load(env.WATCHLISTS, token);
    const role = wl ? "admin" : "viewer";
    if (!wl) {
      token = (await resolveView(env.WATCHLISTS, rest)) ?? "";
      wl = token ? await load(env.WATCHLISTS, token) : null;
    }
    if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
    const hadView = Boolean(wl.viewToken);
    const viewToken = role === "admin" ? await ensureViewToken(env.WATCHLISTS, token, wl) : wl.viewToken;
    if ((wl.viewedAt ?? "").slice(0, 10) !== today() || !hadView) { wl.viewedAt = new Date().toISOString(); await save(env.WATCHLISTS, token, wl); }
    const { webhook, viewToken: _v, audit: _storedAudit, ...shown } = wl;
    const usage = planUsage(wl);
    if (role === "viewer") return Response.json({ ...shown, role, webhook: null, webhookSet: Boolean(webhook), usage });
    // The audit log is a Team feature, so a Free list is shown without one.
    const audit = usage.plan === "free" ? [] : await readAudit(env.WATCHLISTS, token);
    return Response.json({ ...shown, role, viewToken, webhook: maskWebhook(webhook), webhookSet: Boolean(webhook), audit, usage });
  },
  "DELETE /api/watchlists": async (_req, env, rest) => {
    const wl = await load(env.WATCHLISTS, rest);
    if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
    await appendAudit(env.WATCHLISTS, rest, "deleted");
    await remove(env.WATCHLISTS, rest);
    return Response.json({ deleted: true });
  },
  "PUT /api/watchlists": async (req, env, rest) => {
    // Operator only: billing is not live, so a plan changes only with the operator code on top of the admin link.
    if (rest.endsWith("/plan")) {
      const token = rest.slice(0, -"/plan".length);
      const wl = await load(env.WATCHLISTS, token);
      if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
      if (!env.OPERATOR_CODE || !(await sameSecret(req.headers.get("x-operator-code") ?? "", env.OPERATOR_CODE))) {
        return Response.json({ error: "Plans are changed by the operator while billing is not live." }, { status: 403 });
      }
      const value = (await json<{ plan?: unknown }>(req)).plan;
      const raw = typeof value === "string" ? value.trim().toLowerCase() : "";
      if (raw !== "free" && raw !== "team") throw new FetchError(400, "Use a plan of free or team.");
      const plan = raw as Plan;
      if (plan !== wl.plan) await appendAudit(env.WATCHLISTS, token, "plan set to " + plan);
      wl.plan = plan;
      wl.trialEndsAt = undefined;
      await save(env.WATCHLISTS, token, wl);
      return Response.json({ plan, usage: planUsage(wl) });
    }
    const wl = await load(env.WATCHLISTS, rest);
    if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
    const body = await json<{ webhook?: unknown; name?: unknown }>(req);
    if (body.webhook !== undefined) {
      const raw = String(body.webhook ?? "").trim();
      const problem = raw ? webhookProblem(raw) : null;
      if (problem) throw new FetchError(400, problem);
      const next = raw || null;
      if (next !== (wl.webhook ?? null)) await appendAudit(env.WATCHLISTS, rest, next ? "webhook set" : "webhook removed");
      wl.webhook = next;
    }
    if (body.name !== undefined) {
      const name = String(body.name ?? "").trim().slice(0, 60);
      if (name && name !== wl.name) { wl.name = name; await appendAudit(env.WATCHLISTS, rest, "renamed"); }
    }
    await save(env.WATCHLISTS, rest, wl);
    return Response.json({ webhook: Boolean(wl.webhook), name: wl.name });
  },
  "POST /api/test-alert": async (req, env) => {
    const token = String((await json<{ token?: unknown }>(req)).token ?? "");
    if (!(await allow(env.WATCHLISTS, ipOf(req), "test-alert", 10, today()))) throw new FetchError(429, "Test alert limit reached for today.");
    const wl = await load(env.WATCHLISTS, token);
    if (!wl) return Response.json({ error: "This watchlist does not exist." }, { status: 404 });
    if (!wl.webhook) throw new FetchError(400, "Save a webhook URL first.");
    const id = wl.ids[0] ?? "";
    const sample = [{ kind: "permission_added", value: "cookies (test alert, not a real change)", severity: "high" as const, id, at: new Date().toISOString() }];
    const viewToken = await ensureViewToken(env.WATCHLISTS, token, wl);
    await save(env.WATCHLISTS, token, wl);
    const res = await sendAlert(wl, sample, `${new URL(req.url).origin}/w/${viewToken}`);
    if (res.ok) await appendAudit(env.WATCHLISTS, token, "test alert sent");
    return Response.json({ sent: res.ok, status: res.status });
  },
  "GET /api/rules": async () => Response.json({ rules: RULES }),
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    setAddressSalt(env.ADDRESS_SALT);
    const res = secure(await route(request, env));
    // A response that can carry a watchlist token or an export must never be stored by a shared cache.
    if (new URL(request.url).pathname.startsWith("/api/")) res.headers.set("cache-control", "no-store");
    return res;
  },
  async scheduled(_event: unknown, env: Env & { ORIGIN?: string }): Promise<void> {
    const budget: Budget = { left: FETCH_BUDGET, kv: KV_BUDGET };
    const get = snapshotter(env.WATCHLISTS, new Map(), budget);
    const origin = env.ORIGIN ?? "https://extension-watch.lipmichal.workers.dev";
    for (const token of (await dueTokens(env.WATCHLISTS, DAY_MS - 3_600_000)).slice(0, MAX_LISTS_PER_RUN)) {
      if (budget.left <= 0 || budget.kv <= 10) break;
      budget.kv -= 6; // load, re-load before save, save with its two tombstone checks, and the view-token write when one is created
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
    // Burst limit per address on every write (Cloudflare rate limiting binding); the daily KV counters are approximate on top.
    if (request.method !== "GET" && url.pathname.startsWith("/api/") && env.WRITE_LIMIT && !(await env.WRITE_LIMIT.limit({ key: ipOf(request) })).success) {
      return Response.json({ error: "Too many requests. Wait a minute and try again." }, { status: 429 });
    }
    if (url.pathname.startsWith("/w/")) return env.ASSETS.fetch(new Request(new URL("/", url), request));
    // The privacy page is a served static document, not a single-page-app route.
    if (url.pathname === "/privacy" || url.pathname === "/privacy/") return env.ASSETS.fetch(new Request(new URL("/privacy.html", url), request));
    const parts = url.pathname.split("/");
    const a = parts[2] ?? "";
    const rest = parts.slice(3).join("/");
    const handler = routes[`${request.method} /api/${a}`];
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    if (!handler) return Response.json({ error: "Not found." }, { status: 404 });
    try { return await handler(request, env, rest); } catch (err) {
      if (err instanceof AddressSaltMissing) {
        console.error(err.message);
        return Response.json({ error: err.message }, { status: 503 });
      }
      const status = err instanceof FetchError ? err.status : 500;
      return Response.json({ error: err instanceof FetchError ? err.message : "Something went wrong." }, { status: status >= 400 && status < 600 ? status : 500 });
    }
}

export { apply as applySnapshots };
