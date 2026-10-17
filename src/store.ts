import type { Assessment, Change, Manifest } from "./types.js";

// One KV record per watchlist (key wl:<token>, metadata {lastCheck}) and one shared cache record per extension per day
// (key ext:<id>). The 32-byte random token in the link is the only key to a watchlist; no personal data is stored.
/** `transient` marks failures worth retrying (Google 5xx, timeouts); a definitive answer (not listed, 404, unreadable) counts as a check. */
export interface Snapshot { id: string; manifest: Manifest | null; assessment: Assessment | null; error: string | null; checkedAt: string; transient?: boolean }
export type LoggedChange = Omit<Change, "kind"> & { kind: string; id: string; at: string };
export interface Watchlist { name: string; ids: string[]; snapshots: Record<string, Snapshot>; changes: LoggedChange[]; createdAt: string; lastCheck: string; webhook?: string | null; viewedAt?: string; viewToken?: string }
export interface Kv {
  get(k: string): Promise<string | null>;
  put(k: string, v: string, o?: { expirationTtl?: number; metadata?: unknown }): Promise<void>;
  delete(k: string): Promise<void>;
  list(o: { prefix: string; cursor?: string }): Promise<{ keys: { name: string; metadata?: unknown }[]; list_complete: boolean; cursor?: string }>;
}

export const MAX_IDS = 50;
export const MAX_CHANGES = 200;
export const IDLE_TTL = 90 * 86400; // every save renews it; the scheduler stops saving lists nobody opened for 90 days, so they expire
const CACHE_TTL = 3 * 86400;

export function newToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const validToken = (t: string) => /^[A-Za-z0-9_-]{43}$/.test(t);

export async function load(kv: Kv, token: string): Promise<Watchlist | null> {
  if (!validToken(token)) return null;
  const raw = await kv.get(`wl:${token}`);
  return raw ? (JSON.parse(raw) as Watchlist) : null;
}

export async function save(kv: Kv, token: string, wl: Watchlist): Promise<void> {
  wl.changes = wl.changes.slice(-MAX_CHANGES);
  await kv.put(`wl:${token}`, JSON.stringify(wl), { expirationTtl: IDLE_TTL, metadata: { lastCheck: wl.lastCheck } });
}

export async function remove(kv: Kv, token: string): Promise<boolean> {
  const wl = await load(kv, token);
  if (!wl) return false;
  await kv.delete(`wl:${token}`);
  if (wl.viewToken) await kv.delete(`vw:${wl.viewToken}`);
  return true;
}

/** Read-only share links map to the admin token; only the admin token can change or delete a list. */
export async function resolveView(kv: Kv, viewToken: string): Promise<string | null> {
  if (!validToken(viewToken)) return null;
  return kv.get(`vw:${viewToken}`);
}

export async function ensureViewToken(kv: Kv, token: string, wl: Watchlist): Promise<string> {
  if (wl.viewToken) return wl.viewToken;
  wl.viewToken = newToken();
  await kv.put(`vw:${wl.viewToken}`, token, { expirationTtl: 400 * 86400 }); // outlives the list; a stale view link resolves to 404
  return wl.viewToken;
}

/** Watchlists due for a check (last check older than maxAgeMs), oldest first. Bounded by page count. */
export async function dueTokens(kv: Kv, maxAgeMs: number, now = Date.now(), maxPages = 20): Promise<string[]> {
  const due: Array<[string, number]> = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const res = await kv.list({ prefix: "wl:", cursor });
    for (const k of res.keys) {
      const last = Date.parse(String((k.metadata as { lastCheck?: string } | undefined)?.lastCheck ?? "1970-01-01"));
      if (now - last >= maxAgeMs) due.push([k.name.slice(3), last]);
    }
    if (res.list_complete || !res.cursor) break;
    cursor = res.cursor;
  }
  return due.sort((a, b) => a[1] - b[1]).map(([t]) => t);
}

export async function cachedSnapshot(kv: Kv, id: string, day: string): Promise<Snapshot | null> {
  const raw = await kv.get(`ext:${id}`);
  if (!raw) return null;
  const hit = JSON.parse(raw) as Snapshot & { day?: string };
  return hit.day === day ? hit : null;
}

export async function cacheSnapshot(kv: Kv, snap: Snapshot, day: string): Promise<void> {
  // Definitive failures are cached for the day too, so a removed extension is not downloaded again on every run.
  if (!snap.transient) await kv.put(`ext:${snap.id}`, JSON.stringify({ ...snap, day }), { expirationTtl: CACHE_TTL });
}

/** Per-address daily counter for anonymous writes. Returns false when the limit is reached. */
export async function allow(kv: Kv, ip: string, action: string, limit: number, day: string): Promise<boolean> {
  const key = `rl:${action}:${day}:${ip.slice(0, 64)}`;
  const used = Number((await kv.get(key)) ?? "0");
  if (used >= limit) return false;
  await kv.put(key, String(used + 1), { expirationTtl: 2 * 86400 });
  return true;
}
