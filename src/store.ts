import type { Assessment, Change, Manifest } from "./types.js";

// One KV record per watchlist. The 32-byte random token in the link is the only key; no personal data is stored.
export interface Snapshot { id: string; manifest: Manifest | null; assessment: Assessment | null; error: string | null; checkedAt: string }
export interface Watchlist { name: string; ids: string[]; snapshots: Record<string, Snapshot>; changes: Array<Change & { id: string; at: string }>; createdAt: string; lastCheck: string }
export interface Kv { get(k: string): Promise<string | null>; put(k: string, v: string): Promise<void>; list(o: { prefix: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }> }

export const MAX_IDS = 50;
export const MAX_CHANGES = 200;

export function newToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function load(kv: Kv, token: string): Promise<Watchlist | null> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const raw = await kv.get(`wl:${token}`);
  return raw ? (JSON.parse(raw) as Watchlist) : null;
}

export async function save(kv: Kv, token: string, wl: Watchlist): Promise<void> {
  wl.changes = wl.changes.slice(-MAX_CHANGES);
  await kv.put(`wl:${token}`, JSON.stringify(wl));
}

/** All watchlist tokens, page by page (bounded). */
export async function allTokens(kv: Kv, maxPages = 20): Promise<string[]> {
  const out: string[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const res = await kv.list({ prefix: "wl:", cursor });
    out.push(...res.keys.map((k) => k.name.slice(3)));
    if (res.list_complete || !res.cursor) break;
    cursor = res.cursor;
  }
  return out;
}
