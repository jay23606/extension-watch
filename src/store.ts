import type { Assessment, Change, Manifest } from "./types.js";

// One KV record per watchlist (key wl:<token>, metadata {lastCheck}), one shared cache record per extension per day
// (key ext:<id>) and one KV key per audit entry (key au:<token>:<id>). The 32-byte random token in the link is the
// only key to a watchlist; no personal data is stored.
/** `transient` marks failures worth retrying (Google 5xx, timeouts); a definitive answer (not listed, 404, unreadable) counts as a check. */
export interface Snapshot { id: string; manifest: Manifest | null; assessment: Assessment | null; error: string | null; checkedAt: string; transient?: boolean }
export type LoggedChange = Omit<Change, "kind"> & { kind: string; id: string; at: string };
/** One admin action with its time only, never a token or a webhook URL. */
export interface AuditEntry { at: string; action: string }
export type Plan = "free" | "team" | "trial";
export interface Watchlist { name: string; ids: string[]; snapshots: Record<string, Snapshot>; changes: LoggedChange[]; audit?: AuditEntry[]; createdAt: string; lastCheck: string; webhook?: string | null; viewedAt?: string; viewToken?: string; plan?: Plan; trialEndsAt?: string }
export interface Kv {
  get(k: string): Promise<string | null>;
  put(k: string, v: string, o?: { expirationTtl?: number; metadata?: unknown }): Promise<void>;
  delete(k: string): Promise<void>;
  list(o: { prefix: string; cursor?: string }): Promise<{ keys: { name: string; metadata?: unknown }[]; list_complete: boolean; cursor?: string }>;
}

export const MAX_IDS = 50;
export const MAX_CHANGES = 200;
export const MAX_AUDIT = 100;
export const IDLE_TTL = 90 * 86400; // every save renews it; the scheduler stops saving lists nobody opened for 90 days, so they expire
/** A list on the Free plan holds at most this many extension ids. */
export const FREE_MAX_IDS = 25;
/** A new list starts on this many days of the Team plan, so a first visitor sees every feature at once. */
export const TRIAL_DAYS = 14;
/** One Team trial is allowed per client address inside this many days, so a fresh list cannot renew it. */
export const TRIAL_WINDOW_DAYS = 30;
/** Trials one address may start inside the window. Enough for a team or a judge to try a few lists, not to churn forever. */
export const TRIALS_PER_WINDOW = 3;
const CACHE_TTL = 3 * 86400;

/** The instant a Team trial granted now would end. */
export function trialEndFrom(now = Date.now()): string {
  return new Date(now + TRIAL_DAYS * 86_400_000).toISOString();
}

/** Thrown when the Worker has no usable address salt, so no address hash could be safe. */
export class AddressSaltMissing extends Error {
  constructor() {
    super("server misconfigured, address salt missing");
    this.name = "AddressSaltMissing";
  }
}

/** A hex SHA-256 of the client address, so the trial markers never store the raw address. */
let addressSalt = "";

/**
 * The Worker sets a secret salt per request, so a stored address hash cannot be reversed by trying
 * every address. A missing or short secret is refused rather than replaced by an empty salt.
 */
export function setAddressSalt(salt: string | undefined): void {
  const value = (salt ?? "").trim();
  addressSalt = value.length >= 16 ? value : "";
}

export function hasAddressSalt(): boolean {
  return addressSalt.length >= 16;
}

/**
 * The value that identifies a client for hashing. IPv4 stays whole. IPv6 is reduced to its /64
 * prefix after expanding "::", because one subscriber is normally handed a whole /64.
 */
export function normalizedAddress(address: string): string {
  const raw = address.trim().replace(/%.*$/, "");
  if (!raw.includes(":")) return raw;
  const sides = raw.replace(/^\[|\]$/g, "").split("::");
  const left = sides[0] ? sides[0].split(":") : [];
  const right = sides.length > 1 && sides[1] ? sides[1].split(":") : [];
  const missing = Math.max(0, 8 - left.length - right.length);
  const hextets = [...left, ...Array<string>(missing).fill("0"), ...right];
  return hextets.slice(0, 4).map((h) => (h || "0").toLowerCase().padStart(4, "0")).join(":");
}

export async function addressHash(address: string): Promise<string> {
  if (!hasAddressSalt()) throw new AddressSaltMissing();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(addressSalt + "|" + normalizedAddress(address)));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** One time-sortable, unique trial attempt id, so each claim gets its own key. */
let trialSeq = 0;
function trialId(now: number): string {
  trialSeq = (trialSeq + 1) % 1_000_000;
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  const rand = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${now.toString().padStart(13, "0")}-${trialSeq.toString().padStart(6, "0")}-${rand}`;
}

interface TrialMarker { name: string; at: number }

/** Every trial marker for one address hash, including legacy single counter records. */
async function trialMarkers(kv: Kv, hash: string): Promise<TrialMarker[]> {
  const base = `tri:${hash}`;
  const out: TrialMarker[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 25; page++) {
    const res = await kv.list({ prefix: base, cursor });
    for (const k of res.keys) {
      if (k.name === base) {
        const raw = await kv.get(base);
        if (!raw) continue;
        let count = 1;
        let at = 0;
        try {
          const parsed = JSON.parse(raw) as { count?: unknown; first?: unknown };
          count = typeof parsed.count === "number" ? parsed.count : 1;
          at = typeof parsed.first === "number" ? parsed.first : 0;
        } catch {
          at = Date.parse(raw) || 0;
        }
        // A legacy record held a count in one key, so it counts as that many attempts in the window.
        for (let i = 0; i < count; i++) out.push({ name: `${base}:${i.toString().padStart(13, "0")}`, at });
      } else if (k.name.startsWith(base + ":")) {
        const meta = k.metadata as { at?: unknown } | undefined;
        const stamp = Number(k.name.slice(base.length + 1, base.length + 14));
        out.push({ name: k.name, at: typeof meta?.at === "number" ? meta.at : Number.isFinite(stamp) ? stamp : 0 });
      }
    }
    if (res.list_complete || !res.cursor) break;
    cursor = res.cursor;
  }
  return out;
}

/**
 * Claim one Team trial for this address inside the window. Workers KV has no compare and set, so
 * each attempt writes its own unique marker, then reads the markers back and refuses when its
 * place in the order is past the cap. The cap holds for claims that see each other's markers and is
 * best effort across locations, because KV is eventually consistent.
 */
export async function claimTrial(kv: Kv, address: string, now = Date.now()): Promise<boolean> {
  const hash = await addressHash(address);
  const base = `tri:${hash}`;
  const existing = await trialMarkers(kv, hash);
  const inWindow = existing.filter((m) => m.at + TRIAL_WINDOW_DAYS * 86_400_000 > now);
  const first = inWindow.length ? Math.min(...inWindow.map((m) => m.at)) : now;
  // The window is fixed from the first trial, so later trials do not extend it.
  const windowEnd = first + TRIAL_WINDOW_DAYS * 86_400_000;
  const ttl = Math.max(60, Math.ceil((windowEnd - now) / 1000));
  const key = `${base}:${trialId(now)}`;
  await kv.put(key, JSON.stringify({ at: now }), { expirationTtl: ttl, metadata: { at: now } });
  const after = (await trialMarkers(kv, hash)).filter((m) => m.at + TRIAL_WINDOW_DAYS * 86_400_000 > now);
  const place = after.filter((m) => m.name <= key).length;
  if (place <= TRIALS_PER_WINDOW) return true;
  await kv.delete(key);
  return false;
}

/**
 * The plan in force for a list right now. A list with no plan field is a legacy list and counts as
 * Team, so a list saved before plans existed keeps every feature. A trial that has run out is Free.
 */
export function effectivePlan(wl: Watchlist, now = Date.now()): "free" | "team" {
  if (wl.plan === "free") return "free";
  if (wl.plan !== "trial") return "team";
  const ends = Date.parse(wl.trialEndsAt ?? "");
  return Number.isFinite(ends) && now < ends ? "team" : "free";
}

/** Whole days left in the Team trial, 0 when the list is not on a live trial. */
export function trialDaysLeft(wl: Watchlist, now = Date.now()): number {
  if (wl.plan !== "trial") return 0;
  const ends = Date.parse(wl.trialEndsAt ?? "");
  if (!Number.isFinite(ends) || now >= ends) return 0;
  return Math.max(0, Math.ceil((ends - now) / 86_400_000));
}

/** What the usage badge shows: the plan in force, the ids used and the free limit, and trial days left. */
export interface PlanUsage { plan: "free" | "team"; ids: number; limit: number | null; trialDaysLeft: number }

/** The ids a scheduled check covers. A Free list is checked for its first 25 ids only, even if it held more on the trial. */
export function idsToCheck(wl: Watchlist, now = Date.now()): string[] {
  return effectivePlan(wl, now) === "free" ? wl.ids.slice(0, FREE_MAX_IDS) : wl.ids;
}

export function planUsage(wl: Watchlist, now = Date.now()): PlanUsage {
  const plan = effectivePlan(wl, now);
  return { plan, ids: wl.ids.length, limit: plan === "free" ? FREE_MAX_IDS : null, trialDaysLeft: trialDaysLeft(wl, now) };
}

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

const TOMBSTONE_PREFIX = "del:";
const TOMBSTONE_TTL = 400 * 86400;

/** True when this admin token was deleted, so a slow check cannot recreate it with old data. */
export async function isDeleted(kv: Kv, token: string): Promise<boolean> {
  return (await kv.get(TOMBSTONE_PREFIX + token)) !== null;
}

export async function save(kv: Kv, token: string, wl: Watchlist): Promise<boolean> {
  // Check before and after the write. A delete that lands between the two removes the record again.
  if (await isDeleted(kv, token)) return false;
  wl.changes = wl.changes.slice(-MAX_CHANGES);
  await kv.put(`wl:${token}`, JSON.stringify(wl), { expirationTtl: IDLE_TTL, metadata: { lastCheck: wl.lastCheck } });
  if (await isDeleted(kv, token)) {
    await kv.delete(`wl:${token}`);
    return false;
  }
  return true;
}

/**
 * Append one admin action in memory, capped at the newest MAX_AUDIT entries. The worker writes each
 * action under its own KV key instead, so concurrent actions cannot overwrite each other.
 * Tokens and webhook URLs are never written here.
 */
export function logAudit(wl: Watchlist, action: string): void {
  wl.audit = [...(wl.audit ?? []), { at: new Date().toISOString(), action }].slice(-MAX_AUDIT);
}

const AUDIT_PREFIX = "au:";
let auditSeq = 0;

/** A time-sortable, unique id so a listing of the prefix reads back in the order the actions happened. */
function auditId(): string {
  auditSeq = (auditSeq + 1) % 1_000_000;
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  const rand = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${Date.now().toString().padStart(13, "0")}-${auditSeq.toString().padStart(6, "0")}-${rand}`;
}

async function listAudit(kv: Kv, token: string): Promise<{ name: string; metadata?: unknown }[]> {
  const prefix = `${AUDIT_PREFIX}${token}:`;
  const keys: { name: string; metadata?: unknown }[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 25; page++) {
    const res = await kv.list({ prefix, cursor });
    for (const k of res.keys) if (k.name.startsWith(prefix)) keys.push(k);
    if (res.list_complete || !res.cursor) break;
    cursor = res.cursor;
  }
  return keys.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/**
 * Write one admin action under its own key, then drop the oldest when more than MAX_AUDIT remain.
 * A concurrent action writes a different key, so neither can overwrite the other.
 */
export async function appendAudit(kv: Kv, token: string, action: string): Promise<void> {
  await kv.put(`${AUDIT_PREFIX}${token}:${auditId()}`, "", { metadata: { at: new Date().toISOString(), action }, expirationTtl: IDLE_TTL });
  const keys = await listAudit(kv, token);
  for (const k of keys.slice(0, Math.max(0, keys.length - MAX_AUDIT))) await kv.delete(k.name);
}

/** The newest `limit` admin actions for a list, oldest first. */
export async function readAudit(kv: Kv, token: string, limit = MAX_AUDIT): Promise<AuditEntry[]> {
  const out: AuditEntry[] = [];
  for (const k of (await listAudit(kv, token)).slice(-limit)) {
    const meta = k.metadata as { at?: unknown; action?: unknown } | undefined;
    if (meta && typeof meta.action === "string") out.push({ at: typeof meta.at === "string" ? meta.at : "", action: meta.action });
  }
  return out;
}

async function moveAudit(kv: Kv, from: string, to: string): Promise<void> {
  for (const k of await listAudit(kv, from)) {
    const id = k.name.slice(`${AUDIT_PREFIX}${from}:`.length);
    await kv.put(`${AUDIT_PREFIX}${to}:${id}`, "", { metadata: k.metadata, expirationTtl: IDLE_TTL });
    await kv.delete(k.name);
  }
}

async function deleteAudit(kv: Kv, token: string): Promise<void> {
  for (const k of await listAudit(kv, token)) await kv.delete(k.name);
}

/**
 * Move a list to a fresh admin token and a fresh read-only token, then delete the old keys. The
 * caller must already hold the admin token. Returns the new pair, or null when the list is gone.
 */
export async function rotate(kv: Kv, token: string): Promise<{ token: string; viewToken: string } | null> {
  const wl = await load(kv, token);
  if (!wl) return null;
  const oldView = wl.viewToken;
  const newAdmin = newToken();
  const newView = newToken();
  wl.viewToken = newView;
  await save(kv, newAdmin, wl);
  await kv.put(`vw:${newView}`, newAdmin, { expirationTtl: 400 * 86400 });
  // The audit keys carry the list token, so move them to the new prefix, then record the rotation.
  await moveAudit(kv, token, newAdmin);
  await appendAudit(kv, newAdmin, "rotate");
  // Retire the old admin token the same way delete does, so a check that loaded the old record cannot save it back.
  await kv.put(TOMBSTONE_PREFIX + token, JSON.stringify({ deletedAt: new Date().toISOString() }), { expirationTtl: TOMBSTONE_TTL });
  await kv.delete(`wl:${token}`);
  if (oldView) await kv.delete(`vw:${oldView}`);
  return { token: newAdmin, viewToken: newView };
}

export async function remove(kv: Kv, token: string): Promise<boolean> {
  const wl = await load(kv, token);
  if (!wl) return false;
  // Write the tombstone first, then delete the record, so a save from a running check cannot put it back.
  await kv.put(TOMBSTONE_PREFIX + token, JSON.stringify({ deletedAt: new Date().toISOString() }), { expirationTtl: TOMBSTONE_TTL });
  await kv.delete(`wl:${token}`);
  if (wl.viewToken) await kv.delete(`vw:${wl.viewToken}`);
  await deleteAudit(kv, token);
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
export async function dueTokens(kv: Kv, maxAgeMs: number, now = Date.now(), maxPages = 50): Promise<string[]> {
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
  // Daily counters are keyed by the salted address hash, never the raw address.
  const key = `rl:${action}:${day}:${(await addressHash(ip)).slice(0, 32)}`;
  const used = Number((await kv.get(key)) ?? "0");
  if (used >= limit) return false;
  await kv.put(key, String(used + 1), { expirationTtl: 2 * 86400 });
  return true;
}
