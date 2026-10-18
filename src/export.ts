import { SENSITIVE_DOMAINS } from "./risk.js";
import type { Assessment } from "./types.js";
import type { Watchlist } from "./store.js";

// Plain exports for a watchlist. CSV follows RFC 4180 quoting, and the policy is the Chrome
// ExtensionSettings shape used in the Google Admin console (Chrome browser > Custom Configurations
// under Chrome Enterprise Core).

const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };

/** A grade threshold from A to F, or null when the value is not a grade. Null input means F. */
export function thresholdFrom(raw: string | null): string | null {
  if (raw === null || raw.trim() === "") return "F";
  const grade = raw.trim().toUpperCase();
  return Object.hasOwn(GRADE_RANK, grade) ? grade : null;
}

export function csvCell(value: unknown): string {
  let text = value === undefined || value === null ? "" : String(value);
  // A cell that starts with one of these characters can run as a formula in a spreadsheet, so a
  // single quote is prefixed (OWASP CSV injection guidance) before the usual RFC 4180 quoting.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function csv(rows: unknown[][]): string {
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

function topFindings(assessment: Assessment | null | undefined): string {
  const findings = assessment?.findings.filter((f) => f.points > 0).slice(0, 3) ?? [];
  return findings.map((f) => f.title).join("; ");
}

export function inventoryCsv(wl: Watchlist): string {
  const rows: unknown[][] = [["id", "name", "version", "grade", "score", "top findings", "last checked"]];
  for (const id of wl.ids) {
    const snap = wl.snapshots[id];
    rows.push([id, snap?.manifest?.name ?? "", snap?.manifest?.version ?? "", snap?.assessment?.grade ?? "",
      snap?.assessment?.score ?? "", topFindings(snap?.assessment), snap?.checkedAt ?? ""]);
  }
  return csv(rows);
}

export function changesCsv(wl: Watchlist): string {
  const rows: unknown[][] = [["at", "extension id", "extension name", "kind", "value", "severity"]];
  for (const change of wl.changes) {
    rows.push([change.at, change.id, wl.snapshots[change.id]?.manifest?.name ?? "", change.kind, change.value, change.severity]);
  }
  return csv(rows);
}

/** The admin action log, one row per action with its time and label only. */
export function auditCsv(wl: Watchlist): string {
  const rows: unknown[][] = [["at", "action"]];
  for (const entry of wl.audit ?? []) rows.push([entry.at, entry.action]);
  return csv(rows);
}

const BLOCKED_PERMISSIONS: readonly string[] = ["debugger"];

export type PolicyMode = "threshold" | "default-deny";

/** A policy mode from the query string. Null input means threshold, an unknown value means null. */
export function modeFrom(raw: string | null): PolicyMode | null {
  if (raw === null || raw.trim() === "") return "threshold";
  const mode = raw.trim().toLowerCase();
  return mode === "threshold" || mode === "default-deny" ? mode : null;
}

/**
 * Password managers and single sign-on tools that must keep their own sign-in domains at runtime. Each
 * one is matched by extension id from a fixed list, never by the publisher-controlled name.
 */
const RUNTIME_TOOLS: readonly { ids: readonly string[]; vendor: readonly string[]; signIn: readonly string[] }[] = [
  { ids: ["nngceckbapebfimnlniiiahkandclblb"], vendor: ["bitwarden.com"], signIn: ["vault.bitwarden.com"] },
  { ids: ["aeblfdkhhhdcdjpifhhbdiojplfjncoa"], vendor: ["1password.com"], signIn: ["my.1password.com", "start.1password.com"] },
  { ids: ["hdokiejnpimakedhajhdlcegeplioahd"], vendor: ["lastpass.com"], signIn: ["lastpass.com"] },
  { ids: ["fdjamakpfbbddfjaooikfcpapjohcfmg"], vendor: ["dashlane.com"], signIn: ["www.dashlane.com"] },
  { ids: ["bfogiafebfohielmmehodmfbbebbbpei"], vendor: ["keepersecurity.com", "keepersecurity.eu"], signIn: ["keepersecurity.com"] },
  { ids: ["glnpjglilkicbckjpbgcfkogebgllemb"], vendor: ["okta.com"], signIn: ["okta.com"] },
];

/**
 * One Chrome host pattern per sensitive domain family. A wildcard covers the host and its
 * subdomains, so a family listed under another one is dropped, and runtime_blocked_hosts takes no
 * path and no port.
 */
export function runtimeBlockedHosts(): string[] {
  const hosts = [...new Set(SENSITIVE_DOMAINS.map((domain) => domain.trim().toLowerCase()))];
  return hosts
    .filter((host) => !hosts.some((other) => other !== host && host.endsWith(`.${other}`)))
    .sort()
    .map((host) => `*://*.${host}`);
}

function toolFor(id: string | null | undefined): { vendor: readonly string[]; signIn: readonly string[] } | null {
  if (!id) return null;
  const key = id.trim().toLowerCase();
  return RUNTIME_TOOLS.find((tool) => tool.ids.includes(key)) ?? null;
}

/**
 * An allowed extension repeats the permission and host blocks from the catch-all entry, because Chrome
 * does not inherit them. A password manager or sign-on tool, found by its extension id, keeps its own
 * vendor domains, and gets the sign-in domains it needs as runtime_allowed_hosts, which the
 * ExtensionSettings format accepts.
 */
function allowedEntry(id: string): Record<string, unknown> {
  const tool = toolFor(id);
  const blocked = runtimeBlockedHosts().filter((pattern) => !(tool?.vendor ?? []).some((domain) => pattern === `*://*.${domain}`));
  const entry: Record<string, unknown> = {
    installation_mode: "allowed",
    blocked_permissions: [...BLOCKED_PERMISSIONS],
    runtime_blocked_hosts: blocked,
  };
  if (tool && tool.signIn.length) entry.runtime_allowed_hosts = tool.signIn.map((domain) => `*://*.${domain}`);
  return entry;
}

/** Chrome ExtensionSettings policy for one of two modes. See the README for what each mode blocks. */
export function policyFor(wl: Watchlist, threshold: string, mode: PolicyMode = "threshold"): { ExtensionSettings: Record<string, unknown> } {
  const blockedRank = GRADE_RANK[threshold] ?? GRADE_RANK.F!;
  const settings: Record<string, unknown> = {
    // Default deny blocks every extension that is not on the list. Threshold mode keeps the catch-all
    // installable but still keeps every extension off the debugger permission and off sensitive sites.
    "*": mode === "default-deny"
      ? { installation_mode: "blocked", blocked_permissions: [...BLOCKED_PERMISSIONS], runtime_blocked_hosts: runtimeBlockedHosts() }
      : { blocked_permissions: [...BLOCKED_PERMISSIONS], runtime_blocked_hosts: runtimeBlockedHosts() },
  };
  for (const id of wl.ids) {
    const snap = wl.snapshots[id];
    const grade = snap?.assessment?.grade;
    const rank = grade ? (GRADE_RANK[grade] ?? GRADE_RANK.F!) : null;
    // Default deny blocks anything that was not reviewed. Threshold mode blocks only what was graded at
    // or below the threshold, and allows the rest of the list.
    const allowed = mode === "default-deny" ? rank !== null && rank < blockedRank : rank === null || rank < blockedRank;
    settings[id] = allowed ? allowedEntry(id) : { installation_mode: "blocked" };
  }
  return { ExtensionSettings: settings };
}
