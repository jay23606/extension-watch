import { SENSITIVE_DOMAINS } from "./risk.js";
import type { Assessment } from "./types.js";
import type { Watchlist } from "./store.js";

// Plain exports for a watchlist. CSV follows RFC 4180 quoting, and the policy is the Chrome
// ExtensionSettings shape used by the Google Admin console (Apps > Additional Google services >
// Chrome Web Store > ExtensionSettings).

const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };

/** A grade threshold from A to F, or null when the value is not a grade. Null input means F. */
export function thresholdFrom(raw: string | null): string | null {
  if (raw === null || raw.trim() === "") return "F";
  const grade = raw.trim().toUpperCase();
  return Object.hasOwn(GRADE_RANK, grade) ? grade : null;
}

export function csvCell(value: unknown): string {
  const text = value === undefined || value === null ? "" : String(value);
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

const BLOCKED_PERMISSIONS: readonly string[] = ["debugger"];

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

function restrictedEntry(installationMode: "allowed" | "blocked"): Record<string, unknown> {
  return {
    installation_mode: installationMode,
    blocked_permissions: [...BLOCKED_PERMISSIONS],
    runtime_blocked_hosts: runtimeBlockedHosts(),
  };
}

/** Chrome ExtensionSettings policy. Grades at or below the threshold are blocked; the rest are allowed. */
export function policyFor(wl: Watchlist, threshold: string): { ExtensionSettings: Record<string, unknown> } {
  const blockedRank = GRADE_RANK[threshold] ?? GRADE_RANK.F!;
  const settings: Record<string, unknown> = { "*": restrictedEntry("blocked") };
  for (const id of wl.ids) {
    const grade = wl.snapshots[id]?.assessment?.grade;
    // An extension that could not be read is not reviewed, so the default block stands.
    settings[id] = grade && (GRADE_RANK[grade] ?? GRADE_RANK.F!) < blockedRank
      // Chrome does not inherit from "*", so an allowed extension repeats the permission and host blocks.
      ? restrictedEntry("allowed")
      : { installation_mode: "blocked" };
  }
  return { ExtensionSettings: settings };
}
