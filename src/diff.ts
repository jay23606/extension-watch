import type { Change, Manifest, Severity } from "./types";
import { assess, cspUnsafe, isBroad, isGoogleHost, permissionSeverity } from "./risk";

function demote(severity: Severity): Severity {
  if (severity === "critical") return "high";
  if (severity === "high") return "medium";
  if (severity === "medium") return "low";
  return "low";
}

function optionalSeverity(perm: string, next: Manifest): Severity {
  if (isBroad(perm)) return "high";
  return demote(permissionSeverity(perm, next));
}

function added(setPrev: Set<string>, setNext: Set<string>): string[] {
  return [...setNext].filter((v) => !setPrev.has(v));
}

function removed(setPrev: Set<string>, setNext: Set<string>): string[] {
  return [...setPrev].filter((v) => !setNext.has(v));
}

export function diff(prev: Manifest | null, next: Manifest | null): Change[] {
  if (prev === null) {
    if (next === null) return [];
    return [{ kind: "new_extension", value: next.id, severity: "medium" }];
  }
  if (next === null) return [{ kind: "removed_from_store", value: prev.id, severity: "low" }];

  const changes: Change[] = [];
  const push = (kind: Change["kind"], value: string, severity: Severity) =>
    changes.push({ kind, value, severity });

  for (const p of added(new Set(prev.permissions), new Set(next.permissions))) push("permission_added", p, permissionSeverity(p, next));
  for (const p of removed(new Set(prev.permissions), new Set(next.permissions))) push("permission_removed", p, permissionSeverity(p, prev));

  for (const h of added(new Set(prev.hostPermissions), new Set(next.hostPermissions))) push("host_added", h, isBroad(h) ? "critical" : "medium");
  for (const h of removed(new Set(prev.hostPermissions), new Set(next.hostPermissions))) push("host_removed", h, "low");

  for (const m of added(new Set(prev.contentScriptMatches), new Set(next.contentScriptMatches))) push("content_script_added", m, isBroad(m) ? "critical" : "medium");
  for (const m of removed(new Set(prev.contentScriptMatches), new Set(next.contentScriptMatches))) push("content_script_removed", m, "low");

  for (const p of added(new Set(prev.optionalPermissions), new Set(next.optionalPermissions))) push("optional_added", p, optionalSeverity(p, next));

  for (const e of added(new Set(prev.externallyConnectable), new Set(next.externallyConnectable))) push("externally_connectable_added", e, isBroad(e) ? "high" : "low");

  if (prev.csp !== next.csp && cspUnsafe(next.csp) && !cspUnsafe(prev.csp)) push("csp_changed", next.csp ?? "", "high");

  if (prev.updateUrl !== next.updateUrl) {
    const external = next.updateUrl !== null && !isGoogleHost(next.updateUrl);
    push("update_url_changed", next.updateUrl ?? "(none)", external ? "high" : "low");
  }

  if (prev.manifestVersion !== next.manifestVersion) {
    push("mv_changed", `${prev.manifestVersion} -> ${next.manifestVersion}`, next.manifestVersion === 2 ? "medium" : "low");
  }

  const prevScore = assess(prev).score;
  const nextScore = assess(next).score;
  const jump = nextScore - prevScore;
  if (jump >= 15) push("score_jump", `${prevScore} -> ${nextScore}`, jump >= 25 ? "critical" : "high");

  return changes;
}
