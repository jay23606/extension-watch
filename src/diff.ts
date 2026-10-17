import type { Change, Manifest } from "./types";
import { permissionSeverity } from "./risk";

export function diff(prev: Manifest | null, next: Manifest | null): Change[] {
  if (prev === null) {
    if (next === null) return [];
    return [{ kind: "new_extension", value: next.id, severity: "medium" }];
  }
  if (next === null) return [{ kind: "removed_from_store", value: prev.id, severity: "low" }];

  const changes: Change[] = [];

  const prevPerms = new Set(prev.permissions);
  const nextPerms = new Set(next.permissions);
  for (const p of nextPerms) {
    if (!prevPerms.has(p)) changes.push({ kind: "permission_added", value: p, severity: permissionSeverity(p) });
  }
  for (const p of prevPerms) {
    if (!nextPerms.has(p)) changes.push({ kind: "permission_removed", value: p, severity: permissionSeverity(p) });
  }

  const prevHosts = new Set(prev.hostPermissions);
  const nextHosts = new Set(next.hostPermissions);
  for (const h of nextHosts) {
    if (!prevHosts.has(h)) changes.push({ kind: "host_added", value: h, severity: "critical" });
  }
  for (const h of prevHosts) {
    if (!nextHosts.has(h)) changes.push({ kind: "host_removed", value: h, severity: "low" });
  }

  if (prev.manifestVersion !== next.manifestVersion) {
    changes.push({
      kind: "mv_changed",
      value: `${prev.manifestVersion} -> ${next.manifestVersion}`,
      severity: next.manifestVersion === 2 ? "medium" : "low",
    });
  }

  return changes;
}
