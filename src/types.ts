// Shared contract for Extension Watch. Owned by the orchestrator; workers import, never edit.
export interface Manifest {
  id: string; name: string; version: string; manifestVersion: number; permissions: string[]; optionalPermissions: string[];
  hostPermissions: string[]; contentScriptMatches: string[]; externallyConnectable: string[]; hasBackground: boolean;
  csp: string | null; updateUrl: string | null; description: string;
}
export type Severity = "critical" | "high" | "medium" | "low";
export interface Finding { code: string; severity: Severity; title: string; detail: string; points: number }
export interface Assessment { score: number; grade: "A" | "B" | "C" | "D" | "F"; findings: Finding[]; summary: string }
export interface Change {
  kind: "permission_added" | "permission_removed" | "host_added" | "host_removed" | "mv_changed" | "new_extension" | "removed_from_store"
    | "content_script_added" | "content_script_removed" | "optional_added" | "externally_connectable_added" | "csp_changed" | "update_url_changed" | "score_jump";
  value: string; severity: Severity;
}
export class FetchError extends Error {
  constructor(public status: number, message: string) { super(message); this.name = "FetchError"; }
}
