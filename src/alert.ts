import type { LoggedChange, Watchlist } from "./store.js";

// Outgoing alerts. One https webhook per watchlist: Slack and Discord get chat JSON, ntfy.sh gets a plain-text push.
// The payload holds only the watchlist name and public extension data. Redirects are not followed.

const LABEL: Record<string, string> = {
  permission_added: "Permission added", host_added: "Site access added", content_script_added: "Runs on new sites",
  optional_added: "Can now request", externally_connectable_added: "Accepts messages from", csp_changed: "Script policy loosened",
  update_url_changed: "Updates from outside the store", score_jump: "Access grade rose", removed_from_store: "Removed from the store",
  mv_changed: "Manifest version changed", version_changed: "New version",
};
const RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function webhookProblem(raw: string): string | null {
  let u: URL;
  try { u = new URL(raw); } catch { return "That is not a valid URL."; }
  if (u.protocol !== "https:") return "Use an https webhook URL.";
  if (raw.length > 500) return "That URL is too long.";
  if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.)/.test(u.hostname) || !u.hostname.includes(".")) return "Use a public webhook URL.";
  return null;
}

/** Changes worth a notification: medium severity or above. */
export const alertable = (changes: LoggedChange[]) => changes.filter((c) => (RANK[c.severity] ?? 0) >= 1);

export function alertText(name: string, changes: LoggedChange[], names: Record<string, string>, link: string): string {
  const lines = changes.slice(0, 10).map((c) => `- ${c.severity.toUpperCase()}: ${names[c.id] ?? c.id}: ${LABEL[c.kind] ?? c.kind}${c.value && c.value !== c.id ? ` (${c.value})` : ""}`);
  const more = changes.length > 10 ? `\n- and ${changes.length - 10} more` : "";
  return `Extension Watch: ${changes.length} change${changes.length === 1 ? "" : "s"} in "${name}"\n${lines.join("\n")}${more}\n${link}`;
}

export async function sendAlert(wl: Watchlist, changes: LoggedChange[], link: string): Promise<{ ok: boolean; status: number }> {
  if (!wl.webhook || changes.length === 0) return { ok: false, status: 0 };
  const names: Record<string, string> = {};
  for (const [id, s] of Object.entries(wl.snapshots)) names[id] = s.manifest?.name ?? id;
  const text = alertText(wl.name, changes, names, link);
  const host = new URL(wl.webhook).hostname;
  const init: RequestInit = host === "ntfy.sh"
    ? { method: "POST", body: text, headers: { Title: "Extension Watch alert", Tags: "warning" } }
    : { method: "POST", body: JSON.stringify({ text, content: text.slice(0, 1900) }), headers: { "content-type": "application/json" } };
  try {
    const res = await fetch(wl.webhook, { ...init, redirect: "manual", signal: AbortSignal.timeout(5000) });
    return { ok: res.ok, status: res.status };
  } catch (err) {
    console.log("alert failed", host, err instanceof Error ? err.name : "error");
    return { ok: false, status: 0 };
  }
}
