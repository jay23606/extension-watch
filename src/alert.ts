import type { LoggedChange, Watchlist } from "./store.js";

// Outgoing alerts. One https webhook per watchlist. The JSON body carries `text` (Slack, Google Chat) and `content` (Discord).
// The payload holds only the watchlist name and public extension data. Redirects are not followed.

const LABEL: Record<string, string> = {
  permission_added: "Permission added", host_added: "Site access added", content_script_added: "Runs on new sites",
  optional_added: "Can now request", externally_connectable_added: "Accepts messages from", csp_changed: "Script policy loosened",
  update_url_changed: "Updates from outside the store", score_jump: "Access grade rose", removed_from_store: "Removed from the store",
  mv_changed: "Manifest version changed", version_changed: "New version",
  unreadable: "Package can no longer be read", new_extension: "New extension",
};
const RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** Webhooks must be a public https host name on the default port: no IP literals, no user names, no internal names. */
export function webhookProblem(raw: string): string | null {
  if (raw.length > 500) return "That URL is too long.";
  let u: URL;
  try { u = new URL(raw); } catch { return "That is not a valid URL."; }
  if (u.protocol !== "https:") return "Use an https webhook URL.";
  if (u.username || u.password) return "Remove the user name and password from the URL.";
  if (u.port !== "") return "Use the standard https port.";
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  if (/^[\d.]+$/.test(host) || host.startsWith("[")) return "Use a host name, not an IP address.";
  if (!host.includes(".") || /(^|\.)(localhost|local|internal|intranet|lan|home|corp|localtest\.me|lvh\.me|vcap\.me|nip\.io|sslip\.io|xip\.io|traefik\.me)$/.test(host)) return "Use a public webhook host.";
  return null;
}

/** What a saved webhook looks like when shown back: the host only. */
export function maskWebhook(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try { return `https://${new URL(raw).hostname}/...`; } catch { return "https://.../..."; }
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
  const init: RequestInit = { method: "POST", body: JSON.stringify({ text, content: text.slice(0, 1900) }), headers: { "content-type": "application/json" } };
  try {
    const res = await fetch(wl.webhook, { ...init, redirect: "manual", signal: AbortSignal.timeout(5000) });
    return { ok: res.ok, status: res.status };
  } catch (err) {
    console.log("alert failed", host, err instanceof Error ? err.name : "error");
    return { ok: false, status: 0 };
  }
}
