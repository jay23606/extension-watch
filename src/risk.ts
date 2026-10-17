import type { Assessment, Finding, Manifest, Severity } from "./types";

export interface Rule {
  code: string;
  group: string;
  title: string;
  points: number;
  severity: Severity;
  detail: string;
}

export function severityFor(points: number): Severity {
  if (points >= 25) return "critical";
  if (points >= 15) return "high";
  if (points >= 8) return "medium";
  return "low";
}

/** Capabilities whose rules overlap: score them by the maximum, not the sum. */
const GROUP_CODE_ON_EVERY_SITE = "code_on_every_site";

// Transparent points table. Exposed as RULES for the methodology page (GET /api/rules).
export const RULES: Rule[] = [
  { code: "broad_hosts", group: GROUP_CODE_ON_EVERY_SITE, title: "Broad host access", points: 30, severity: severityFor(30), detail: "Host permissions cover every site (<all_urls>, *://*/*, http(s)://*/*, or any scheme with a bare path)." },
  { code: "debugger", group: "debugger", title: "Debugger access", points: 30, severity: severityFor(30), detail: "The debugger permission can attach to any page and step through its code." },
  { code: "native_messaging", group: "native_messaging", title: "Native messaging", points: 20, severity: severityFor(20), detail: "Talks to a native application outside the browser." },
  { code: "user_scripts", group: "user_scripts", title: "User scripts", points: 20, severity: severityFor(20), detail: "Injects scripts into arbitrary pages (Manifest V3)." },
  { code: "web_request_blocking", group: "web_request_blocking", title: "Blocking web requests", points: 20, severity: severityFor(20), detail: "webRequest with webRequestBlocking can rewrite or drop network requests." },
  { code: "declarative_net_request", group: "declarative_net_request", title: "Declarative net request", points: 8, severity: severityFor(8), detail: "declarativeNetRequest rules can rewrite network requests." },
  { code: "cookies", group: "cookies", title: "Cookies", points: 15, severity: severityFor(15), detail: "Reads and sets browser cookies." },
  { code: "history", group: "history", title: "Browsing history", points: 12, severity: severityFor(12), detail: "Reads and clears browsing history." },
  { code: "management", group: "management", title: "Extension management", points: 15, severity: severityFor(15), detail: "Manages other installed extensions." },
  { code: "proxy", group: "proxy", title: "Proxy control", points: 15, severity: severityFor(15), detail: "Controls the browser network proxy." },
  { code: "privacy", group: "privacy", title: "Privacy settings", points: 12, severity: severityFor(12), detail: "Changes privacy-related browser settings." },
  { code: "tabs", group: "tabs", title: "Tabs", points: 6, severity: severityFor(6), detail: "Reads tab URLs and metadata." },
  { code: "scripting", group: GROUP_CODE_ON_EVERY_SITE, title: "Script injection", points: 8, severity: severityFor(8), detail: "The scripting API injects code; 25 when combined with broad host access." },
  { code: "clipboard_read", group: "clipboard_read", title: "Clipboard read", points: 10, severity: severityFor(10), detail: "Reads the system clipboard." },
  { code: "screen_capture", group: "screen_capture", title: "Screen capture", points: 12, severity: severityFor(12), detail: "desktopCapture or tabCapture records the screen or tabs." },
  { code: "downloads", group: "downloads", title: "Downloads", points: 6, severity: severityFor(6), detail: "Downloads files to disk." },
  { code: "geolocation", group: "geolocation", title: "Geolocation", points: 6, severity: severityFor(6), detail: "Reads the device location." },
  { code: "mv2", group: "mv2", title: "Manifest V2", points: 10, severity: severityFor(10), detail: "Manifest version 2 is deprecated by Google." },
  { code: "content_scripts_all_sites", group: GROUP_CODE_ON_EVERY_SITE, title: "Content scripts on all sites", points: 20, severity: severityFor(20), detail: "Content scripts are injected into every site." },
  { code: "externally_connectable_all", group: "externally_connectable", title: "Externally connectable everywhere", points: 15, severity: severityFor(15), detail: "Any website can send messages to the extension." },
  { code: "csp_unsafe", group: "csp", title: "Unsafe content security policy", points: 20, severity: severityFor(20), detail: "CSP allows 'unsafe-eval' or remote script hosts." },
  { code: "update_url_external", group: "update_url", title: "External update URL", points: 15, severity: severityFor(15), detail: "Updates come from a host outside Google." },
];

const RULE_MAP: Map<string, Rule> = new Map(RULES.map((r) => [r.code, r]));

const PERMISSION_POINTS: Record<string, number> = {
  debugger: 30,
  nativeMessaging: 20,
  userScripts: 20,
  webRequest: 20,
  webRequestBlocking: 20,
  declarativeNetRequest: 8,
  declarativeNetRequestWithHostAccess: 8,
  cookies: 15,
  history: 12,
  management: 15,
  proxy: 15,
  privacy: 12,
  tabs: 6,
  scripting: 8,
  clipboardRead: 10,
  desktopCapture: 12,
  tabCapture: 12,
  downloads: 6,
  geolocation: 6,
};

/** Chrome ignores the path of a host permission, so any scheme with a bare path grants every site. */
export function isBroad(pattern: string): boolean {
  return pattern === "<all_urls>" || /^(\*|https?|wss?|file):\/\/\*\//.test(pattern);
}

/** True when the CSP allows 'unsafe-eval' (not 'wasm-unsafe-eval') or remote script hosts. */
export function cspUnsafe(csp: string | null): boolean {
  if (!csp) return false;
  const lower = csp.toLowerCase();
  if (/(^|[\s;])'unsafe-eval'/.test(lower)) return true;
  const script = lower.match(/script-src[^;]*/);
  if (script) return /https?:\/\//.test(script[0] ?? "");
  const fallback = lower.match(/default-src[^;]*/);
  return fallback !== null && /https?:\/\//.test(fallback[0] ?? "");
}

/** True when the update URL is hosted by Google (a host under google.com or googleusercontent.com). */
export function isGoogleHost(url: string): boolean {
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch { return false; }
  return host === "google.com" || host.endsWith(".google.com") || host === "googleusercontent.com" || host.endsWith(".googleusercontent.com");
}

export function gradeFor(score: number): Assessment["grade"] {
  if (score >= 80) return "F";
  if (score >= 60) return "D";
  if (score >= 40) return "C";
  if (score >= 20) return "B";
  return "A";
}

export function permissionSeverity(permission: string, manifest?: Manifest): Severity {
  if (permission === "scripting") {
    const broad = manifest?.hostPermissions.some(isBroad) ?? false;
    return severityFor(broad ? 25 : 8);
  }
  if (permission === "webRequest" || permission === "webRequestBlocking") {
    const other = permission === "webRequest" ? "webRequestBlocking" : "webRequest";
    const paired = manifest?.permissions.includes(other) ?? false;
    return severityFor(paired ? 20 : 0);
  }
  return severityFor(PERMISSION_POINTS[permission] ?? 0);
}

function summarize(findings: Finding[]): string {
  const scored = findings.filter((f) => f.points > 0);
  const [first, second] = scored;
  if (!first) return "No scored permissions.";
  return second ? `Highest access: ${first.title} and ${second.title}.` : `Highest access: ${first.title}.`;
}

interface Scored {
  code: string;
  group: string;
  title: string;
  detail: string;
  points: number;
}

export function assess(m: Manifest): Assessment {
  const items: Scored[] = [];
  const broad = m.hostPermissions.some(isBroad);
  const rule = (code: string, points?: number): Scored => {
    const r = RULE_MAP.get(code)!;
    return { code, group: r.group, title: r.title, detail: r.detail, points: points ?? r.points };
  };

  if (broad) items.push(rule("broad_hosts"));
  if (m.permissions.includes("debugger")) items.push(rule("debugger"));
  if (m.permissions.includes("nativeMessaging")) items.push(rule("native_messaging"));
  if (m.permissions.includes("userScripts")) items.push(rule("user_scripts"));
  if (m.permissions.includes("webRequest") && m.permissions.includes("webRequestBlocking")) items.push(rule("web_request_blocking"));
  if (m.permissions.includes("declarativeNetRequest") || m.permissions.includes("declarativeNetRequestWithHostAccess")) items.push(rule("declarative_net_request"));
  if (m.permissions.includes("cookies")) items.push(rule("cookies"));
  if (m.permissions.includes("history")) items.push(rule("history"));
  if (m.permissions.includes("management")) items.push(rule("management"));
  if (m.permissions.includes("proxy")) items.push(rule("proxy"));
  if (m.permissions.includes("privacy")) items.push(rule("privacy"));
  if (m.permissions.includes("tabs")) items.push(rule("tabs"));
  if (m.permissions.includes("scripting")) items.push(rule("scripting", broad ? 25 : 8));
  if (m.permissions.includes("clipboardRead")) items.push(rule("clipboard_read"));
  if (m.permissions.includes("desktopCapture") || m.permissions.includes("tabCapture")) items.push(rule("screen_capture"));
  if (m.permissions.includes("downloads")) items.push(rule("downloads"));
  if (m.permissions.includes("geolocation")) items.push(rule("geolocation"));
  if (m.manifestVersion === 2) items.push(rule("mv2"));
  if (m.contentScriptMatches.some(isBroad)) items.push(rule("content_scripts_all_sites"));
  if (m.externallyConnectable.some(isBroad)) items.push(rule("externally_connectable_all"));
  if (cspUnsafe(m.csp)) items.push(rule("csp_unsafe"));
  if (m.updateUrl && !isGoogleHost(m.updateUrl)) items.push(rule("update_url_external"));

  for (const p of m.optionalPermissions) {
    items.push({ code: "optional", group: "optional", title: `Can request later: ${p}`, detail: "Requestable at runtime; not granted on install.", points: 0 });
  }

  items.sort((a, b) => b.points - a.points || a.code.localeCompare(b.code));

  const groupMax = new Map<string, number>();
  for (const it of items) groupMax.set(it.group, Math.max(groupMax.get(it.group) ?? 0, it.points));
  const raw = [...groupMax.values()].reduce((sum, p) => sum + p, 0);
  const score = Math.min(100, raw);

  const findings: Finding[] = items.map((it) => ({ code: it.code, title: it.title, detail: it.detail, points: it.points, severity: severityFor(it.points) }));
  return { score, grade: gradeFor(score), findings, summary: summarize(findings) };
}
