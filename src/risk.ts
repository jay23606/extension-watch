import type { Assessment, Finding, Manifest, Severity } from "./types";

export interface Rule {
  code: string;
  title: string;
  points: number;
  detail: string;
}

// Transparent points table. Exposed as RULES for the methodology page (GET /api/rules).
export const RULES: Rule[] = [
  { code: "broad_hosts", title: "Broad host access", points: 30, detail: "Host permissions include <all_urls>, *://*/*, http://*/* or https://*/*." },
  { code: "debugger", title: "Debugger access", points: 30, detail: "The debugger permission can attach to any page and step through its code." },
  { code: "native_messaging", title: "Native messaging", points: 20, detail: "Talks to a native application outside the browser." },
  { code: "user_scripts", title: "User scripts", points: 20, detail: "Injects scripts into arbitrary pages (Manifest V3)." },
  { code: "web_request_blocking", title: "Blocking web requests", points: 20, detail: "webRequest with webRequestBlocking can rewrite or drop network requests." },
  { code: "declarative_net_request", title: "Declarative net request", points: 8, detail: "declarativeNetRequest rules can rewrite network requests." },
  { code: "cookies", title: "Cookies", points: 15, detail: "Reads and sets browser cookies." },
  { code: "history", title: "Browsing history", points: 12, detail: "Reads and clears browsing history." },
  { code: "management", title: "Extension management", points: 15, detail: "Manages other installed extensions." },
  { code: "proxy", title: "Proxy control", points: 15, detail: "Controls the browser network proxy." },
  { code: "privacy", title: "Privacy settings", points: 12, detail: "Changes privacy-related browser settings." },
  { code: "tabs", title: "Tabs", points: 6, detail: "Reads tab URLs and metadata." },
  { code: "scripting", title: "Script injection", points: 8, detail: "The scripting API injects code; 25 when combined with broad host access." },
  { code: "clipboard_read", title: "Clipboard read", points: 10, detail: "Reads the system clipboard." },
  { code: "screen_capture", title: "Screen capture", points: 12, detail: "desktopCapture or tabCapture records the screen or tabs." },
  { code: "downloads", title: "Downloads", points: 6, detail: "Downloads files to disk." },
  { code: "geolocation", title: "Geolocation", points: 6, detail: "Reads the device location." },
  { code: "mv2", title: "Manifest V2", points: 10, detail: "Manifest version 2 is deprecated by Google." },
  { code: "content_scripts_all_sites", title: "Content scripts on all sites", points: 20, detail: "Content scripts are injected into every site." },
  { code: "externally_connectable_all", title: "Externally connectable everywhere", points: 15, detail: "Any website can send messages to the extension." },
  { code: "csp_unsafe", title: "Unsafe content security policy", points: 20, detail: "CSP allows 'unsafe-eval' or remote script hosts." },
  { code: "update_url_external", title: "External update URL", points: 15, detail: "Updates come from a host outside Google." },
];

const BROAD_HOSTS = new Set(["<all_urls>", "*://*/*", "http://*/*", "https://*/*"]);

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

export function severityFor(points: number): Severity {
  if (points >= 25) return "critical";
  if (points >= 15) return "high";
  if (points >= 8) return "medium";
  return "low";
}

export function permissionSeverity(permission: string): Severity {
  return severityFor(PERMISSION_POINTS[permission] ?? 0);
}

export function gradeFor(score: number): Assessment["grade"] {
  if (score >= 80) return "F";
  if (score >= 60) return "D";
  if (score >= 40) return "C";
  if (score >= 20) return "B";
  return "A";
}

function has(list: string[], value: string): boolean {
  return list.includes(value);
}

function hasBroad(patterns: string[]): boolean {
  return patterns.some((p) => BROAD_HOSTS.has(p));
}

function makeFinding(code: string, title: string, detail: string, points: number): Finding {
  return { code, title, detail, points, severity: severityFor(points) };
}

function isGoogleHost(url: string): boolean {
  return url.includes("google.com") || url.includes("googleusercontent.com");
}

function cspUnsafe(csp: string | null): boolean {
  if (!csp) return false;
  const lower = csp.toLowerCase();
  if (lower.includes("unsafe-eval")) return true;
  const script = lower.match(/script-src[^;]*/);
  return script !== null && /https?:\/\//.test(script[0] ?? "");
}

function summarize(findings: Finding[]): string {
  const [first, second] = findings;
  if (!first) return "No notable risk permissions.";
  return second ? `Highest risk: ${first.title} and ${second.title}.` : `Highest risk: ${first.title}.`;
}

export function assess(m: Manifest): Assessment {
  const broad = hasBroad(m.hostPermissions);
  const findings: Finding[] = [];

  if (broad) findings.push(makeFinding("broad_hosts", "Broad host access", "Host permissions include <all_urls> or *://*/*.", 30));
  if (has(m.permissions, "debugger")) findings.push(makeFinding("debugger", "Debugger access", "Can attach a debugger to any page.", 30));
  if (has(m.permissions, "nativeMessaging")) findings.push(makeFinding("native_messaging", "Native messaging", "Can message a native application.", 20));
  if (has(m.permissions, "userScripts")) findings.push(makeFinding("user_scripts", "User scripts", "Can inject scripts into arbitrary pages.", 20));
  if (has(m.permissions, "webRequest") && has(m.permissions, "webRequestBlocking")) {
    findings.push(makeFinding("web_request_blocking", "Blocking web requests", "webRequest with webRequestBlocking can rewrite or drop requests.", 20));
  }
  if (has(m.permissions, "declarativeNetRequest") || has(m.permissions, "declarativeNetRequestWithHostAccess")) {
    findings.push(makeFinding("declarative_net_request", "Declarative net request", "declarativeNetRequest rules can rewrite requests.", 8));
  }
  if (has(m.permissions, "cookies")) findings.push(makeFinding("cookies", "Cookies", "Reads and sets browser cookies.", 15));
  if (has(m.permissions, "history")) findings.push(makeFinding("history", "Browsing history", "Reads and clears browsing history.", 12));
  if (has(m.permissions, "management")) findings.push(makeFinding("management", "Extension management", "Manages other installed extensions.", 15));
  if (has(m.permissions, "proxy")) findings.push(makeFinding("proxy", "Proxy control", "Controls the network proxy.", 15));
  if (has(m.permissions, "privacy")) findings.push(makeFinding("privacy", "Privacy settings", "Changes privacy-related browser settings.", 12));
  if (has(m.permissions, "tabs")) findings.push(makeFinding("tabs", "Tabs", "Reads tab URLs and metadata.", 6));
  if (has(m.permissions, "scripting")) findings.push(makeFinding("scripting", "Script injection", "The scripting API can inject code into pages.", broad ? 25 : 8));
  if (has(m.permissions, "clipboardRead")) findings.push(makeFinding("clipboard_read", "Clipboard read", "Reads the system clipboard.", 10));
  if (has(m.permissions, "desktopCapture") || has(m.permissions, "tabCapture")) {
    findings.push(makeFinding("screen_capture", "Screen capture", "desktopCapture or tabCapture records the screen.", 12));
  }
  if (has(m.permissions, "downloads")) findings.push(makeFinding("downloads", "Downloads", "Downloads files to disk.", 6));
  if (has(m.permissions, "geolocation")) findings.push(makeFinding("geolocation", "Geolocation", "Reads the device location.", 6));
  if (m.manifestVersion === 2) findings.push(makeFinding("mv2", "Manifest V2", "Manifest version 2 is deprecated.", 10));
  if (hasBroad(m.contentScriptMatches)) findings.push(makeFinding("content_scripts_all_sites", "Content scripts on all sites", "Content scripts run on every site.", 20));
  if (hasBroad(m.externallyConnectable)) findings.push(makeFinding("externally_connectable_all", "Externally connectable everywhere", "Any website can message the extension.", 15));
  if (cspUnsafe(m.csp)) findings.push(makeFinding("csp_unsafe", "Unsafe content security policy", "CSP allows 'unsafe-eval' or remote script hosts.", 20));
  if (m.updateUrl && !isGoogleHost(m.updateUrl)) findings.push(makeFinding("update_url_external", "External update URL", "Updates come from outside Google.", 15));

  findings.sort((a, b) => b.points - a.points || a.code.localeCompare(b.code));

  const raw = findings.reduce((sum, f) => sum + f.points, 0);
  const score = Math.min(100, raw);

  return { score, grade: gradeFor(score), findings, summary: summarize(findings) };
}
