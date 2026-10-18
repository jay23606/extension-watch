import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { assess, isBroad, isSensitive, RULES, SENSITIVE_DOMAINS } from "../src/risk";
import { isPublicSuffix } from "../src/public_suffixes";
import { diff } from "../src/diff";
import { alertable } from "../src/alert";
import type { Manifest } from "../src/types";

function manifest(overrides: Partial<Manifest> = {}): Manifest {
  return {
    id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    name: "Test Extension",
    version: "1.0.0",
    manifestVersion: 3,
    permissions: [],
    optionalPermissions: [],
    hostPermissions: [],
    contentScriptMatches: [],
    externallyConnectable: [],
    hasBackground: false,
    csp: null,
    updateUrl: null,
    description: "",
    ...overrides,
  };
}

const GOLDEN_PERMISSIONS: Array<[string, number, string, string]> = [
  ["webNavigation", 12, "medium", "web_navigation"],
  ["topSites", 8, "medium", "top_sites"],
  ["bookmarks", 10, "medium", "bookmarks"],
  ["identity.email", 10, "medium", "identity_email"],
  ["contentSettings", 15, "high", "content_settings"],
  ["browsingData", 10, "medium", "browsing_data"],
  ["pageCapture", 10, "medium", "page_capture"],
  ["sessions", 12, "medium", "sessions"],
  ["history", 12, "medium", "history"],
  ["tabCapture", 12, "medium", "screen_capture"],
  ["desktopCapture", 12, "medium", "screen_capture"],
  ["downloads", 6, "low", "downloads"],
  ["management", 15, "high", "management"],
  ["privacy", 12, "medium", "privacy"],
  ["proxy", 15, "high", "proxy"],
  ["geolocation", 6, "low", "geolocation"],
  ["clipboardRead", 10, "medium", "clipboard_read"],
  ["nativeMessaging", 20, "high", "native_messaging"],
  ["declarativeNetRequestFeedback", 4, "low", "declarative_net_request_feedback"],
];

for (const [permission, points, severity, code] of GOLDEN_PERMISSIONS) {
  test(`install warning permission ${permission} is ${points} points and ${severity}`, () => {
    const a = assess(manifest({ permissions: [permission] }));
    assert.equal(a.score, points);
    assert.equal(a.findings.length, 1);
    assert.equal(a.findings[0]!.code, code);
    assert.equal(a.findings[0]!.points, points);
    assert.equal(a.findings[0]!.severity, severity);
  });
}

test("golden update adding webNavigation, topSites and identity.email scores 30 and alerts", () => {
  const before = manifest({ permissions: ["storage"] });
  const after = manifest({ permissions: ["storage", "webNavigation", "topSites", "identity.email"], version: "2" });
  const a = assess(after);
  assert.equal(a.score, 30);
  assert.equal(a.grade, "B");
  assert.deepEqual(a.findings.map((f) => f.code).sort(), ["identity_email", "top_sites", "web_navigation"]);
  const changes = diff(before, after);
  const logged = changes.map((c) => ({ ...c, id: after.id, at: "2026-10-18T00:00:00Z" }));
  const alerts = alertable(logged);
  assert.ok(alerts.length >= 1);
  assert.deepEqual(alerts.filter((c) => c.kind === "permission_added").map((c) => c.value).sort(),
    ["identity.email", "topSites", "webNavigation"]);
  assert.ok(alerts.every((c) => ["medium", "high", "critical"].includes(c.severity)));
});

test("every new rule is served with a title and detail at /api/rules", async () => {
  const mod = await import("../src/worker.js");
  const res = await mod.default.fetch(new Request("http://x/api/rules"), {} as never);
  assert.equal(res.status, 200);
  const body = await res.json() as { rules: Array<{ code: string; detail: string }> };
  for (const [, , , code] of GOLDEN_PERMISSIONS) {
    const rule = body.rules.find((r) => r.code === code);
    assert.ok(rule, code);
    assert.ok(rule.detail.length > 0, code);
  }
  const broad = body.rules.find((r) => r.code === "broad_hosts");
  assert.match(broad!.detail, /public suffix/);
  const sensitive = body.rules.find((r) => r.code === "sensitive_hosts");
  assert.match(sensitive!.detail, /mail/);
  assert.equal(body.rules.filter((r) => r.code === "sensitive_hosts").length, 1);
});

test("public suffix data keeps its source and date header", () => {
  const source = readFileSync(new URL("../src/public_suffixes.ts", import.meta.url), "utf8");
  assert.match(source, /publicsuffix\.org\/list\/public_suffix_list\.dat/);
  assert.match(source, /2026-10-18/);
});

test("public suffix check replaces the short label plus 2-letter guess", () => {
  assert.equal(isPublicSuffix("co.uk"), true);
  assert.equal(isPublicSuffix("com"), true);
  assert.equal(isPublicSuffix("bit.ly"), false);
  assert.equal(isPublicSuffix("x.ai"), false);
  assert.equal(isPublicSuffix("t.co"), false);
  for (const p of ["*://*.co.uk/*", "https://*.com/*", "*://*.de/*", "*://*.uk/*"]) assert.equal(isBroad(p), true, p);
  for (const p of ["*://*.bit.ly/*", "*://*.x.ai/*", "*://*.t.co/*", "*://*.abc.de/*", "https://*.google.com/*"]) assert.equal(isBroad(p), false, p);
});

const SENSITIVE_EXAMPLES = [
  "mail.google.com", "outlook.office.com", "login.microsoftonline.com", "accounts.google.com", "*.okta.com",
  "*.salesforce.com", "console.aws.amazon.com", "portal.azure.com", "console.cloud.google.com", "github.com",
];

for (const example of SENSITIVE_EXAMPLES) {
  test(`sensitive host ${example} scores high`, () => {
    const pattern = example.startsWith("*.") ? `*://${example}/*` : `https://${example}/*`;
    const a = assess(manifest({ hostPermissions: [pattern] }));
    assert.equal(a.score, 15);
    assert.equal(a.grade, "A");
    assert.equal(a.findings.length, 1);
    assert.equal(a.findings[0]!.code, "sensitive_hosts");
    assert.equal(a.findings[0]!.severity, "high");
    assert.equal(isSensitive(pattern), true);
  });
}

test("ordinary hosts are not sensitive and the sensitive list is exported for policies", () => {
  for (const pattern of ["https://example.com/*", "https://api.example.org/*", "https://notokta.example/*"]) {
    assert.equal(isSensitive(pattern), false, pattern);
    assert.equal(assess(manifest({ hostPermissions: [pattern] })).findings.length, 0, pattern);
  }
  assert.ok(SENSITIVE_DOMAINS.includes("okta.com"));
  assert.ok(SENSITIVE_DOMAINS.includes("github.com"));
});

test("rule table keeps unique codes and a non-empty detail for every rule", () => {
  const codes = new Set(RULES.map((r) => r.code));
  assert.equal(codes.size, RULES.length);
  for (const rule of RULES) assert.ok(rule.detail.length > 0, rule.code);
});

// R6: sensitive host check covers content scripts and optional permissions, and the new domains.
test("a content script match on a sensitive site scores as sensitive site access", () => {
  const a = assess(manifest({ contentScriptMatches: ["https://mail.google.com/*"] }));
  assert.equal(a.score, 15);
  assert.equal(a.findings.length, 1);
  assert.equal(a.findings[0]!.code, "sensitive_hosts");
  assert.match(a.findings[0]!.title, /content script/);
  assert.equal(a.findings[0]!.points, 15);
});

test("a sensitive host and a sensitive content script still count once at 15", () => {
  const a = assess(manifest({ hostPermissions: ["https://mail.google.com/*"], contentScriptMatches: ["https://app.slack.com/*"] }));
  assert.equal(a.score, 15);
  assert.equal(a.findings.filter((f) => f.code === "sensitive_hosts").length, 2);
  assert.equal(a.grade, "A");
});

test("an optional permission on a sensitive site is labelled and worth 0 points", () => {
  const a = assess(manifest({ optionalPermissions: ["https://acme.sharepoint.com/*"] }));
  assert.equal(a.score, 0);
  assert.equal(a.grade, "A");
  assert.equal(a.findings.length, 1);
  assert.equal(a.findings[0]!.points, 0);
  assert.equal(a.findings[0]!.severity, "low");
  assert.equal(a.findings[0]!.title, "Can request later: Sensitive site access (https://acme.sharepoint.com/*)");
});

test("the new Microsoft 365, Slack, Workday, Atlassian and Google admin hosts are sensitive", () => {
  for (const host of ["outlook.office365.com", "app.slack.com", "admin.google.com", "sharepoint.com", "myworkday.com", "atlassian.net"]) {
    for (const pattern of [`https://${host}/*`, `*://*.${host}/*`]) {
      assert.equal(isSensitive(pattern), true, pattern);
    }
  }
  for (const pattern of ["https://acme.sharepoint.com/*", "https://acme.myworkday.com/*", "https://acme.atlassian.net/*", "https://tenant.sharepoint.com/*"])
    assert.equal(isSensitive(pattern), true, pattern);
});

test("a bare parent domain and a documentation subdomain are not sensitive", () => {
  for (const pattern of ["*://*.amazon.com/*", "https://amazon.com/*", "https://docs.github.com/*", "https://api.sub.github.com/*", "https://docs.google.com/*"])
    assert.equal(isSensitive(pattern), false, pattern);
  assert.equal(isSensitive("https://github.com/*"), true);
  assert.equal(assess(manifest({ hostPermissions: ["https://docs.github.com/*"] })).score, 0);
});

test("notifications, readingList, tabGroups and tts score low", () => {
  const expected: Array<[string, string]> = [["notifications", "notifications"], ["readingList", "reading_list"], ["tabGroups", "tab_groups"], ["tts", "text_to_speech"]];
  for (const [permission, code] of expected) {
    const a = assess(manifest({ permissions: [permission] }));
    assert.equal(a.findings.length, 1, permission);
    assert.equal(a.findings[0]!.code, code);
    assert.equal(a.findings[0]!.points, 2);
    assert.equal(a.findings[0]!.severity, "low");
    assert.equal(a.grade, "A");
  }
  assert.equal(assess(manifest({ permissions: ["notifications", "readingList", "tabGroups", "tts"] })).score, 8);
});
