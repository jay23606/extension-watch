import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, RULES, gradeFor, severityFor } from "../src/risk";
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

const GOOGLE_TRANSLATE = manifest({
  id: "aapbdbdomjkkjkaonfhkkikfgjllcleb",
  name: "Google Translate",
  version: "3.0.1",
  permissions: ["activeTab", "contextMenus", "storage", "offscreen", "scripting"],
  hostPermissions: ["<all_urls>"],
});

test("empty manifest scores 0 and grades A with no findings", () => {
  const a = assess(manifest());
  assert.equal(a.score, 0);
  assert.equal(a.grade, "A");
  assert.equal(a.findings.length, 0);
  assert.equal(a.summary, "No notable risk permissions.");
});

test("debugger is 30 points and critical", () => {
  const a = assess(manifest({ permissions: ["debugger"] }));
  assert.equal(a.score, 30);
  assert.equal(a.grade, "B");
  assert.equal(a.findings.length, 1);
  assert.equal(a.findings[0]!.code, "debugger");
  assert.equal(a.findings[0]!.severity, "critical");
  assert.equal(a.findings[0]!.points, 30);
});

test("broad host access is 30 points and critical", () => {
  const a = assess(manifest({ hostPermissions: ["*://*/*"] }));
  assert.equal(a.score, 30);
  assert.equal(a.findings[0]!.code, "broad_hosts");
  assert.equal(a.findings[0]!.severity, "critical");
});

test("Google Translate manifest scores 55, grade C", () => {
  const a = assess(GOOGLE_TRANSLATE);
  assert.equal(a.score, 55);
  assert.equal(a.grade, "C");
  assert.equal(a.findings.length, 2);
  assert.equal(a.findings[0]!.code, "broad_hosts");
  assert.equal(a.findings[1]!.code, "scripting");
  assert.equal(a.findings[1]!.points, 25);
  assert.equal(a.summary, "Highest risk: Broad host access and Script injection.");
});

test("scripting without broad hosts is 8 points medium", () => {
  const a = assess(manifest({ permissions: ["scripting"] }));
  assert.equal(a.findings[0]!.points, 8);
  assert.equal(a.findings[0]!.severity, "medium");
  assert.equal(a.score, 8);
});

test("webRequest plus webRequestBlocking is 20 points high", () => {
  const a = assess(manifest({ permissions: ["webRequest", "webRequestBlocking"] }));
  assert.equal(a.findings.length, 1);
  assert.equal(a.findings[0]!.code, "web_request_blocking");
  assert.equal(a.findings[0]!.points, 20);
  assert.equal(a.findings[0]!.severity, "high");
});

test("webRequest alone is not scored", () => {
  const a = assess(manifest({ permissions: ["webRequest"] }));
  assert.equal(a.findings.length, 0);
});

test("declarativeNetRequest is 8 points medium", () => {
  const a = assess(manifest({ permissions: ["declarativeNetRequest"] }));
  assert.equal(a.findings[0]!.code, "declarative_net_request");
  assert.equal(a.findings[0]!.points, 8);
  assert.equal(a.findings[0]!.severity, "medium");
});

test("cookies, management, proxy, privacy, history are scored", () => {
  const a = assess(manifest({ permissions: ["cookies", "management", "proxy", "privacy", "history"] }));
  assert.equal(a.score, 69);
  assert.equal(a.grade, "D");
  const codes = a.findings.map((f) => f.code).sort();
  assert.deepEqual(codes, ["cookies", "history", "management", "privacy", "proxy"]);
});

test("manifest version 2 is 10 points medium", () => {
  const a = assess(manifest({ manifestVersion: 2 }));
  assert.equal(a.score, 10);
  assert.equal(a.findings[0]!.code, "mv2");
  assert.equal(a.findings[0]!.severity, "medium");
  assert.equal(a.grade, "A");
});

test("content scripts on all sites is 20 points high", () => {
  const a = assess(manifest({ contentScriptMatches: ["<all_urls>"] }));
  assert.equal(a.findings[0]!.code, "content_scripts_all_sites");
  assert.equal(a.findings[0]!.points, 20);
  assert.equal(a.findings[0]!.severity, "high");
});

test("externally connectable everywhere is 15 points high", () => {
  const a = assess(manifest({ externallyConnectable: ["*://*/*"] }));
  assert.equal(a.findings[0]!.code, "externally_connectable_all");
  assert.equal(a.findings[0]!.points, 15);
  assert.equal(a.findings[0]!.severity, "high");
});

test("CSP with unsafe-eval is 20 points high", () => {
  const a = assess(manifest({ csp: "script-src 'self' 'unsafe-eval'; object-src 'self'" }));
  assert.equal(a.findings[0]!.code, "csp_unsafe");
  assert.equal(a.findings[0]!.points, 20);
});

test("CSP with remote script host is 20 points high", () => {
  const a = assess(manifest({ csp: "script-src 'self' https://cdn.example.com" }));
  assert.equal(a.findings[0]!.code, "csp_unsafe");
});

test("safe CSP is not flagged", () => {
  const a = assess(manifest({ csp: "script-src 'self'; object-src 'self'" }));
  assert.equal(a.findings.length, 0);
});

test("update URL outside Google is 15 points high", () => {
  const a = assess(manifest({ updateUrl: "https://updates.evil.example/ext.xml" }));
  assert.equal(a.findings[0]!.code, "update_url_external");
  assert.equal(a.findings[0]!.points, 15);
  assert.equal(a.findings[0]!.severity, "high");
});

test("Google update URL is not flagged", () => {
  const a = assess(manifest({ updateUrl: "https://clients2.google.com/service/update2/crx" }));
  assert.equal(a.findings.length, 0);
});

test("optional permissions do not affect the score", () => {
  const a = assess(manifest({ optionalPermissions: ["debugger", "cookies"] }));
  assert.equal(a.score, 0);
  assert.equal(a.findings.length, 0);
});

test("low severity permissions: tabs, downloads, geolocation", () => {
  const a = assess(manifest({ permissions: ["tabs", "downloads", "geolocation"] }));
  assert.equal(a.score, 18);
  assert.equal(a.grade, "A");
  for (const f of a.findings) assert.equal(f.severity, "low");
});

test("screen capture via desktopCapture or tabCapture", () => {
  const byDesktop = assess(manifest({ permissions: ["desktopCapture"] }));
  assert.equal(byDesktop.findings[0]!.code, "screen_capture");
  assert.equal(byDesktop.findings[0]!.points, 12);
  const byTab = assess(manifest({ permissions: ["tabCapture"] }));
  assert.equal(byTab.findings[0]!.code, "screen_capture");
});

test("clipboardRead is 10 points medium", () => {
  const a = assess(manifest({ permissions: ["clipboardRead"] }));
  assert.equal(a.findings[0]!.code, "clipboard_read");
  assert.equal(a.findings[0]!.points, 10);
  assert.equal(a.findings[0]!.severity, "medium");
});

test("score is capped at 100 with grade F", () => {
  const a = assess(
    manifest({
      manifestVersion: 2,
      permissions: [
        "debugger", "nativeMessaging", "userScripts", "webRequest", "webRequestBlocking",
        "declarativeNetRequest", "cookies", "history", "management", "proxy", "privacy",
        "tabs", "scripting", "clipboardRead", "desktopCapture", "downloads", "geolocation",
      ],
      hostPermissions: ["<all_urls>"],
      contentScriptMatches: ["*://*/*"],
      externallyConnectable: ["<all_urls>"],
      csp: "script-src 'unsafe-eval'",
      updateUrl: "https://updates.evil.example/ext.xml",
    }),
  );
  assert.equal(a.score, 100);
  assert.equal(a.grade, "F");
  assert.equal(a.findings.length, 22);
});

test("summary names the single top finding", () => {
  const a = assess(manifest({ permissions: ["debugger"] }));
  assert.equal(a.summary, "Highest risk: Debugger access.");
});

test("gradeFor boundaries are correct", () => {
  assert.equal(gradeFor(0), "A");
  assert.equal(gradeFor(19), "A");
  assert.equal(gradeFor(20), "B");
  assert.equal(gradeFor(39), "B");
  assert.equal(gradeFor(40), "C");
  assert.equal(gradeFor(59), "C");
  assert.equal(gradeFor(60), "D");
  assert.equal(gradeFor(79), "D");
  assert.equal(gradeFor(80), "F");
  assert.equal(gradeFor(100), "F");
});

test("severityFor boundaries are correct", () => {
  assert.equal(severityFor(0), "low");
  assert.equal(severityFor(7), "low");
  assert.equal(severityFor(8), "medium");
  assert.equal(severityFor(14), "medium");
  assert.equal(severityFor(15), "high");
  assert.equal(severityFor(24), "high");
  assert.equal(severityFor(25), "critical");
});

test("RULES has unique codes and positive points", () => {
  const codes = new Set(RULES.map((r) => r.code));
  assert.equal(codes.size, RULES.length);
  for (const r of RULES) assert.ok(r.points > 0);
});
