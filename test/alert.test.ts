import test from "node:test";
import assert from "node:assert/strict";
import { alertable, alertText, maskWebhook, sendAlert, webhookProblem } from "../src/alert.js";
import type { LoggedChange, Watchlist } from "../src/store.js";

const ch = (kind: string, severity: LoggedChange["severity"], value = ""): LoggedChange => ({ kind, severity, value, id: "a".repeat(32), at: "2026-10-18T00:00:00Z" });

test("only public https host names are accepted as webhooks", () => {
  assert.equal(webhookProblem("https://hooks.slack.com/services/T/B/x"), null);
  assert.equal(webhookProblem("https://discord.com/api/webhooks/1/abc"), null);
  for (const bad of ["http://hooks.slack.com/x", "https://localhost/x", "https://192.168.1.4/x", "https://172.16.0.1/x", "https://0.0.0.0/x",
    "https://[::1]/x", "https://metadata.google.internal/x", "https://localhost./x", "https://lvh.me/x", "https://localtest.me/x", "https://a:b@example.com/x", "https://example.com:8443/x", "not a url"]) {
    assert.notEqual(webhookProblem(bad), null, bad);
  }
});

test("a saved webhook is shown back as its host only", () => {
  assert.equal(maskWebhook("https://hooks.slack.com/services/T0/B0/SECRET"), "https://hooks.slack.com/...");
  assert.equal(maskWebhook("https://hooks.example.com?token=SECRET"), "https://hooks.example.com/...");
  assert.equal(maskWebhook(null), null);
});

test("low-severity changes such as a new version do not alert", () => {
  assert.deepEqual(alertable([ch("version_changed", "low"), ch("host_added", "critical")]).map((c) => c.kind), ["host_added"]);
});

test("alert text names the extension and caps at 10 lines", () => {
  const many = Array.from({ length: 12 }, () => ch("permission_added", "high", "cookies"));
  const text = alertText("Design team", many, { ["a".repeat(32)]: "Calc" }, "https://x/w/t");
  assert.match(text, /12 changes in "Design team"/);
  assert.match(text, /HIGH: Calc: Permission added \(cookies\)/);
  assert.match(text, /and 2 more/);
});

test("unreadable alert text uses a readable label", () => {
  const text = alertText("Design team", [ch("unreadable", "high")], { ["a".repeat(32)]: "Calc" }, "https://x/w/t");
  assert.match(text, /HIGH: Calc: Package can no longer be read/);
  assert.doesNotMatch(text, /unreadable/);
});

test("alerts are JSON with text and content, and redirects are not followed", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: RequestInit) => { calls.push({ url, init }); return new Response("ok"); }) as typeof fetch;
  try {
    const wl = { name: "t", ids: [], snapshots: {}, changes: [], createdAt: "", lastCheck: "", webhook: "https://hooks.slack.com/services/x" } as Watchlist;
    await sendAlert(wl, [ch("host_added", "critical", "<all_urls>")], "https://x/w/t");
  } finally { globalThis.fetch = real; }
  const body = JSON.parse(String(calls[0]?.init.body));
  assert.ok(body.text.includes("Site access added"));
  assert.equal(body.content, body.text);
  assert.equal(calls[0]?.init.redirect, "manual");
});
