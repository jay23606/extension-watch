import test from "node:test";
import assert from "node:assert/strict";
import { alertable, alertText, sendAlert, webhookProblem } from "../src/alert.js";
import type { LoggedChange, Watchlist } from "../src/store.js";

const ch = (kind: string, severity: LoggedChange["severity"], value = ""): LoggedChange => ({ kind, severity, value, id: "a".repeat(32), at: "2026-10-18T00:00:00Z" });

test("only https public webhooks are accepted", () => {
  assert.equal(webhookProblem("https://hooks.slack.com/services/T/B/x"), null);
  assert.equal(webhookProblem("https://ntfy.sh/my-topic"), null);
  assert.match(String(webhookProblem("http://hooks.slack.com/x")), /https/);
  assert.match(String(webhookProblem("https://localhost/x")), /public/);
  assert.match(String(webhookProblem("https://192.168.1.4/x")), /public/);
  assert.match(String(webhookProblem("not a url")), /valid/);
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

test("Slack gets JSON, ntfy gets plain text, redirects are not followed", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: RequestInit) => { calls.push({ url, init }); return new Response("ok"); }) as typeof fetch;
  try {
    const wl = { name: "t", ids: [], snapshots: {}, changes: [], createdAt: "", lastCheck: "", webhook: "https://hooks.slack.com/services/x" } as Watchlist;
    await sendAlert(wl, [ch("host_added", "critical", "<all_urls>")], "https://x/w/t");
    wl.webhook = "https://ntfy.sh/topic";
    await sendAlert(wl, [ch("host_added", "critical", "<all_urls>")], "https://x/w/t");
  } finally { globalThis.fetch = real; }
  assert.equal(JSON.parse(String(calls[0]?.init.body)).text.includes("Site access added"), true);
  assert.equal(calls[0]?.init.redirect, "manual");
  assert.equal(typeof calls[1]?.init.body, "string");
  assert.ok(!String(calls[1]?.init.body).startsWith("{"));
});
