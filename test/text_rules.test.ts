import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { assess, RULES } from "../src/risk";
import type { Manifest } from "../src/types";

const html = readFileSync(new URL("../web/index.html", import.meta.url), "utf8");
const app = readFileSync(new URL("../web/app.js", import.meta.url), "utf8");

// A scheme URL such as https://... or a match pattern such as *://*/* counts as a URL or a code sample.
const URL_RE = /(?:\*|[a-z][a-z0-9+.-]*):\/\/[^\s"'<>()]*/gi;
const TIME_RE = /\b\d{1,2}:\d{2}(?::\d{2})?\b/g;
const STRING_RE = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g;
const ATTR_RE = /(?:placeholder|title|aria-label|alt|content)="([^"]*)"/gi;

const DASHES = ["\u2012", "\u2013", "\u2014", "\u2015"];

function scrub(text: string): string {
  return text.replace(URL_RE, " ").replace(TIME_RE, " ");
}

function decodeEscapes(text: string): string {
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

function decodeEntities(text: string): string {
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => String.fromCharCode(Number(dec)))
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"');
}

function excerpt(text: string, index: number): string {
  return text.slice(Math.max(0, index - 40), index + 40).replace(/\s+/g, " ");
}

function assertNoColons(text: string, where: string): void {
  for (const hit of scrub(text).matchAll(/:/g)) {
    assert.fail(where + " has a colon outside a URL or time, near " + excerpt(text, hit.index ?? 0));
  }
}

function assertNoDashes(text: string, where: string): void {
  for (const dash of DASHES) {
    const at = text.indexOf(dash);
    if (at >= 0) assert.fail(where + " has an en or em dash, near " + excerpt(text, at));
  }
}

function visibleHtml(): string {
  const text = html.replace(/<[^>]*>/g, " ");
  const attrs = [...html.matchAll(ATTR_RE)].map((m) => m[1] ?? "").join("\n");
  return decodeEntities(text + "\n" + attrs);
}

function visibleAppStrings(): string {
  const literals = [...app.matchAll(STRING_RE)].map((m) => m[0]);
  return decodeEscapes(literals.join("\n"));
}

function ruleStrings(): string[] {
  const out: string[] = [];
  for (const r of RULES) out.push(r.title, r.detail);
  return out;
}

function generatedStrings(): string[] {
  const base: Manifest = {
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
  };
  const a = assess({
    ...base,
    permissions: ["debugger", "scripting"],
    hostPermissions: ["<all_urls>"],
    optionalPermissions: ["cookies", "https://acme.sharepoint.com/*"],
  });
  const out = [a.summary];
  for (const f of a.findings) out.push(f.title, f.detail);
  return out;
}

test("index.html visible text has no colons outside URLs or times and no en or em dashes", () => {
  const text = visibleHtml();
  assertNoColons(text, "web/index.html");
  assertNoDashes(text, "web/index.html");
});

test("web/app.js visible string literals have no colons outside URLs or times and no en or em dashes", () => {
  const text = visibleAppStrings();
  assertNoColons(text, "web/app.js");
  assertNoDashes(text, "web/app.js");
});

test("the rule titles and details served at /api/rules are free of stray colons and em dashes", () => {
  for (const value of ruleStrings()) {
    assertNoColons(value, "src/risk.ts rule text");
    assertNoDashes(value, "src/risk.ts rule text");
  }
});

test("generated finding titles, details and the summary keep the same rules", () => {
  for (const value of generatedStrings()) {
    assertNoColons(value, "src/risk.ts generated text");
    assertNoDashes(value, "src/risk.ts generated text");
  }
});

test("visible text keeps at most one semicolon per 500 words", () => {
  const text = [visibleHtml(), visibleAppStrings(), ...ruleStrings()].join("\n");
  const semicolons = (text.match(/;/g) ?? []).length;
  const words = text.split(/\s+/).filter(Boolean).length;
  const allowed = Math.max(1, Math.ceil(words / 500));
  assert.ok(semicolons <= allowed, "found " + semicolons + " semicolons in " + words + " words, allowed " + allowed);
});
