import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const app = readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../web/index.html", import.meta.url), "utf8");

test("the sample button fills the form with 8 real extension IDs", () => {
  assert.match(html, /id="sampleButton"/);
  assert.match(html, /Try a sample team list/);
  assert.match(app, /wireSample\(\)/);
  const block = /const SAMPLE_IDS = \[([\s\S]*?)\];/.exec(app)?.[1] ?? "";
  const ids = [...block.matchAll(/"([a-p]{32})"/g)].map((m) => m[1]!);
  assert.equal(ids.length, 8);
  assert.equal(new Set(ids).size, 8);
  assert.ok(ids.includes("aapbdbdomjkkjkaonfhkkikfgjllcleb"));
  assert.ok(ids.includes("gighmmpiobklfepjocnamgkkbiglidom"));
  assert.ok(!ids.includes("cjpalhdlnbpafiamejdnhcphjbkeiagm"));
  assert.match(app, /SAMPLE_IDS\.join\("\\n"\)/);
});

test("the watchlist page shows both CSV downloads and the admin policy download", () => {
  assert.match(html, /id="exportCsv"/);
  assert.match(html, /id="exportChanges"/);
  assert.match(html, /id="exportPolicy"/);
  assert.match(html, /id="policyThreshold"/);
  assert.match(app, /\/export\.csv/);
  assert.match(app, /\/changes\.csv/);
  assert.match(app, /\/policy\.json\?threshold=/);
  assert.match(app, /\$\("#policyTools"\)\.hidden = !admin/);
});

test("the policy note explains the Google Admin console paste step", () => {
  assert.match(html, /Google Admin console/);
  assert.match(html, /ExtensionSettings/);
  assert.match(html, /Paste the downloaded JSON/);
});

test("the page warns when the 50 cap drops IDs and when most IDs are missing", () => {
  assert.match(app, /The list holds 50 extensions/);
  assert.match(app, /ew-watch-warning/);
  assert.match(app, /Most IDs were not on the Chrome Web Store/);
  assert.match(app, /Most IDs in this list are not on the Chrome Web Store/);
  assert.match(html, /id="watchWarning"/);
});

// R6: policy mode selector, a preview of what is blocked, and the corrected deployment note.
test("the export tools offer both policy modes and a preview", () => {
  assert.match(html, /id="policyMode"/);
  assert.match(html, /value="threshold" selected/);
  assert.match(html, /value="default-deny"/);
  assert.match(html, /id="policyPreview"/);
  assert.match(app, /policyPreviewText/);
  assert.match(app, /\/policy\.json\?threshold=/);
  assert.match(app, /&mode=/);
});

test("both policy modes are described with what each one blocks", () => {
  assert.match(app, /blocks every extension that is not on this list/);
  assert.match(app, /leaves extensions that are not on the list installable/);
  assert.match(app, /kept off the debugger permission and off the sensitive sites/);
  assert.match(html, /Default deny blocks every extension that is not on the list/);
  assert.match(html, /keep every extension off the debugger permission and off the sensitive sites/);
});

test("the deployment note names the console, Group Policy, plist and Linux routes", () => {
  assert.match(html, /Custom Configurations/);
  assert.match(html, /Chrome Enterprise Core/);
  assert.match(html, /Chrome Group Policy/);
  assert.match(html, /configuration profile plist/);
  assert.match(html, /\/etc\/opt\/chrome\/policies\/managed\//);
  assert.doesNotMatch(html, /Additional Google services/);
});
