"use strict";

const $ = (selector, root) => (root || document).querySelector(selector);
const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));

const GRADE_COLOR = { A: "green", B: "teal", C: "amber", D: "orange", F: "red" };
const GRADE_RANK = { A: 0, B: 1, C: 2, D: 3, F: 4 };
const SEVERITY_COLOR = { critical: "red", high: "orange", medium: "amber", low: "muted" };

// Real, popular Web Store extensions, used by the sample button.
const SAMPLE_IDS = [
  "aapbdbdomjkkjkaonfhkkikfgjllcleb",
  "gighmmpiobklfepjocnamgkkbiglidom",
  "nngceckbapebfimnlniiiahkandclblb",
  "aeblfdkhhhdcdjpifhhbdiojplfjncoa",
  "kbfnbcaeplbcioakkpcpgfkobkghlhen",
  "hdokiejnpimakedhajhdlcegeplioahd",
  "fmkadmapgofadopljbjfkapdkoienihi",
  "eimadpbcbfnmbkopoojfekhnkhdbieeh",
];

const CHANGE_LABEL = {
  permission_added: "Permission added",
  permission_removed: "Permission removed",
  host_added: "Host access added",
  host_removed: "Host access removed",
  mv_changed: "Manifest version changed",
  new_extension: "New extension",
  unreadable: "Package can no longer be read",
  removed_from_store: "Removed from store",
  content_script_added: "Runs on new sites",
  content_script_removed: "No longer runs on sites",
  optional_added: "Can now request",
  externally_connectable_added: "Accepts messages from",
  csp_changed: "Script policy loosened",
  update_url_changed: "Updates from outside the store",
  score_jump: "Access grade rose",
  version_changed: "New version",
};

let lastIds = [];
let rulesLoaded = false;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setStatus(node, message, kind) {
  node.textContent = message || "";
  node.className = "status" + (kind ? " status--" + kind : "");
  node.hidden = !message;
}

async function readErrorMessage(res) {
  const fallback = res.statusText || "Request failed (" + res.status + ")";
  try {
    const data = await res.json();
    if (data && typeof data.error === "string" && data.error) return data.error;
    return fallback;
  } catch {
    return fallback;
  }
}

async function apiJson(path, options) {
  let res;
  try {
    res = await fetch(path, options);
  } catch {
    throw new Error("Network error. Is the service reachable?");
  }
  if (!res.ok) throw new Error(await readErrorMessage(res));
  return res.json();
}

function normalizeId(input) {
  const value = String(input || "").trim();
  if (!value) return null;
  if (/^[a-p]{32}$/.test(value)) return value;
  const match = value.match(/[a-p]{32}/);
  return match ? match[0] : null;
}

function parseIds(text) {
  const ids = [];
  const seen = new Set();
  // Policy exports often put many IDs on one line, separated by commas or spaces.
  for (const match of String(text || "").matchAll(/[a-p]{32}/g)) {
    const id = match[0];
    if (!seen.has(id)) {
      seen.add(id);
      ids.push(id);
    }
  }
  return ids;
}

function extractResults(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.results)) return data.results;
  return [];
}

function topFinding(assessment) {
  const findings = assessment && Array.isArray(assessment.findings) ? assessment.findings : [];
  if (!findings.length) return null;
  let best = findings[0];
  for (const f of findings) if (f.points > best.points) best = f;
  return best;
}

function severityTag(severity) {
  const color = SEVERITY_COLOR[severity] || "muted";
  return el("span", "severity severity--" + color, severity);
}

function gradeBadge(grade) {
  const color = GRADE_COLOR[grade] || "muted";
  return el("span", "grade grade--" + color, grade);
}

function buildFindingItem(f) {
  const li = el("li", "finding");
  const top = el("div", "finding__top");
  top.appendChild(severityTag(f.severity));
  top.appendChild(el("span", "finding__title", f.title));
  top.appendChild(el("span", "finding__points", "+" + f.points));
  li.appendChild(top);
  if (f.detail) li.appendChild(el("p", "finding__detail", f.detail));
  return li;
}

function addChipGroup(wrap, label, values) {
  const group = el("div", "perms__group");
  group.appendChild(el("div", "perms__label", label));
  const chips = el("div", "chips");
  if (!values || !values.length) chips.appendChild(el("span", "chip chip--empty", "None"));
  else for (const v of values) chips.appendChild(el("span", "chip mono", v));
  group.appendChild(chips);
  wrap.appendChild(group);
}

function buildPermissions(m) {
  const wrap = el("div", "perms");
  addChipGroup(wrap, "Permissions", m.permissions);
  addChipGroup(wrap, "Optional permissions", m.optionalPermissions);
  addChipGroup(wrap, "Host access", m.hostPermissions);
  addChipGroup(wrap, "Content scripts on", m.contentScriptMatches);
  addChipGroup(wrap, "Externally connectable", m.externallyConnectable);

  const group = el("div", "perms__group");
  group.appendChild(el("div", "perms__label", "Other"));
  const chips = el("div", "chips");
  chips.appendChild(el("span", "chip mono", "MV" + m.manifestVersion));
  chips.appendChild(el("span", "chip mono", m.hasBackground ? "background script" : "no background"));
  chips.appendChild(el("span", "chip mono", m.updateUrl ? "update URL " + m.updateUrl : "no update URL"));
  chips.appendChild(el("span", "chip mono", m.csp ? "CSP " + m.csp : "no CSP"));
  group.appendChild(chips);
  wrap.appendChild(group);
  return wrap;
}

function buildDrawer(item) {
  const wrap = el("div", "drawer");
  const a = item.assessment;
  const m = item.manifest;
  const findings = a && Array.isArray(a.findings) ? a.findings : [];

  wrap.appendChild(el("h3", "drawer__heading", "Findings"));
  if (!findings.length) {
    wrap.appendChild(el("p", "drawer__empty", "No scored permissions. The grade covers access only, not intent."));
  } else {
    const list = el("ul", "finding-list");
    for (const f of findings) list.appendChild(buildFindingItem(f));
    wrap.appendChild(list);
  }

  if (a && a.summary) {
    wrap.appendChild(el("h3", "drawer__heading", "Summary"));
    wrap.appendChild(el("p", "drawer__summary", a.summary));
  }

  if (m) {
    wrap.appendChild(el("h3", "drawer__heading", "Manifest permissions"));
    wrap.appendChild(buildPermissions(m));
  }
  return wrap;
}

function buildErrorRow(item) {
  const row = el("tr", "result result--error");
  const cell = el("td", "result__cell");
  cell.colSpan = 5;
  cell.appendChild(el("span", "muted", "Could not load"));
  if (item.id) cell.appendChild(el("span", "mono result__cell-id", " " + item.id));
  cell.appendChild(el("span", "severity severity--red", item.error));
  row.appendChild(cell);
  return row;
}

function buildSummaryRow(item) {
  const m = item.manifest;
  const a = item.assessment;
  const name = (m && m.name) || item.id || "Unknown";
  const version = m && m.version ? "v" + m.version : "";
  const grade = a && a.grade ? a.grade : "?";
  const score = a && typeof a.score === "number" ? a.score : 0;
  const top = topFinding(a);

  const row = el("tr", "result");

  const nameCell = el("td", "result__name");
  nameCell.appendChild(el("div", "result__name-line", name));
  nameCell.appendChild(el("div", "result__id mono", (m && m.id) || item.id || ""));
  if (version) nameCell.appendChild(el("div", "result__version", version));
  row.appendChild(nameCell);

  const riskCell = el("td", "result__risk");
  riskCell.appendChild(gradeBadge(grade));
  row.appendChild(riskCell);

  const scoreCell = el("td", "result__score");
  scoreCell.appendChild(el("span", "score", String(score)));
  row.appendChild(scoreCell);

  const topCell = el("td", "result__top");
  if (top) {
    topCell.appendChild(el("div", "result__top-title", top.title));
    topCell.appendChild(severityTag(top.severity));
  } else {
    topCell.appendChild(el("span", "muted", "No findings"));
  }
  row.appendChild(topCell);

  const detailsCell = el("td", "result__details");
  const btn = el("button", "btn btn--ghost btn--small", "Details");
  btn.type = "button";
  btn.setAttribute("aria-expanded", "false");
  detailsCell.appendChild(btn);
  row.appendChild(detailsCell);

  return row;
}

function buildResultRow(item) {
  const frag = document.createDocumentFragment();
  if (item.error) {
    frag.appendChild(buildErrorRow(item));
    return frag;
  }

  const row = buildSummaryRow(item);
  frag.appendChild(row);

  const detailRow = el("tr", "result__detail");
  detailRow.hidden = true;
  const detailCell = el("td", "result__detail-cell");
  detailCell.colSpan = 5;
  detailCell.appendChild(buildDrawer(item));
  detailRow.appendChild(detailCell);
  frag.appendChild(detailRow);

  const btn = row.querySelector(".result__details .btn");
  btn.addEventListener("click", () => {
    const expanded = btn.getAttribute("aria-expanded") === "true";
    btn.setAttribute("aria-expanded", String(!expanded));
    detailRow.hidden = expanded;
  });

  return frag;
}

function renderResults(results, invalid = [], dropped = 0) {
  $("#workspaceEmpty").hidden = results.length > 0;
  const tbody = $("#resultsTbody");
  tbody.replaceChildren();
  for (const item of results) tbody.appendChild(buildResultRow(item));
  const ok = results.filter((r) => !r.error).length;
  const bad = results.length - ok;
  const skipped = invalid.length ? " These entries are not extension IDs, " + invalid.slice(0, 5).join(", ") + (invalid.length > 5 ? " and " + (invalid.length - 5) + " more" : "") + "." : "";
  const over = dropped > 0 ? " Only the first 25 were scanned. " + dropped + " more were left out." : "";
  const missing = results.length > 0 && bad > ok ? " Most IDs were not on the Chrome Web Store. Check them and try again." : "";
  setStatus($("#scanStatus"), "Scanned " + ok + " extension" + (ok === 1 ? "" : "s") + (bad ? ", " + bad + " could not be read" : "") + "." + skipped + over + missing, missing ? "error" : "info");
}

async function runScan(ids) {
  return apiJson("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ids }),
  });
}

async function createWatchlist(name, ids) {
  return apiJson("/api/watchlists", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, ids }),
  });
}

async function loadWatchlist(token) {
  return apiJson("/api/watchlists/" + encodeURIComponent(token));
}

function formatDate(value) {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function watchMetaText(data) {
  const last = data && data.lastCheck ? formatDate(data.lastCheck) : "";
  const n = data && Array.isArray(data.ids) ? data.ids.length : 0;
  const when = last ? "Last checked " + last : "Not checked yet";
  return when + " \u00b7 " + n + " extension" + (n === 1 ? "" : "s");
}

function usageBadgeText(usage) {
  if (!usage) return "";
  if (usage.plan === "team" && usage.trialDaysLeft > 0) return "Team trial, " + usage.trialDaysLeft + " day" + (usage.trialDaysLeft === 1 ? "" : "s") + " left";
  if (usage.plan === "free") {
    const limit = usage.limit || 25;
    const checked = Math.min(usage.ids, limit);
    const extra = usage.ids > limit ? " " + (usage.ids - limit) + " more are stored but only the first " + limit + " are checked." : "";
    return "Free plan, " + checked + " of " + limit + " extensions." + extra;
  }
  return "Team plan";
}

function showUsage(usage) {
  const node = $("#usageBadge");
  const text = usageBadgeText(usage);
  node.textContent = text;
  node.hidden = !text;
}

function buildChangeList(changes) {
  const wrap = el("div", "changelog");
  if (!changes || !changes.length) {
    wrap.appendChild(el("p", "drawer__empty", "No changes yet. Alerts appear here when an update adds permissions or host access."));
    return wrap;
  }
  const list = el("ul", "change-list");
  for (const c of changes) {
    const li = el("li", "change");
    li.appendChild(severityTag(c.severity));
    li.appendChild(el("span", "change__kind", CHANGE_LABEL[c.kind] || c.kind));
    if (c.label) li.appendChild(el("span", "change__ext", c.label));
    if (c.value && c.value !== c.id) li.appendChild(el("span", "change__value mono", c.value));
    if (c.at) li.appendChild(el("span", "change__at", new Date(c.at).toLocaleDateString()));
    list.appendChild(li);
  }
  wrap.appendChild(list);
  return wrap;
}

const AUDIT_LABEL = {
  created: "List created",
  "webhook set": "Webhook set",
  "webhook removed": "Webhook removed",
  "test alert sent": "Test alert sent",
  "policy exported": "Policy exported",
  "inventory exported": "Inventory CSV downloaded",
  "change log exported": "Change log CSV downloaded",
  "audit exported": "Audit CSV downloaded",
  deleted: "List deleted",
  rotate: "Links rotated",
  renamed: "Renamed",
  "plan set to team": "Plan upgraded to Team",
  "plan set to free": "Plan set to Free",
};

function buildAuditList(entries) {
  const wrap = el("div", "changelog");
  if (!entries || !entries.length) {
    wrap.appendChild(el("p", "drawer__empty", "No admin actions yet."));
    return wrap;
  }
  const list = el("ul", "change-list");
  for (const entry of entries.slice().reverse()) {
    const li = el("li", "change");
    li.appendChild(el("span", "change__kind", AUDIT_LABEL[entry.action] || entry.action));
    if (entry.at) li.appendChild(el("span", "change__at", new Date(entry.at).toLocaleString()));
    list.appendChild(li);
  }
  wrap.appendChild(list);
  return wrap;
}

function buildWatchExtensions(extensions) {
  const wrap = el("div", "watch-ext");
  if (!extensions || !extensions.length) {
    wrap.appendChild(el("p", "drawer__empty", "No snapshots recorded yet."));
    return wrap;
  }
  const table = el("table", "watch-table");
  const thead = el("thead");
  const headRow = el("tr");
  for (const h of ["Extension", "Access", "Score", "Version"]) headRow.appendChild(el("th", null, h));
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const item of extensions) {
    const m = item && item.manifest;
    const a = item && item.assessment;
    const tr = el("tr");
    const nameCell = el("td", "watch-table__name", (m && m.name) || (item && item.id) || "");
    if (item && item.error) nameCell.appendChild(el("span", "watch-table__error", " " + item.error));
    tr.appendChild(nameCell);
    const risk = el("td");
    risk.appendChild(gradeBadge(a && a.grade ? a.grade : "?"));
    tr.appendChild(risk);
    tr.appendChild(el("td", "mono", a && typeof a.score === "number" ? String(a.score) : "-"));
    tr.appendChild(el("td", "mono", m && m.version ? m.version : ""));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function showWatchWarning(message) {
  const node = $("#watchWarning");
  node.textContent = message || "";
  node.hidden = !message;
}

function policyPreviewText(data, mode, threshold) {
  const rank = GRADE_RANK[threshold] ?? GRADE_RANK.F;
  const snaps = (data && data.snapshots) || {};
  const ids = (data && data.ids) || Object.keys(snaps);
  const blocked = ids.filter((id) => {
    const grade = snaps[id] && snaps[id].assessment && snaps[id].assessment.grade;
    return grade && (GRADE_RANK[grade] ?? GRADE_RANK.F) >= rank;
  });
  const names = blocked.map((id) => (snaps[id] && snaps[id].manifest && snaps[id].manifest.name) || id);
  const list = names.length
    ? names.slice(0, 8).join(", ") + (names.length > 8 ? " and " + (names.length - 8) + " more" : "")
    : "none";
  const count = blocked.length + " listed extension" + (blocked.length === 1 ? "" : "s");
  if (mode === "default-deny") {
    return "Default deny blocks every extension that is not on this list, and also blocks the " + count + " at or below grade " + threshold + ". Those are " + list + ". Every extension, listed or not, is kept off the debugger permission and off the sensitive sites.";
  }
  return "Threshold leaves extensions that are not on the list installable and blocks only the " + count + " at or below grade " + threshold + ". Those are " + list + ". Every extension, listed or not, is kept off the debugger permission and off the sensitive sites.";
}

function wireExports(token, admin, data) {
  const base = "/api/watchlists/" + encodeURIComponent(token);
  $("#exportCsv").href = base + "/export.csv";
  $("#exportChanges").href = base + "/changes.csv";
  $("#exportAudit").href = base + "/audit.csv";
  // A Free list past its trial keeps the risk report but not the Team exports, which the API answers with 402.
  const free = Boolean(data && data.usage && data.usage.plan === "free");
  // Set every export button on every render, so an in page move between two lists cannot leave one hidden.
  $("#exportCsv").hidden = free;
  $("#exportChanges").hidden = free;
  $("#exportAudit").hidden = !admin || free;
  $("#policyTools").hidden = !admin || free;
  $("#policyNote").hidden = !admin || free;
  $("#policyModes").hidden = !admin || free;
  const policy = $("#exportPolicy");
  const mode = $("#policyMode");
  const threshold = $("#policyThreshold");
  const preview = $("#policyPreview");
  const update = () => {
    policy.href = base + "/policy.json?threshold=" + encodeURIComponent(threshold.value) + "&mode=" + encodeURIComponent(mode.value);
    preview.textContent = policyPreviewText(data, mode.value, threshold.value);
    preview.hidden = !admin || free;
  };
  mode.onchange = update;
  threshold.onchange = update;
  update();
}

function renderWatchlist(data, token) {
  $("#watchTitle").textContent = (data && data.name) || "Watchlist";
  $("#watchMeta").textContent = watchMetaText(data);
  showUsage(data && data.usage);
  const admin = Boolean(data && data.role === "admin");
  const shareToken = admin && data.viewToken ? data.viewToken : token;
  const link = $("#watchLink");
  link.href = "/w/" + shareToken;
  link.textContent = window.location.origin + "/w/" + shareToken;
  $("#watchLinkLabel").textContent = admin ? "Read-only link to share " : "Read-only view ";
  $("#adminNote").hidden = !admin;
  $("#adminLinkNote").hidden = !admin;
  $("#alertSection").hidden = !admin;
  $("#watchExports").hidden = false;
  wireExports(token, admin, data);
  if (admin) wireAlerts(token, data && data.webhookSet ? data.webhook : null);
  let del = document.getElementById("watchDelete");
  let rot = document.getElementById("watchRotate");
  if (!admin) {
    if (del) del.remove();
    if (rot) rot.remove();
  } else {
    if (!del) {
      del = el("button", "btn btn--ghost", "Delete this watchlist");
      del.id = "watchDelete";
      del.type = "button";
      link.parentNode.appendChild(del);
    }
    del.onclick = () => deleteWatchlist(token, del);
    if (!rot) {
      rot = el("button", "btn btn--ghost", "Rotate links");
      rot.id = "watchRotate";
      rot.type = "button";
      link.parentNode.appendChild(rot);
    }
    wireRotate(token, rot);
  }
  const changes = $("#watchChanges");
  const names = {};
  for (const [id, snap] of Object.entries((data && data.snapshots) || {})) names[id] = snap && snap.manifest ? snap.manifest.name : id;
  const named = ((data && data.changes) || []).slice().reverse().map((c) => Object.assign({}, c, { label: names[c.id] || c.id }));
  changes.replaceChildren(buildChangeList(named));
  const exts = $("#watchExtensions");
  // The API keys snapshots by extension ID; show them in the order the list was created.
  const snaps = (data && data.snapshots) || {};
  const ids = (data && data.ids) || Object.keys(snaps);
  const list = ids.map((id) => snaps[id]).filter(Boolean);
  exts.replaceChildren(buildWatchExtensions(list));
  const auditSection = $("#auditSection");
  const free = Boolean(data && data.usage && data.usage.plan === "free");
  auditSection.hidden = !admin || free;
  if (admin && !free) $("#watchAudit").replaceChildren(buildAuditList((data && data.audit) || []));
  let warning = "";
  try {
    warning = window.sessionStorage.getItem("ew-watch-warning") || "";
    if (warning) window.sessionStorage.removeItem("ew-watch-warning");
  } catch {
    warning = "";
  }
  const missing = ids.filter((id) => snaps[id] && snaps[id].error === "Not on the Chrome Web Store").length;
  if (!warning && ids.length > 0 && missing * 2 > ids.length) warning = "Most IDs in this list are not on the Chrome Web Store. Check them and try again.";
  showWatchWarning(warning);
}

function wireRotate(token, button) {
  button.onclick = async () => {
    if (!window.confirm("Rotate both links? The old admin and read-only links stop working within about a minute, the time Workers KV takes to drop cached reads.")) return;
    button.disabled = true;
    try {
      const data = await apiJson("/api/watchlists/" + encodeURIComponent(token) + "/rotate", { method: "POST" });
      const origin = window.location.origin;
      window.alert("New admin link " + origin + data.url + "\nNew read-only link " + origin + data.viewUrl + "\nSave them now. The old links stop working within about a minute.");
      window.location.assign(data.url);
    } catch (err) {
      button.disabled = false;
      $("#watchMeta").textContent = err.message || "Could not rotate the links.";
    }
  };
}

async function deleteWatchlist(token, button) {
  if (!window.confirm("Delete this watchlist and its history? This cannot be undone.")) return;
  try {
    const res = await fetch("/api/watchlists/" + encodeURIComponent(token), { method: "DELETE" });
    if (!res.ok) throw new Error("status " + res.status);
    $("#watchMeta").textContent = "Deleted. Both links stop working within about a minute.";
    $("#watchExtensions").replaceChildren();
    $("#watchChanges").replaceChildren();
    $("#alertSection").hidden = true;
    button.remove();
  } catch (err) {
    $("#watchMeta").textContent = "Could not delete (" + err.message + "). Try again.";
  }
}

function wireAlerts(token, webhook) {
  const form = $("#alertForm");
  const input = $("#alertUrl");
  const status = $("#alertStatus");
  input.value = "";
  input.placeholder = webhook ? "Alerts go to " + webhook + ". Paste a new URL to replace it." : "https://hooks.slack.com/services/...";
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (!input.value.trim() && webhook && !window.confirm("Turn off alerts for this watchlist?")) return;
    try {
      const res = await apiJson("/api/watchlists/" + encodeURIComponent(token), {
        method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ webhook: input.value.trim() }),
      });
      webhook = res.webhook ? "https://" + new URL(input.value.trim()).hostname + "/..." : null;
      input.value = "";
      input.placeholder = webhook ? "Alerts go to " + webhook + ". Paste a new URL to replace it." : "https://hooks.slack.com/services/...";
      setStatus(status, res.webhook ? "Saved. Changes will be sent to this webhook." : "Alerts turned off.", "info");
    } catch (err) {
      setStatus(status, err.message, "error");
    }
  };
  $("#alertTest").onclick = async () => {
    setStatus(status, "Sending\u2026", "info");
    try {
      const res = await apiJson("/api/test-alert", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
      setStatus(status, res.sent ? "Test alert sent. Check your channel." : "The webhook did not accept it (HTTP " + res.status + "). Check the URL.", res.sent ? "info" : "error");
    } catch (err) {
      setStatus(status, err.message, "error");
    }
  };
}

function extractRules(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.rules)) return data.rules;
  if (data && Array.isArray(data.points)) return data.points;
  return [];
}

function renderRules(rules) {
  const wrap = $("#rulesWrap");
  wrap.replaceChildren();
  if (!rules.length) {
    wrap.appendChild(el("p", "drawer__empty", "Rules could not be loaded."));
    return;
  }
  const table = el("table", "rules-table");
  const thead = el("thead");
  const headRow = el("tr");
  for (const h of ["Rule", "Group (counts once)", "Severity", "Points"]) headRow.appendChild(el("th", null, h));
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const r of rules) {
    const tr = el("tr");
    const name = r.title || r.name || r.code || "";
    tr.appendChild(el("td", "rules__name", name));
    tr.appendChild(el("td", "rules__group mono", String(r.group || "").replace(/_/g, " ")));
    const sev = el("td");
    sev.appendChild(severityTag(r.severity));
    tr.appendChild(sev);
    tr.appendChild(el("td", "rules__points mono", String(r.points ?? "")));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
}

async function loadRules() {
  try {
    const data = await apiJson("/api/rules");
    renderRules(extractRules(data));
    setStatus($("#rulesStatus"), "", null);
  } catch (err) {
    renderRules([]);
    setStatus($("#rulesStatus"), err.message || "Rules could not be loaded.", "error");
  }
}

function showView(name) {
  for (const view of $$(".view")) view.hidden = view.id !== "view-" + name;
  for (const btn of $$("[data-nav]")) {
    const active = btn.getAttribute("data-nav") === name;
    if (active) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
    btn.classList.toggle("nav__link--active", active);
  }
  if (name !== "watchlist") history.replaceState(null, "", "/");
  if (name === "methodology" && !rulesLoaded) {
    rulesLoaded = true;
    loadRules();
  }
  window.scrollTo(0, 0);
}

function route() {
  const match = window.location.pathname.match(/^\/w\/([A-Za-z0-9_-]+)$/);
  if (!match) {
    showView("landing");
    return;
  }
  showView("watchlist");
  loadWatchlist(match[1])
    .then((data) => renderWatchlist(data, match[1]))
    .catch((err) => {
      $("#watchTitle").textContent = "Watchlist not found";
      $("#watchMeta").textContent = err.message || "This link is not valid.";
      $("#watchLink").textContent = "";
      $("#watchChanges").replaceChildren();
      $("#watchExtensions").replaceChildren();
      showUsage(null);
      showWatchWarning("");
      $("#watchExports").hidden = true;
    });
}

function wireNav() {
  for (const btn of $$("[data-nav]")) {
    btn.addEventListener("click", (event) => {
      event.preventDefault();
      showView(btn.getAttribute("data-nav"));
    });
  }
}

function wireSample() {
  const button = $("#sampleButton");
  button.addEventListener("click", () => {
    $("#tryInput").value = SAMPLE_IDS.join("\n");
    setStatus($("#tryStatus"), "Sample list ready. Scan it to see real grades.", "info");
    $("#tryInput").focus();
  });
}

function wireTryForm() {
  const form = $("#tryForm");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = $("#tryStatus");
    const ids = parseIds($("#tryInput").value);
    if (!ids.length) {
      setStatus(status, "Paste at least one extension ID or Web Store URL.", "error");
      return;
    }
    setStatus(status, "Scanning " + ids.length + " extension" + (ids.length === 1 ? "" : "s") + "\u2026", "info");
    try {
      const data = await runScan(ids);
      const results = extractResults(data);
      lastIds = ids;
      const invalid = $("#tryInput").value.split(/[\s,;]+/).filter(Boolean).filter((part) => parseIds(part).length === 0);
      renderResults(results, invalid, Number(data && data.dropped) || 0);
      $("#watchForm").hidden = false;
      setStatus($("#watchStatus"), "", null);
      showView("workspace");
    } catch (err) {
      setStatus(status, err.message || "Scan failed.", "error");
    }
  });
}

function wireWatchForm() {
  const form = $("#watchForm");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = $("#watchStatus");
    if (!lastIds.length) return;
    const name = $("#watchName").value.trim() || "Watchlist " + new Date().toISOString().slice(0, 10);
    setStatus(status, "Creating watchlist\u2026", "info");
    try {
      const data = await createWatchlist(name, lastIds);
      const token = data && data.token;
      if (!token) throw new Error("The service did not return a link.");
      const notice = data && data.note
        ? String(data.note)
        : data && Number(data.dropped) > 0
          ? "The list holds 50 extensions. " + data.dropped + " more were left out."
          : "";
      if (notice) {
        try {
          window.sessionStorage.setItem("ew-watch-warning", notice);
        } catch {
          // Storage can be unavailable in private modes; the list is still created.
        }
      }
      window.location.assign("/w/" + encodeURIComponent(token));
    } catch (err) {
      setStatus(status, err.message || "Could not create watchlist.", "error");
    }
  });
}

function init() {
  wireNav();
  wireSample();
  wireTryForm();
  wireWatchForm();
  route();
}

init();
