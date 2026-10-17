"use strict";

const $ = (selector, root) => (root || document).querySelector(selector);
const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));

const GRADE_COLOR = { A: "green", B: "teal", C: "amber", D: "orange", F: "red" };
const SEVERITY_COLOR = { critical: "red", high: "orange", medium: "amber", low: "muted" };

const CHANGE_LABEL = {
  permission_added: "Permission added",
  permission_removed: "Permission removed",
  host_added: "Host access added",
  host_removed: "Host access removed",
  mv_changed: "Manifest version changed",
  new_extension: "New extension",
  removed_from_store: "Removed from store",
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
  for (const line of String(text || "").split(/\r?\n/)) {
    const id = normalizeId(line);
    if (id && !seen.has(id)) {
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
  chips.appendChild(el("span", "chip mono", m.updateUrl ? "update URL: " + m.updateUrl : "no update URL"));
  chips.appendChild(el("span", "chip mono", m.csp ? "CSP: " + m.csp : "no CSP"));
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
    wrap.appendChild(el("p", "drawer__empty", "No risk findings. This extension looks clean."));
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

function buildResultRow(item) {
  const frag = document.createDocumentFragment();
  const detailCols = 5;

  if (item.error) {
    const row = el("tr", "result result--error");
    const cell = el("td", "result__cell");
    cell.colSpan = detailCols;
    cell.appendChild(el("span", "muted", "Could not load"));
    if (item.id) cell.appendChild(el("span", "mono result__cell-id", " " + item.id));
    cell.appendChild(el("span", "severity severity--red", item.error));
    row.appendChild(cell);
    frag.appendChild(row);
    return frag;
  }

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

  frag.appendChild(row);

  const detailRow = el("tr", "result__detail");
  detailRow.hidden = true;
  const detailCell = el("td", "result__detail-cell");
  detailCell.colSpan = detailCols;
  detailCell.appendChild(buildDrawer(item));
  detailRow.appendChild(detailCell);
  frag.appendChild(detailRow);

  btn.addEventListener("click", () => {
    const expanded = btn.getAttribute("aria-expanded") === "true";
    btn.setAttribute("aria-expanded", String(!expanded));
    detailRow.hidden = expanded;
  });

  return frag;
}

function renderResults(results) {
  const tbody = $("#resultsTbody");
  tbody.replaceChildren();
  for (const item of results) tbody.appendChild(buildResultRow(item));
  const ok = results.filter((r) => !r.error).length;
  const bad = results.length - ok;
  setStatus($("#scanStatus"), "Scanned " + ok + " extension" + (ok === 1 ? "" : "s") + (bad ? ", " + bad + " failed" : "") + ".", "info");
}

async function runScan(ids) {
  const data = await apiJson("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ids }),
  });
  return extractResults(data);
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
    if (c.value) li.appendChild(el("span", "change__value mono", c.value));
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
  for (const h of ["Extension", "Risk", "Score", "Version"]) headRow.appendChild(el("th", null, h));
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const item of extensions) {
    const m = item && item.manifest;
    const a = item && item.assessment;
    const tr = el("tr");
    tr.appendChild(el("td", "watch-table__name", (m && m.name) || (item && item.id) || ""));
    const risk = el("td");
    risk.appendChild(gradeBadge(a && a.grade ? a.grade : "?"));
    tr.appendChild(risk);
    tr.appendChild(el("td", "mono", a && typeof a.score === "number" ? String(a.score) : "\u2013"));
    tr.appendChild(el("td", "mono", m && m.version ? m.version : ""));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function renderWatchlist(data, token) {
  $("#watchTitle").textContent = (data && data.name) || "Watchlist";
  $("#watchMeta").textContent = watchMetaText(data);
  const link = $("#watchLink");
  link.href = "/w/" + token;
  link.textContent = window.location.origin + "/w/" + token;
  const changes = $("#watchChanges");
  changes.replaceChildren(buildChangeList(data && data.changes));
  const exts = $("#watchExtensions");
  const list = data && Array.isArray(data.extensions) ? data.extensions : [];
  exts.replaceChildren(buildWatchExtensions(list));
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
  for (const h of ["Rule", "Severity", "Points"]) headRow.appendChild(el("th", null, h));
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const r of rules) {
    const tr = el("tr");
    const name = r.title || r.name || r.code || "";
    tr.appendChild(el("td", "rules__name", name));
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
  } catch (err) {
    renderRules([]);
    setStatus($("#scanStatus"), err.message || "Rules could not be loaded.", "error");
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
  if (name !== "watchlist") {
    const path = name === "landing" ? "/" : "/";
    history.replaceState(null, "", path);
  }
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
      const results = await runScan(ids);
      lastIds = ids;
      renderResults(results);
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
      window.location.assign("/w/" + encodeURIComponent(token));
    } catch (err) {
      setStatus(status, err.message || "Could not create watchlist.", "error");
    }
  });
}

function init() {
  wireNav();
  wireTryForm();
  wireWatchForm();
  route();
}

init();
