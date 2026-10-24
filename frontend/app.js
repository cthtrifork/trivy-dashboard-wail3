import { Call, Events } from "/wails/runtime.js";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const SEV_COLOR = { CRITICAL: "--CRITICAL", HIGH: "--HIGH", MEDIUM: "--MEDIUM", LOW: "--LOW", UNKNOWN: "--UNKNOWN" };
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...kids);
  return e;
};
const call = (method, ...args) => Call.ByName(`main.ScanService.${method}`, ...args);

let result = null;
const vulnState = { filter: "", sort: "priority", dir: 1, hidden: new Set() };
const sbomState = { filter: "", sort: "name", dir: 1, hidden: new Set() };

// ---- tabs ----
document.querySelectorAll(".tab").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === b));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${b.dataset.tab}`));
  })
);

// ---- status / log ----
function setStatus(msg, { err = false, busy = false } = {}) {
  const s = $("status");
  s.textContent = msg;
  s.className = (err ? "err " : "") + (busy ? "spin" : "");
}
Events.On("scan:log", (ev) => {
  const log = $("log");
  const line = Array.isArray(ev.data) ? ev.data[0] : ev.data;
  log.append(line + "\n");
  log.scrollTop = log.scrollHeight;
  if ($("scan-btn").disabled) setStatus(String(line).slice(0, 200), { busy: true });
});

// ---- scan ----
$("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("scan-btn").disabled = true;
  $("cancel-btn").hidden = false;
  $("log").textContent = "";
  setStatus("Starting scan…", { busy: true });
  try {
    result = await call("Scan", {
      image: $("image").value,
      username: $("username").value,
      password: $("password").value,
      ignoreUnfixed: $("ignore-unfixed").checked,
      trivyImage: $("trivy-image").value.trim(),
    });
    await render();
    setStatus(`Scan complete: ${result.vulnerabilities.length} vulnerabilities, ${result.components.length} components.`);
  } catch (err) {
    setStatus(String(err.message || err), { err: true });
  } finally {
    $("scan-btn").disabled = false;
    $("cancel-btn").hidden = true;
  }
});
$("cancel-btn").addEventListener("click", () => call("Cancel"));

// ---- self-update ----
// The Go side decides whether this build may update itself (release builds only).
call("UpdateInfo").then((u) => {
  $("app-version").textContent = "Version " + u.version;
  $("update-btn").disabled = !u.enabled;
  if (!u.enabled) $("update-btn").title = u.reason;
}, () => {});
$("update-btn").addEventListener("click", async () => {
  $("update-btn").disabled = true;
  setStatus("Checking for updates…", { busy: true });
  try {
    await call("CheckForUpdates"); // opens the updater window; resolves once the update is staged or none is found
    setStatus("Update check finished.");
  } catch (err) {
    setStatus(String(err.message || err), { err: true });
  } finally {
    $("update-btn").disabled = false;
  }
});

// Development builds replay recorded scans: say so, and prefill the inputs with something that works.
call("Mode").then((m) => {
  if (m.trivyImage) $("trivy-image").placeholder = "Trivy version or image (default " + m.trivyImage.split("/").pop() + ")";
  if (!m.fixtures) return;
  $("mode-banner").textContent = m.detail;
  $("mode-banner").hidden = false;
  if (!$("image").value) $("image").value = m.image;
  if (!$("cmp-repo").value) $("cmp-repo").value = m.repo;
  if (!$("cmp-a").value) $("cmp-a").value = m.tagA;
  if (!$("cmp-b").value) $("cmp-b").value = m.tagB;
}, () => {});

call("PodmanVersion").then((v) => setStatus(v), (err) => setStatus(String(err.message || err), { err: true }));

// ---- rendering ----
function cards(container, entries, state, colorOf, rerender) {
  container.replaceChildren(
    ...entries.map(([name, count]) => {
      const c = el("div", { className: "card" + (state.hidden.has(name) ? " off" : "") }, el("b", { textContent: count }), el("span", { textContent: name }));
      c.style.setProperty("--c", `var(${colorOf(name)})`);
      c.addEventListener("click", () => {
        state.hidden.has(name) ? state.hidden.delete(name) : state.hidden.add(name);
        rerender();
      });
      return c;
    })
  );
}

function sortRows(rows, state, key) {
  const val = (r) => {
    const v = key(r, state.sort);
    return typeof v === "string" ? v.toLowerCase() : v;
  };
  return [...rows].sort((a, b) => {
    const x = val(a), y = val(b);
    return (x < y ? -1 : x > y ? 1 : 0) * state.dir;
  });
}

function markSort(table, state) {
  table.querySelectorAll("th").forEach((th) => {
    th.className = th.dataset.sort === state.sort ? (state.dir > 0 ? "asc" : "desc") : "";
  });
}

function wireSort(table, state, rerender) {
  table.querySelectorAll("th").forEach((th) =>
    th.addEventListener("click", () => {
      state.dir = state.sort === th.dataset.sort ? -state.dir : 1;
      state.sort = th.dataset.sort;
      rerender();
    })
  );
}

function renderVulns() {
  if (!result) return;
  const counts = result.severityCounts;
  cards($("sev-cards"), SEVERITIES.map((s) => [s, counts[s] || 0]), vulnState, (s) => SEV_COLOR[s], renderVulns);
  const q = vulnState.filter.toLowerCase();
  const rows = result.vulnerabilities.filter(
    (v) => !vulnState.hidden.has(v.severity) && (!q || [v.id, v.package, v.title, v.installed, v.fixed].join(" ").toLowerCase().includes(q))
  );
  const signalRank = (v) => (v.kev ? 2 : 0) + (vex.has(v.key) ? 1 : 0);
  const sorted = sortRows(rows, vulnState, (v, k) =>
    k === "severity" ? SEVERITIES.indexOf(v.severity) : k === "score" ? -v.score : k === "priority" ? -v.priority :
    k === "epss" ? -v.epss : k === "signals" ? -signalRank(v) : v[k] ?? ""
  );
  const tbody = $("vuln-table").tBodies[0];
  tbody.replaceChildren();
  for (const v of sorted) {
    const sev = el("span", { className: "sev", textContent: v.severity });
    sev.style.setProperty("--c", `var(${SEV_COLOR[v.severity]})`);
    const signals = el("td", {});
    if (v.kev) signals.append(chip("KEV", "hot", "Known exploited (CISA)"), " ");
    const ve = vex.get(v.key);
    if (ve) signals.append(chip("VEX: " + ve.status.replace("_", " "), "vex"));
    const tier = el("span", { className: "sev tier", textContent: `${v.tier} ${v.priority}` });
    tier.style.setProperty("--c", `var(${TIER_COLOR[v.tier]})`);
    const row = el("tr", { className: "row" },
      el("td", {}, tier),
      el("td", {}, sev),
      el("td", { className: "mono", textContent: v.id, style: "white-space:nowrap" }),
      el("td", { className: "mono", textContent: v.package }),
      el("td", { className: "mono", textContent: v.installed }),
      el("td", { className: "mono", textContent: v.fixed || "—" }),
      el("td", { textContent: v.score ? v.score.toFixed(1) : "—" }),
      el("td", { textContent: v.hasEpss ? pct(v.epss) : "—" }),
      signals,
      el("td", { textContent: v.title })
    );
    let detail = null;
    row.addEventListener("click", () => {
      if (detail) { detail.remove(); detail = null; return; }
      const td = el("td", { colSpan: 10 });
      td.append(el("p", { className: "attack", textContent: v.attack }));
      td.append(`Target: ${v.target}\nStatus: ${v.status || "—"}\n\n${v.description || "No description."}\n\n`);
      if (/^https?:\/\//.test(v.url)) td.append(el("span", { className: "mono", textContent: v.url }), "\n");
      td.append(vexBox(v));
      detail = el("tr", { className: "detail" }, td);
      row.after(detail);
    });
    tbody.append(row);
  }
  markSort($("vuln-table"), vulnState);
  $("vuln-count").textContent = result.vulnerabilities.length;
  $("vuln-shown").textContent = `${sorted.length} shown`;
  $("vuln-empty").hidden = sorted.length > 0;
  $("vuln-empty").textContent = result.vulnerabilities.length ? "No vulnerabilities match the filter." : "No vulnerabilities found 🎉";
}

// ---- prioritisation + VEX ----
const vex = new Map(); // finding key -> saved VEX entry for the scanned image repo
const prio = { top: 10, hideResolved: true, fixableOnly: false, includeLow: false };
const openVex = new Set();
const RESOLVED = new Set(["not_affected", "fixed"]);
const TIER_COLOR = { "Act now": "--CRITICAL", "Fix soon": "--HIGH", Plan: "--MEDIUM", Monitor: "--UNKNOWN" };
const TIERS = Object.keys(TIER_COLOR);
const STATUS_LABEL = { affected: "Affected", not_affected: "Not affected", fixed: "Fixed", under_investigation: "Under investigation" };
const JUSTIFICATIONS = {
  component_not_present: "Component not present",
  vulnerable_code_not_present: "Vulnerable code not present",
  vulnerable_code_not_in_execute_path: "Vulnerable code not in execute path",
  vulnerable_code_cannot_be_controlled_by_adversary: "Code cannot be controlled by an adversary",
  inline_mitigations_already_exist: "Inline mitigations already exist",
};
const pct = (x) => (x * 100 < 0.1 ? "<0.1%" : (x * 100).toFixed(x >= 0.1 ? 0 : 1) + "%");
const chip = (text, kind = "", title = "") => el("span", { className: "chip " + kind, textContent: text, title });
const isResolved = (v) => RESOLVED.has(vex.get(v.key)?.status);

async function loadVEX() {
  vex.clear();
  try {
    for (const e of (await call("VEXList", result.image)) || []) vex.set(e.key, e);
  } catch (err) {
    setStatus("Could not load VEX assessments: " + (err.message || err), { err: true });
  }
}

function vexBox(v) {
  const existing = vex.get(v.key);
  const box = el("details", { className: "vexbox" });
  box.open = openVex.has(v.key) || !!existing;
  box.addEventListener("toggle", () => (box.open ? openVex.add(v.key) : openVex.delete(v.key)));
  box.addEventListener("click", (e) => e.stopPropagation());
  box.append(el("summary", { textContent: existing ? `VEX assessment: ${STATUS_LABEL[existing.status]}` : "Assess this finding (VEX)" }));

  const status = el("select", {});
  status.append(el("option", { value: "", textContent: "— select status —" }));
  for (const [k, l] of Object.entries(STATUS_LABEL)) status.append(el("option", { value: k, textContent: l }));
  status.value = existing?.status || "";
  const just = el("select", {});
  just.append(el("option", { value: "", textContent: "— select justification —" }));
  for (const [k, l] of Object.entries(JUSTIFICATIONS)) just.append(el("option", { value: k, textContent: l }));
  just.value = existing?.justification || "";
  const impact = el("textarea", { rows: 2, placeholder: "Explain why (e.g. the service is not exposed, the code path is never loaded)", value: existing?.impact || "" });
  const action = el("textarea", { rows: 2, placeholder: "What will be done about it (e.g. upgrade to 3.1 in the next release)", value: existing?.action || "" });
  const err = el("div", { className: "vexerr" });
  const field = (label, input) => el("label", { textContent: label }, input);
  const justF = field("Justification (required unless an impact statement is given)", just);
  const impF = field("Impact statement", impact);
  const actF = field("Action statement (required for affected)", action);
  const sync = () => {
    justF.hidden = status.value !== "not_affected";
    actF.hidden = status.value !== "affected";
    impF.hidden = !status.value;
  };
  status.addEventListener("change", sync);
  sync();

  const save = el("button", { textContent: "Save", type: "button" });
  save.addEventListener("click", async () => {
    err.textContent = "";
    if (!status.value) { err.textContent = "Choose a status."; return; }
    try {
      const saved = await call("VEXSet", result.image, {
        vulnerability: v.id, package: v.package, version: v.installed, purl: v.purl,
        status: status.value, justification: just.value, impact: impact.value, action: action.value,
      });
      vex.set(saved.key, saved);
      openVex.add(v.key);
      renderPrio();
      renderVulns();
    } catch (e) {
      err.textContent = e.message || String(e);
    }
  });
  const clear = el("button", { className: "ghost", textContent: "Remove assessment", type: "button", hidden: !existing });
  clear.addEventListener("click", async () => {
    await call("VEXDelete", result.image, v.key);
    vex.delete(v.key);
    openVex.delete(v.key);
    renderPrio();
    renderVulns();
  });
  box.append(el("div", { className: "vexform" }, field("Status", status), justF, impF, actF, el("div", { className: "row" }, save, clear), err));
  return box;
}

function prioCard(v, rank) {
  const c = el("div", { className: "pcard" });
  c.style.setProperty("--c", `var(${TIER_COLOR[v.tier]})`);
  const tier = el("span", { className: "sev tier", textContent: v.tier });
  tier.style.setProperty("--c", `var(${TIER_COLOR[v.tier]})`);
  const chips = el("div", { className: "chips" }, chip(v.severity + (v.score ? ` ${v.score.toFixed(1)}` : ""), "", "CVSS severity"));
  if (v.kev) chips.append(chip("KEV" + (v.kevRansomware ? " · ransomware" : ""), "hot", `Added to CISA KEV on ${v.kevAdded}; due ${v.kevDue}. ${v.kevAction}`));
  if (v.hasEpss) chips.append(chip("EPSS " + pct(v.epss), v.epss >= 0.1 ? "warm" : "", `Exploitation probability in the next 30 days; percentile ${(v.epssPercentile * 100).toFixed(1)}`));
  const av = /AV:([NALP])/.exec(v.vector)?.[1];
  if (av) chips.append(chip({ N: "Network", A: "Adjacent", L: "Local", P: "Physical" }[av], av === "N" ? "warm" : "", v.vector));
  chips.append(chip(v.fixed ? "Fix: " + v.fixed : "No fix yet"));
  const ve = vex.get(v.key);
  if (ve) chips.append(chip("VEX: " + STATUS_LABEL[ve.status], "vex"));
  const why = el("ul", { className: "why" }, ...v.reasons.map((r) =>
    el("li", {}, el("span", { className: "pts" + (r.points > 0 ? " pos" : ""), textContent: (r.points > 0 ? "+" : "") + r.points }), el("span", { textContent: r.text }))));
  c.append(
    el("div", { className: "rank", textContent: rank }),
    el("div", { className: "pbody" },
      el("div", { className: "phead" }, el("span", { className: "id", textContent: v.id }), tier,
        el("span", { className: "mono", textContent: `${v.package} ${v.installed}` })),
      chips,
      el("p", { className: "attack", textContent: v.attack }),
      v.title ? el("div", { className: "kv", textContent: v.title }) : "",
      why, vexBox(v)),
    el("div", { className: "score" }, el("b", { textContent: v.priority }), "score")
  );
  return c;
}

function renderPrio() {
  if (!result) return;
  const all = result.vulnerabilities;
  const hidden = all.filter((v) => prio.hideResolved && isResolved(v));
  const open = all.filter((v) => !(prio.hideResolved && isResolved(v)) && (!prio.fixableOnly || v.fixed));
  const lowN = open.filter((v) => v.tier === "Monitor").length;
  const pool = prio.includeLow ? open : open.filter((v) => v.tier !== "Monitor");
  const list = prio.top ? pool.slice(0, prio.top) : pool;

  const tierCount = Object.fromEntries(TIERS.map((t) => [t, open.filter((v) => v.tier === t).length]));
  $("prio-summary").replaceChildren(...TIERS.map((t) => {
    const k = el("div", { className: "card" }, el("b", { textContent: tierCount[t] }), el("span", { textContent: t }));
    k.style.setProperty("--c", `var(${TIER_COLOR[t]})`);
    k.style.cursor = "default";
    return k;
  }));
  const kevN = open.filter((v) => v.kev).length;
  $("prio-note").textContent =
    `${all.length} findings → ${tierCount["Act now"] + tierCount["Fix soon"]} worth acting on` +
    (kevN ? `, ${kevN} known exploited` : "") + (hidden.length ? ` · ${hidden.length} hidden by VEX` : "") + (!prio.includeLow && lowN ? ` · ${lowN} low-risk not shown` : "");
  $("prio-count").textContent = pool.length;
  $("prio-count").title = "findings that need attention";
  $("vex-count").textContent = vex.size;

  const en = result.enrichment || {};
  const notes = [];
  if (en.kev) notes.push(`CISA KEV ${en.kevDate}`);
  if (en.epss) notes.push("EPSS");
  const banner = [];
  if (!all.length) banner.push(el("div", { className: "empty", textContent: "No vulnerabilities found 🎉" }));
  else {
    banner.push(el("div", { className: "kv", textContent: `Ranked by exploitation evidence, then reachability and severity. Signals: ${notes.join(", ") || "CVSS only"}.` +
      (en.warnings?.length ? " ⚠ " + en.warnings.join("; ") + " — ranking uses CVSS only for the missing signals." : "") }));
    list.forEach((v, i) => banner.push(prioCard(v, i + 1)));
    if (!list.length) banner.push(el("div", { className: "empty", textContent: "Nothing left to show with these filters." }));
    else if (pool.length > list.length) banner.push(el("div", { className: "kv", textContent: `${pool.length - list.length} more findings not shown — they rank lower.` }));
  }
  const keep = $("prio-list").scrollTop;
  $("prio-list").replaceChildren(...banner);
  $("prio-list").scrollTop = keep;
}

$("prio-top").addEventListener("change", (e) => { prio.top = +e.target.value; renderPrio(); });
$("prio-hide").addEventListener("change", (e) => { prio.hideResolved = e.target.checked; renderPrio(); });
$("prio-low").addEventListener("change", (e) => { prio.includeLow = e.target.checked; renderPrio(); });
$("prio-fixable").addEventListener("change", (e) => { prio.fixableOnly = e.target.checked; renderPrio(); });

// ---- OpenVEX export ----
const dlg = $("vex-dialog");
const lsGet = (k) => { try { return localStorage.getItem(k) || ""; } catch { return ""; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* ignore */ } };
$("vex-export-btn").addEventListener("click", async () => {
  if (!result) return;
  $("vex-image").textContent = result.image;
  $("vex-author").value = lsGet("vex-author");
  $("vex-role").value = lsGet("vex-role");
  $("vex-msg").textContent = vex.size ? "" : "No assessments yet: open a finding and set a VEX status first.";
  $("vex-preview").value = "";
  dlg.showModal();
  refreshPreview();
});
async function refreshPreview() {
  $("vex-msg").textContent = "";
  try {
    $("vex-preview").value = await call("VEXExport", result.image, $("vex-author").value, $("vex-role").value);
  } catch (e) {
    $("vex-preview").value = "";
    $("vex-msg").textContent = e.message || String(e);
  }
}
$("vex-author").addEventListener("input", refreshPreview);
$("vex-role").addEventListener("input", refreshPreview);
$("vex-close").addEventListener("click", () => dlg.close());
$("vex-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("vex-preview").value); $("vex-msg").textContent = "Copied."; }
  catch { $("vex-preview").select(); document.execCommand("copy"); $("vex-msg").textContent = "Copied."; }
});
$("vex-save").addEventListener("click", async () => {
  lsSet("vex-author", $("vex-author").value);
  lsSet("vex-role", $("vex-role").value);
  try {
    const path = await call("VEXSave", result.image, $("vex-author").value, $("vex-role").value);
    $("vex-msg").textContent = path ? "Saved to " + path : "";
    return;
  } catch (e) {
    if (!$("vex-preview").value) { $("vex-msg").textContent = e.message || String(e); return; }
  }
  // No native dialog (e.g. server mode): fall back to a browser download.
  const a = el("a", { href: URL.createObjectURL(new Blob([$("vex-preview").value], { type: "application/json" })), download: "vex.openvex.json" });
  a.click();
  $("vex-msg").textContent = "Downloaded vex.openvex.json";
});

function renderSBOM() {
  if (!result) return;
  const types = Object.entries(result.componentTypes).sort((a, b) => b[1] - a[1]);
  cards($("type-cards"), [["total", result.components.length], ...types], sbomState, () => "--accent", renderSBOM);
  // the "total" card is informational only
  $("type-cards").firstChild.style.cursor = "default";
  const q = sbomState.filter.toLowerCase();
  const rows = result.components.filter(
    (c) => !sbomState.hidden.has(c.type) && (!q || [c.name, c.version, c.purl, c.licenses.join(" ")].join(" ").toLowerCase().includes(q))
  );
  const sorted = sortRows(rows, sbomState, (c, k) => (k === "licenses" ? c.licenses.join(", ") : c[k] ?? ""));
  const tbody = $("sbom-table").tBodies[0];
  tbody.replaceChildren(
    ...sorted.map((c) =>
      el("tr", {},
        el("td", { className: "mono", textContent: (c.group ? c.group + "/" : "") + c.name }),
        el("td", { className: "mono", textContent: c.version || "—" }),
        el("td", { textContent: c.type }),
        el("td", { textContent: c.licenses.join(", ") || "—" }),
        el("td", { className: "mono", textContent: c.purl || "—" })
      )
    )
  );
  markSort($("sbom-table"), sbomState);
  $("sbom-count").textContent = result.components.length;
  $("sbom-shown").textContent = `${sorted.length} shown · ${result.sbomFormat}`;
  $("sbom-empty").hidden = sorted.length > 0;
  $("sbom-empty").textContent = "No components match the filter.";
}

// ---- dependency graph ----
import { Graph } from "./graph.js";

const dep = { filter: "", cat: "all", vulnOnly: true, focus: 0, selected: null };
const IMAGE_NODE = "__image__";
const MAX_NODES = 400;
const SEV_ABBR = { CRITICAL: "C", HIGH: "H", MEDIUM: "M", LOW: "L", UNKNOWN: "U" };

function sevBadges(own, total) {
  const wrap = el("span", { className: "sevs" });
  for (const s of SEVERITIES) {
    if (!total[s]) continue;
    const b = el("span", { className: "sev" + (own[s] ? "" : " dim"), textContent: `${SEV_ABBR[s]} ${total[s]}`, title: `${s}: ${own[s] || 0} in this package, ${total[s]} including dependencies` });
    b.style.setProperty("--c", `var(${SEV_COLOR[s]})`);
    wrap.append(b);
  }
  return wrap;
}

const depTotal = (n) => SEVERITIES.reduce((t, s) => t + (n.totalCounts[s] || 0), 0);

const depQuery = () => dep.filter.trim().toLowerCase();
let graph = null;
let depDepth = null; // ref -> hops from the image root, for the layer bands

const worst = (counts) => SEVERITIES.find((s) => counts[s]);
const cssVar = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const sevWeight = (n) => ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].reduce((t, s, i) => t + (n.totalCounts[s] || 0) * [10000, 1000, 100, 10, 5][i], 0);

function computeDepths() {
  depDepth = new Map();
  const queue = [];
  for (const r of result.depRoots) { depDepth.set(r, 1); queue.push(r); }
  for (let i = 0; i < queue.length; i++) {
    for (const c of result.depNodes[queue[i]].children) {
      if (!depDepth.has(c)) { depDepth.set(c, depDepth.get(queue[i]) + 1); queue.push(c); }
    }
  }
}

// Which components to draw: filters, search, or the neighbourhood of the selection.
function visibleRefs() {
  const nodes = result.depNodes;
  const q = depQuery();
  let refs;
  if (dep.focus > 0 && dep.selected && nodes[dep.selected]) {
    const seen = new Map([[dep.selected, 0]]);
    const queue = [dep.selected];
    for (let i = 0; i < queue.length; i++) {
      const d = seen.get(queue[i]);
      if (d >= dep.focus) continue;
      const n = nodes[queue[i]];
      for (const x of [...n.children, ...n.parents]) if (!seen.has(x)) { seen.set(x, d + 1); queue.push(x); }
    }
    refs = [...seen.keys()];
  } else if (q) {
    const hits = Object.keys(nodes).filter((r) => (nodes[r].name + " " + nodes[r].version).toLowerCase().includes(q));
    const set = new Set(hits);
    for (const r of hits) { nodes[r].children.forEach((c) => set.add(c)); nodes[r].parents.forEach((p) => set.add(p)); }
    refs = [...set];
  } else {
    refs = Object.keys(nodes).filter((r) => {
      const n = nodes[r];
      return (dep.cat === "all" || n.category === dep.cat) && (!dep.vulnOnly || depTotal(n) > 0);
    });
  }
  let truncated = 0;
  if (refs.length > MAX_NODES) {
    truncated = refs.length - MAX_NODES;
    refs.sort((a, b) => sevWeight(nodes[b]) - sevWeight(nodes[a]));
    refs = refs.slice(0, MAX_NODES);
    if (dep.selected && !refs.includes(dep.selected) && nodes[dep.selected]) refs.push(dep.selected);
  }
  return { refs, truncated };
}

function renderDeps() {
  if (!result || !Object.keys(result.depNodes).length) return;
  if (!graph) {
    graph = new Graph($("dep-canvas"), { onSelect: (id) => selectDep(id === IMAGE_NODE ? null : id), onHover: showHover });
    window.__depGraph = graph; // handy for debugging in devtools
  }
  if (!depDepth) computeDepths();
  const { refs, truncated } = visibleRefs();
  const keep = new Set(refs);
  const q = depQuery();
  const colors = Object.fromEntries(SEVERITIES.map((s) => [s, cssVar(SEV_COLOR[s])]));
  const neutral = cssVar("--accent");
  const labelled = new Set([...refs].sort((x, y) => sevWeight(result.depNodes[y]) - sevWeight(result.depNodes[x])).slice(0, 12));
  const nodes = refs.map((r) => {
    const n = result.depNodes[r];
    const own = worst(n.ownCounts), tot = worst(n.totalCounts);
    return {
      id: r, label: n.name, sub: n.version, depth: depDepth.get(r) ?? 1,
      r: 5 + Math.min(11, Math.sqrt(depTotal(n)) * 1.6),
      fill: own ? colors[own] : n.category === "OS" ? "#6b7a99" : "#4a8f7a",
      ring: tot && !own ? colors[tot] : own ? colors[own] : null,
      shape: n.category === "OS" ? "square" : "circle",
      always: labelled.has(r) && depTotal(n) > 0,
      hl: !!q && (n.name + " " + n.version).toLowerCase().includes(q),
    };
  });
  const edges = [];
  for (const r of refs) for (const c of result.depNodes[r].children) if (keep.has(c)) edges.push([r, c]);
  nodes.push({ id: IMAGE_NODE, label: result.image, depth: 0, r: 10, fill: neutral, ring: null, shape: "square", always: true });
  for (const r of result.depRoots) if (keep.has(r)) edges.push([IMAGE_NODE, r]);

  graph.setData(nodes, edges);
  if (dep.selected && keep.has(dep.selected)) graph.select(dep.selected);
  else graph.select(null);
  $("dep-shown").textContent = `${refs.length} of ${Object.keys(result.depNodes).length} components` +
    (truncated ? ` · ${truncated} lower-risk hidden: search, filter or focus a node to see them` : "");
  renderDepDetail();
}

function showHover(id) {
  const n = id && result.depNodes[id];
  $("dep-hover").textContent = n ? `${n.name} ${n.version} — ${n.children.length} dependencies, required by ${n.parents.length}` : "";
}

// Select a component. If it is currently filtered out, relax the filters so it shows.
function selectDep(ref, center = false) {
  dep.selected = ref;
  if (ref) {
    const n = result.depNodes[ref];
    const { refs } = visibleRefs();
    if (!refs.includes(ref)) {
      dep.filter = ""; $("dep-filter").value = "";
      dep.cat = "all"; syncCat();
      if (!depTotal(n)) { dep.vulnOnly = false; $("dep-vuln-only").checked = false; }
      renderDeps();
    } else if (dep.focus > 0) {
      renderDeps(); // neighbourhood changes with the selection
    }
  } else if (dep.focus > 0) {
    dep.focus = 0; $("dep-focus").value = "0";
    renderDeps();
  }
  graph?.select(ref, { center });
  renderDepDetail();
}

function syncCat() {
  document.querySelectorAll("#dep-cat button").forEach((b) => b.classList.toggle("on", b.dataset.cat === dep.cat));
}

function renderDepDetail() {
  const box = $("dep-detail");
  const n = dep.selected && result.depNodes[dep.selected];
  if (!n) return box.replaceChildren(el("div", { className: "empty", textContent: "Click a node to inspect it." }));
  const links = (refs) =>
    refs.length
      ? refs.map((r) => {
          const x = result.depNodes[r];
          const l = el("div", { className: "link" }, el("span", { textContent: `${x.name} ${x.version}` }), sevBadges(x.ownCounts, x.totalCounts));
          l.addEventListener("click", () => selectDep(r, true));
          return l;
        })
      : [el("div", { className: "kv", textContent: "none" })];
  const vulns = n.own.map((i) => result.vulnerabilities[i]);
  box.replaceChildren(
    el("h3", { textContent: `${n.name} ${n.version}` }),
    el("div", { className: "kv", textContent: `${n.category} · ${n.type}` }),
    el("div", { className: "kv mono", textContent: n.purl }),
    el("h4", { textContent: `Vulnerabilities (${vulns.length}${depTotal(n) > vulns.length ? `, ${depTotal(n)} incl. dependencies` : ""})` }),
    ...(vulns.length
      ? vulns.map((v) => {
          const sev = el("span", { className: "sev", textContent: v.severity });
          sev.style.setProperty("--c", `var(${SEV_COLOR[v.severity]})`);
          return el("div", { className: "vrow" }, sev, el("span", { className: "mono", textContent: v.id }),
            el("span", { className: "kv", textContent: v.fixed ? `fixed in ${v.fixed}` : "no fix" }));
        })
      : [el("div", { className: "kv", textContent: "none in this package" })]),
    el("h4", { textContent: `Depends on (${n.children.length})` }), ...links(n.children),
    el("h4", { textContent: `Required by (${n.parents.length})` }), ...links(n.parents)
  );
}

$("dep-filter").addEventListener("input", (e) => { dep.filter = e.target.value; renderDeps(); });
$("dep-vuln-only").addEventListener("change", (e) => { dep.vulnOnly = e.target.checked; renderDeps(); });
$("dep-focus").addEventListener("change", (e) => { dep.focus = +e.target.value; renderDeps(); });
$("dep-fit").addEventListener("click", () => graph?.fit());
$("dep-labels").addEventListener("change", (e) => { if (graph) { graph.showLabels = e.target.checked ? "all" : "auto"; graph.draw(); } });
document.querySelectorAll("#dep-cat button").forEach((b) =>
  b.addEventListener("click", () => { dep.cat = b.dataset.cat; syncCat(); renderDeps(); })
);

async function render() {
  if (!$("cmp-repo").value) $("cmp-repo").value = result.image.replace(/@.*$/, "").replace(/:[^/:]*$/, "");
  await loadVEX();
  renderPrio();
  dep.selected = null; depDepth = null;
  $("dep-count").textContent = Object.keys(result.depNodes).length;
  renderDeps();
  $("meta").textContent = `${result.image}${result.os ? " · " + result.os : ""}`;
  renderVulns();
  renderSBOM();
}

$("vuln-filter").addEventListener("input", (e) => { vulnState.filter = e.target.value; renderVulns(); });
$("sbom-filter").addEventListener("input", (e) => { sbomState.filter = e.target.value; renderSBOM(); });
wireSort($("vuln-table"), vulnState, renderVulns);
wireSort($("sbom-table"), sbomState, renderSBOM);

// ---- image compare ----
const CHG_COLOR = { added: "--CRITICAL", removed: "#2fb344", unchanged: "--UNKNOWN", upgraded: "--accent", downgraded: "--HIGH" };
const CHG_SIGN = { added: "+", removed: "−", unchanged: "=", upgraded: "↑", downgraded: "↓" };
const cmp = { data: null, view: "vulns", show: new Set(["added", "removed"]), filter: "" };
const colorVal = (c) => (c.startsWith("--") ? `var(${c})` : c);

$("cmp-repo").value = lsGet("cmp-repo");
$("cmp-a").value = lsGet("cmp-a");
$("cmp-b").value = lsGet("cmp-b");
const cmpBusy = (on, msg = "") => {
  $("cmp-go").disabled = on;
  $("cmp-cancel").hidden = !on;
  if (on) setStatus(msg || "Comparing…", { busy: true });
};

$("cmp-load").addEventListener("click", async () => {
  $("cmp-note").textContent = "Loading tags…";
  try {
    const tags = await call("ListTags", $("cmp-repo").value);
    $("cmp-tags").replaceChildren(...tags.map((t) => el("option", { value: t })));
    $("cmp-note").textContent = `${tags.length} tags loaded (newest first, by name) — type to filter.`;
  } catch (e) {
    $("cmp-note").textContent = "Could not list tags — type them in. " + (e.message || e);
  }
});
$("cmp-cancel").addEventListener("click", () => call("Cancel"));

$("cmp-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const req = {
    repo: $("cmp-repo").value, tagA: $("cmp-a").value, tagB: $("cmp-b").value,
    username: $("username").value, password: $("password").value, ignoreUnfixed: $("ignore-unfixed").checked,
    trivyImage: $("trivy-image").value.trim(),
  };
  for (const k of ["repo", "a", "b"]) lsSet("cmp-" + k, $("cmp-" + k).value);
  $("log").textContent = "";
  cmpBusy(true, "Scanning both images…");
  $("scan-btn").disabled = true;
  try {
    cmp.data = await call("Compare", req);
    renderCompare();
    setStatus("Comparison complete.");
  } catch (err) {
    setStatus(String(err.message || err), { err: true });
  } finally {
    cmpBusy(false);
    $("scan-btn").disabled = false;
  }
});

function deltaEl(a, b, lowerIsBetter = true) {
  const d = b - a;
  const good = lowerIsBetter ? d < 0 : d > 0;
  return el("span", { className: "delta " + (d === 0 ? "flat" : good ? "good" : "bad"), textContent: d === 0 ? "±0" : (d > 0 ? "+" : "−") + Math.abs(d) });
}

function sideBox(title, s, other, isTarget) {
  const box = el("div", { className: "side" }, el("h4", { textContent: `${title}: ${s.ref}` }),
    el("div", { className: "kv", textContent: `${s.os || "unknown OS"} · ${s.packages} packages · ${s.total} vulnerabilities${s.kev ? ` · ${s.kev} KEV` : ""}` }));
  for (const sev of SEVERITIES) {
    const sevEl = el("span", { className: "sev", textContent: sev });
    sevEl.style.setProperty("--c", `var(${SEV_COLOR[sev]})`);
    const row = el("div", { className: "sevrow" }, sevEl, el("span", { className: "n", textContent: s.counts[sev] || 0 }));
    if (isTarget) row.append(deltaEl(other.counts[sev] || 0, s.counts[sev] || 0));
    box.append(row);
  }
  return box;
}

function renderCompare() {
  const d = cmp.data;
  const sum = (m) => Object.values(m).reduce((x, y) => x + y, 0);
  const out = $("cmp-out");
  const net = sum(d.added) - sum(d.removed);
  const verdict = el("div", { className: "verdict", textContent: d.verdict });
  verdict.style.setProperty("--c", net < 0 ? "#2fb344" : net > 0 ? "var(--CRITICAL)" : "var(--mute)");

  const controls = el("div", { className: "cmp-controls" });
  const seg = el("div", { className: "seg" });
  for (const [k, l] of [["vulns", `Vulnerabilities (${d.vulns.length})`], ["pkgs", `Packages (${d.packages.length})`]]) {
    const b = el("button", { type: "button", textContent: l, className: cmp.view === k ? "on" : "" });
    b.addEventListener("click", () => { cmp.view = k; renderCompare(); });
    seg.append(b);
  }
  controls.append(seg);
  const kinds = cmp.view === "vulns" ? ["added", "removed", "unchanged"] : ["added", "removed", "upgraded", "downgraded"];
  const counts = {};
  for (const x of cmp.view === "vulns" ? d.vulns : d.packages) counts[x.change] = (counts[x.change] || 0) + 1;
  for (const k of kinds) {
    const cb = el("input", { type: "checkbox", checked: cmp.show.has(k) });
    cb.addEventListener("change", () => { cb.checked ? cmp.show.add(k) : cmp.show.delete(k); renderCompare(); });
    const tag = el("span", { className: "chg", textContent: CHG_SIGN[k] });
    tag.style.setProperty("--c", colorVal(CHG_COLOR[k]));
    controls.append(el("label", { className: "chk" }, cb, tag, `${k} (${counts[k] || 0})`));
  }
  const q = el("input", { placeholder: "Filter…", value: cmp.filter, autocomplete: "off" });
  q.addEventListener("input", () => { cmp.filter = q.value; renderCmpTable(); });
  controls.append(q);

  out.replaceChildren(
    el("div", { className: "sides" }, sideBox("Base", d.a, d.b, false), sideBox("Target", d.b, d.a, true)),
    verdict, controls, el("div", { className: "table-wrap cmp-table", id: "cmp-table" })
  );
  renderCmpTable();
  q.focus({ preventScroll: true });
  q.setSelectionRange(q.value.length, q.value.length);
}

function renderCmpTable() {
  const d = cmp.data;
  const q = cmp.filter.toLowerCase();
  const wrap = $("cmp-table");
  const chg = (c) => {
    const s = el("span", { className: "chg", textContent: CHG_SIGN[c], title: c });
    s.style.setProperty("--c", colorVal(CHG_COLOR[c]));
    return s;
  };
  const arrow = (a, b) => (a && b ? `${a} → ${b}` : a || b || "—");
  let head, rows;
  if (cmp.view === "vulns") {
    head = ["", "Severity", "ID", "Package", "Version", "Why", "Signals"];
    rows = d.vulns.filter((x) => cmp.show.has(x.change) && (!q || [x.vuln.id, x.vuln.package, x.cause, x.vuln.title].join(" ").toLowerCase().includes(q))).map((x) => {
      const sev = el("span", { className: "sev", textContent: x.vuln.severity });
      sev.style.setProperty("--c", `var(${SEV_COLOR[x.vuln.severity]})`);
      const sig = el("td", {});
      if (x.vuln.kev) sig.append(chip("KEV", "hot"), " ");
      if (x.vuln.hasEpss && x.vuln.epss >= 0.1) sig.append(chip("EPSS " + pct(x.vuln.epss), "warm"));
      return el("tr", {}, el("td", {}, chg(x.change)), el("td", {}, sev), el("td", { className: "mono", textContent: x.vuln.id }),
        el("td", { className: "mono", textContent: x.vuln.package }), el("td", { className: "mono", textContent: arrow(x.versionA, x.versionB) }),
        el("td", { textContent: x.cause }), sig);
    });
  } else {
    head = ["", "Package", "Kind", "Version", "Vulnerabilities"];
    rows = d.packages.filter((x) => cmp.show.has(x.change) && (!q || x.name.toLowerCase().includes(q))).map((x) => {
      const vd = el("td", {}, `${x.vulnsA} → ${x.vulnsB} `, deltaEl(x.vulnsA, x.vulnsB));
      return el("tr", {}, el("td", {}, chg(x.change)), el("td", { className: "mono", textContent: x.name }),
        el("td", { textContent: x.category === "OS" ? "OS" : x.type }), el("td", { className: "mono", textContent: arrow(x.versionA, x.versionB) }), vd);
    });
  }
  const table = el("table", {}, el("thead", {}, el("tr", {}, ...head.map((h) => el("th", { textContent: h, style: "cursor:default" })))), el("tbody", {}, ...rows));
  wrap.replaceChildren(table, rows.length ? "" : el("div", { className: "empty", textContent: "Nothing to show with these filters." }));
}

// The Trivy version is a preference, not a secret: remember it between runs.
$("trivy-image").value = lsGet("trivy-image");
$("trivy-image").addEventListener("change", () => lsSet("trivy-image", $("trivy-image").value.trim()));
