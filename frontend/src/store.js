// Shared state and the calls into the Go ScanService. A plain module of refs instead of a store
// library: the app has one scan result and a handful of settings.
import { reactive, ref, shallowRef } from "vue";
import { Events } from "@wailsio/runtime";
import { ScanService } from "../bindings/github.com/cthtrifork/trivy-dashboard-wail3";

export { ScanService };

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
export const SEV_COLOR = { CRITICAL: "--CRITICAL", HIGH: "--HIGH", MEDIUM: "--MEDIUM", LOW: "--LOW", UNKNOWN: "--UNKNOWN" };
export const sevStyle = (sev) => ({ "--c": `var(${SEV_COLOR[sev]})` });
export const errText = (e) => String(e?.message || e);

export const lsGet = (k) => { try { return localStorage.getItem(k) || ""; } catch { return ""; } };
export const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* ignore */ } };

// The latest scan. Shallow: the dependency graph holds thousands of read-only objects.
export const result = shallowRef(null);
// The findings in the order the current scoring rules rank them: the scan result's own list when
// the rules are the defaults, otherwise the same findings with the priority, tier and reasons
// the Go side computed under the rules (see rerank).
export const vulns = shallowRef([]);
// Saved VEX assessments for the scanned image repo, finding key -> entry. Replaced, never mutated.
export const vex = shallowRef(new Map());

// Findings whose VEX editor the user has opened.
export const openVex = new Set();

// Scoring rules. `rules` is the live set the Go side applies; presets are named copies of it.
// Built-in presets come from Go; the user's own live in localStorage next to the Trivy version.
export const rules = reactive({});
export const builtinPresets = ref([]);
export const userPresets = ref([]);
const RULES_KEY = "score-rules", PRESETS_KEY = "score-presets";
const lsJSON = (k, fallback) => { try { return JSON.parse(lsGet(k)) ?? fallback; } catch { return fallback; } };
const rulesJSON = (r) => JSON.stringify(Object.keys(r).sort().map((k) => [k, r[k]]));
export const allPresets = () => [...builtinPresets.value, ...userPresets.value];
// The preset the live rules equal exactly, or null once the user has changed anything.
export const activePreset = () => allPresets().find((p) => rulesJSON(p.rules) === rulesJSON(rules))?.name ?? null;

let rankToken = 0;
// rerank asks Go to rank the latest scan under the live rules. Calls that are superseded (the user
// kept dragging a threshold, or rescanned) are dropped.
export async function rerank() {
  const r = result.value, token = ++rankToken;
  if (!r) return void (vulns.value = []);
  if (!builtinPresets.value.length || rulesJSON(rules) === rulesJSON(builtinPresets.value[0].rules)) {
    vulns.value = r.vulnerabilities; // the scan already used the default rules
    return;
  }
  try {
    const out = await ScanService.Rescore({ ...rules });
    if (token !== rankToken || out.length !== r.vulnerabilities.length) return;
    vulns.value = out.map((o) => ({ ...r.vulnerabilities[o.index], priority: o.priority, tier: o.tier, tierWhy: o.tierWhy, reasons: o.reasons }));
  } catch (err) {
    setStatus("Could not apply the scoring rules: " + errText(err), { err: true });
  }
}

let rerankTimer;
export function setRules(next) {
  Object.assign(rules, next);
  lsSet(RULES_KEY, JSON.stringify(rules));
  clearTimeout(rerankTimer);
  rerankTimer = setTimeout(rerank, 120); // typing a threshold fires once per pause, not per keystroke
}

export function savePreset(name, description = "") {
  name = name.trim();
  if (!name || builtinPresets.value.some((p) => p.name === name)) return false;
  const entry = { name, description, rules: { ...rules } };
  userPresets.value = [...userPresets.value.filter((p) => p.name !== name), entry];
  lsSet(PRESETS_KEY, JSON.stringify(userPresets.value));
  return true;
}
export function deletePreset(name) {
  userPresets.value = userPresets.value.filter((p) => p.name !== name);
  lsSet(PRESETS_KEY, JSON.stringify(userPresets.value));
}

async function initRules() {
  try {
    builtinPresets.value = (await ScanService.RulePresets()) || [];
  } catch (err) {
    return setStatus("Could not load scoring presets: " + errText(err), { err: true });
  }
  userPresets.value = lsJSON(PRESETS_KEY, []).filter((p) => p?.name && p.rules);
  // Merge over the defaults so a rule added in a later version still has a value.
  Object.assign(rules, builtinPresets.value[0].rules, lsJSON(RULES_KEY, {}));
  rerank();
}

export const status = reactive({ msg: "", err: false, busy: false });
export function setStatus(msg, { err = false, busy = false } = {}) {
  Object.assign(status, { msg, err, busy });
}

export const logText = ref("");
// Trivy can be chatty on big images: keep the tail only, so the log <pre> stays bounded.
const LOG_MAX = 400_000, LOG_KEEP = 300_000;
Events.On("scan:log", (ev) => {
  const line = Array.isArray(ev.data) ? ev.data[0] : ev.data;
  let text = logText.value + line + "\n";
  if (text.length > LOG_MAX) text = text.slice(text.indexOf("\n", text.length - LOG_KEEP) + 1);
  logText.value = text;
  if (scanning.value) setStatus(String(line).slice(0, 200), { busy: true });
});

// Options shared by Scan and Compare.
export const opts = reactive({
  ignoreUnfixed: false,
  username: "",
  password: "",
  // The Trivy version is a preference, not a secret: remember it between runs.
  trivyImage: lsGet("trivy-image"),
});
export const saveTrivyImage = () => lsSet("trivy-image", opts.trivyImage.trim());

export const image = ref("");
export const cmpForm = reactive({ repo: lsGet("cmp-repo"), a: lsGet("cmp-a"), b: lsGet("cmp-b") });

// scanning is true while any scan runs (single scan or compare); comparing marks the latter.
export const scanning = ref(false);
export const comparing = ref(false);

export const mode = ref(null);
export const appInfo = ref(null);
export const footprint = ref(null);

export const refreshFootprint = () => ScanService.Footprint().then((f) => (footprint.value = f), () => {});

export async function loadVEX() {
  const m = new Map();
  try {
    for (const e of (await ScanService.VEXList(result.value.image)) || []) m.set(e.key, e);
  } catch (err) {
    setStatus("Could not load VEX assessments: " + errText(err), { err: true });
  }
  vex.value = m;
}

export async function runScan() {
  scanning.value = true;
  logText.value = "";
  setStatus("Starting scan…", { busy: true });
  try {
    const r = await ScanService.Scan({
      image: image.value,
      username: opts.username,
      password: opts.password,
      ignoreUnfixed: opts.ignoreUnfixed,
      trivyImage: opts.trivyImage.trim(),
    });
    if (!cmpForm.repo) cmpForm.repo = r.image.replace(/@.*$/, "").replace(/:[^/:]*$/, "");
    result.value = r;
    rerank();
    await loadVEX();
    setStatus(`Scan complete: ${r.vulnerabilities.length} vulnerabilities, ${r.components.length} components.`);
  } catch (err) {
    setStatus(errText(err), { err: true });
  } finally {
    scanning.value = false;
    refreshFootprint(); // a scan may have downloaded the DB
  }
}

export const cancel = () => ScanService.Cancel();

export function init() {
  // The Go side decides whether this build may update itself (release builds only).
  ScanService.UpdateInfo().then((u) => (appInfo.value = u), () => {});
  // Development builds replay recorded scans: say so, and prefill the inputs with something that works.
  ScanService.Mode().then((m) => {
    mode.value = m;
    if (!m.fixtures) return;
    if (!image.value) image.value = m.image;
    if (!cmpForm.repo) cmpForm.repo = m.repo;
    if (!cmpForm.a) cmpForm.a = m.tagA;
    if (!cmpForm.b) cmpForm.b = m.tagB;
  }, () => {});
  refreshFootprint();
  initRules();
  ScanService.PodmanVersion().then((v) => setStatus(v), (err) => setStatus(errText(err), { err: true }));
}
