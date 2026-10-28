// Shared state and the calls into the Go ScanService. A plain module of refs instead of a store
// library: the app has one scan result and a handful of settings.
import { computed, reactive, ref, shallowRef, watch } from "vue";
import { Events } from "@wailsio/runtime";
import { ScanService } from "../bindings/github.com/cthtrifork/trivy-dashboard-wail3/internal/app";

export { ScanService };

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
export const SEV_COLOR = { CRITICAL: "--CRITICAL", HIGH: "--HIGH", MEDIUM: "--MEDIUM", LOW: "--LOW", UNKNOWN: "--UNKNOWN" };
export const sevStyle = (sev) => ({ "--c": `var(${SEV_COLOR[sev]})`, "--on": `var(--on${SEV_COLOR[sev]})` });
export const errText = (e) => String(e?.message || e);

export const lsGet = (k) => {
  try {
    return localStorage.getItem(k) || "";
  } catch {
    return "";
  }
};
export const lsSet = (k, v) => {
  try {
    localStorage.setItem(k, v);
  } catch {
    /* ignore */
  }
};

// The latest scan. Shallow: the dependency graph holds thousands of read-only objects.
export const result = shallowRef(null);
// Findings of the latest scan by CVE id, one per VEX key (a finding repeated across image layers counts once),
// so the VEX editor can offer the other components that carry the same CVE.
export const findingsById = computed(() => {
  const m = new Map();
  for (const v of result.value?.vulnerabilities ?? []) {
    const list = m.get(v.id) ?? m.set(v.id, new Map()).get(v.id);
    if (!list.has(v.key)) list.set(v.key, v);
  }
  return m;
});

// The findings in the order the current scoring rules rank them: the scan result's own list when
// the rules are the defaults, otherwise the same findings with the priority, tier and reasons
// the Go side computed under the rules (see rerank).
export const vulns = shallowRef([]);
// Saved VEX assessments for the scanned image repo, finding key -> entry. Replaced, never mutated.
export const vex = shallowRef(new Map());

// The finding open in the VEX assess drawer, or null when it is closed.
export const assessing = shallowRef(null);

// Scoring rules. `rules` is the live set the Go side applies; presets are named copies of it.
// Built-in presets come from Go; the user's own live in localStorage next to the Trivy version.
export const rules = reactive({});
export const builtinPresets = ref([]);
export const userPresets = ref([]);
const RULES_KEY = "score-rules",
  PRESETS_KEY = "score-presets";
const lsJSON = (k, fallback) => {
  try {
    return JSON.parse(lsGet(k)) ?? fallback;
  } catch {
    return fallback;
  }
};
const rulesJSON = (r) =>
  JSON.stringify(
    Object.keys(r)
      .sort()
      .map((k) => [k, r[k]]),
  );
export const allPresets = () => [...builtinPresets.value, ...userPresets.value];
// The preset the live rules equal exactly, or null once the user has changed anything.
export const activePreset = () => allPresets().find((p) => rulesJSON(p.rules) === rulesJSON(rules))?.name ?? null;

let rankToken = 0;
// rerank asks Go to rank the latest scan under the live rules. Calls that are superseded (the user
// kept dragging a threshold, or rescanned) are dropped.
export async function rerank() {
  const r = result.value,
    token = ++rankToken;
  if (!r) return void (vulns.value = []);
  if (!builtinPresets.value.length || rulesJSON(rules) === rulesJSON(builtinPresets.value[0].rules)) {
    vulns.value = r.vulnerabilities; // the scan already used the default rules
    return;
  }
  try {
    const out = await ScanService.Rescore({ ...rules });
    if (token !== rankToken || out.length !== r.vulnerabilities.length) return;
    vulns.value = out.map((o) => ({
      ...r.vulnerabilities[o.index],
      priority: o.priority,
      tier: o.tier,
      tierWhy: o.tierWhy,
      reasons: o.reasons,
    }));
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
const LOG_MAX = 400_000,
  LOG_KEEP = 300_000;
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
  // Trivy-side noise: ignored by default.
  showSuppressed: false,
  ignoreWillNotFix: true,
  ignoreNotAffected: true,
  markUnderInvestigation: false,
  username: "",
  password: "",
  // The Trivy version is a preference, not a secret: remember it between runs.
  trivyImage: lsGet("trivy-image"),
  // Rego source for Trivy's --ignore-policy; also a preference, kept between runs.
  ignorePolicy: lsGet("ignore-policy"),
  // YAML for Trivy's --ignorefile (.trivyignore.yaml); likewise remembered.
  ignoreFile: lsGet("ignore-file"),
});
export const saveTrivyImage = () => lsSet("trivy-image", opts.trivyImage.trim());
// Quick sanity checks of the two texts, run by Go as the user types (empty means fine). Trivy
// stays the authority: these only catch the usual mistakes before a scan starts.
export const ignorePolicyError = ref("");
export const ignoreFileError = ref("");
function checkWhileTyping(source, check, error) {
  let timer;
  watch(
    source,
    (text) => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        try {
          error.value = await check(text);
        } catch {
          error.value = "";
        }
      }, 300);
    },
    { immediate: true },
  );
}
checkWhileTyping(() => opts.ignorePolicy, ScanService.CheckIgnorePolicy, ignorePolicyError);
checkWhileTyping(() => opts.ignoreFile, ScanService.CheckIgnoreFile, ignoreFileError);

export const saveIgnorePolicy = () => lsSet("ignore-policy", opts.ignorePolicy);
export const saveIgnoreFile = () => lsSet("ignore-file", opts.ignoreFile);
// loadIgnorePolicyFile and loadIgnoreFile fill the text from a file the user picked.
export async function loadIgnorePolicyFile(file) {
  if (!file) return;
  opts.ignorePolicy = await file.text();
  saveIgnorePolicy();
}
export async function loadIgnoreFile(file) {
  if (!file) return;
  opts.ignoreFile = await file.text();
  saveIgnoreFile();
}

// The scanned image survives a reload: the last scan's input and result are kept in localStorage,
// and the URL hash (#image=...) names the image so a reload or shared link shows or reruns it.
const IMAGE_KEY = "image",
  RESULT_KEY = "last-result";
const hashImage = () => new URLSearchParams(location.hash.slice(1)).get("image") || "";
const setHashImage = (img) => {
  try {
    history.replaceState(null, "", img ? "#image=" + encodeURIComponent(img) : location.pathname + location.search);
  } catch {
    /* ignore */
  }
};
export const image = ref(hashImage() || lsGet(IMAGE_KEY));

// Images scanned before, newest first, so a rescan is one pick instead of retyping the reference.
const RECENT_KEY = "recent-images",
  RECENT_MAX = 8;
export const recent = ref(lsJSON(RECENT_KEY, []).filter((e) => e?.image));
function remember(ref, r) {
  const entry = { image: ref, at: Date.now(), crit: r.severityCounts?.CRITICAL || 0, high: r.severityCounts?.HIGH || 0 };
  recent.value = [entry, ...recent.value.filter((e) => e.image !== ref)].slice(0, RECENT_MAX);
  lsSet(RECENT_KEY, JSON.stringify(recent.value));
}
// Compare: the base is the image at the top (read only); only the target tag is its own.
export const cmpForm = reactive({ b: lsGet("cmp-b") });

// The last comparison, kept here so a new scan can clear it.
export const compareData = shallowRef(null);

// fillLatestTag looks up the repository's newest semver tag (a registry lookup, not a scan) and
// puts it in the Target box (with the base tag's suffix, e.g. -alpine, when one exists). A failed lookup leaves it as is.
async function fillLatestTag(repo, baseTag) {
  if (!repo) return;
  try {
    const latest = await ScanService.LatestTag(repo, baseTag);
    if (latest && imageRepo.value === repo) cmpForm.b = latest;
  } catch {
    /* the user can still type the tag */
  }
}

// After a scan the image box splits into the repository (read only) and an editable tag with the
// registry's tags to pick from; Clear goes back to the single box. image stays the one reference a scan uses.
export const split = ref(false);
// splitRef splits a reference into repository and tag, or digest when it names one (the digest wins
// over a tag beside it, since it is what gets scanned). It is SplitImage without a call per keystroke.
export function splitRef(ref) {
  const [name, digest] = ref.trim().split("@");
  const i = name.lastIndexOf(":");
  const tagged = i > name.lastIndexOf("/");
  return { repo: tagged ? name.slice(0, i) : name, tag: digest || (tagged ? name.slice(i + 1) : "") };
}
// joinRef is the inverse: a "sha256:..." tag is a digest and joins with "@".
export const joinRef = (repo, tag) => (!tag ? repo : tag.startsWith("sha256:") ? repo + "@" + tag : repo + ":" + tag);
export const imageRepo = ref("");
export const imageTag = ref("");
export const repoTags = ref([]); // newest first, as ListTags returns them
export const trivyTags = ref([]); // the same for the Trivy version option

// tagLoader returns a function that loads the registry's tags for a repository into target once;
// a failed lookup leaves the list empty (tags can still be typed).
function tagLoader(target) {
  let loadedFor = "";
  return async (repo) => {
    if (!repo || loadedFor === repo) return;
    loadedFor = repo;
    target.value = [];
    try {
      const tags = (await ScanService.ListTags(repo)) || [];
      if (loadedFor === repo) target.value = tags;
    } catch {
      loadedFor = ""; // try again on the next open
    }
  };
}
export const ensureTags = tagLoader(repoTags);
const loadTrivyTags = tagLoader(trivyTags);
// ensureTrivyTags loads the tags of the default Trivy repository for the version picker.
export const ensureTrivyTags = () => loadTrivyTags((mode.value?.trivyImage || "docker.io/aquasec/trivy").replace(/:[^/:]*$/, ""));

// trivyNewest is the newest plain version found in the Trivy repository ("0.76.1": not the floating
// "latest" tag). The list is sorted newest plain version first. Empty until the lookup succeeds.
export const trivyNewest = computed(() => trivyTags.value.find((t) => /^\d+(\.\d+)+$/.test(t)) || "");
// The field is never left empty: once the newest version is known it is filled in, unless the user
// has chosen one. It is not saved until the user edits it, so the default keeps following the newest.
watch(trivyNewest, (v) => {
  if (v && !opts.trivyImage.trim()) opts.trivyImage = v;
});
// trivyImageSetting is what scans send: the user's choice, else the newest version found, else
// empty so the backend falls back to its Renovate-managed default.
export const trivyImageSetting = () => opts.trivyImage.trim() || trivyNewest.value;

export function enterSplit(repo, tag) {
  if (!repo) return;
  split.value = true;
  imageRepo.value = repo;
  imageTag.value = tag;
  ensureTags(repo);
}

// The compare base: the split view's repository and tag, or the single box read the same way.
export const cmpBase = computed(() => (split.value ? { repo: imageRepo.value, tag: imageTag.value } : splitRef(image.value)));

// setTag edits the tag for the next scan. What is shown stays until a scan replaces it or Clear removes it.
export function setTag(tag) {
  imageTag.value = tag;
  image.value = joinRef(imageRepo.value, tag);
}

// scanState tells the three situations apart: "new" (nothing scanned), "current" (the shown results are
// for exactly this input, so Scan is a rescan, e.g. for a floating tag) and "changed" (edited since, not scanned).
const sameRef = (a, b) => {
  const x = splitRef(a),
    y = splitRef(b);
  return joinRef(x.repo, x.tag) === joinRef(y.repo, y.tag);
};
export const scanState = computed(() => (!result.value ? "new" : sameRef(result.value.image, image.value) ? "current" : "changed"));

// clearAll empties the shown findings and goes back to the single image box (which keeps the reference).
export function clearAll() {
  split.value = false;
  result.value = null;
  compareData.value = null;
  vex.value = new Map();
  try {
    localStorage.removeItem(RESULT_KEY);
  } catch {
    /* ignore */
  }
  setHashImage("");
  rerank();
  setStatus("Cleared.");
}

// scanning is true while any scan runs (single scan or compare); comparing marks the latter.
export const scanning = ref(false);
export const comparing = ref(false);

export const mode = ref(null);
export const appInfo = ref(null);
export const footprint = ref(null);

export const refreshFootprint = () =>
  ScanService.Footprint().then(
    (f) => (footprint.value = f),
    () => {},
  );

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
  compareData.value = null;
  const { repo, tag } = splitRef(image.value);
  cmpForm.b = "";
  enterSplit(repo, tag);
  fillLatestTag(repo, tag);
  refreshFootprint(); // recalculate now; it is measured again when the scan ends
  logText.value = "";
  vex.value = new Map(); // the backend drops the saved VEX file when a scan starts
  result.value = null; // don't show the previous image's findings while the new scan runs
  rerank();
  setStatus("Starting scan…", { busy: true });
  try {
    const r = await ScanService.Scan({
      image: image.value,
      username: opts.username,
      password: opts.password,
      ignoreUnfixed: opts.ignoreUnfixed,
      showSuppressed: opts.showSuppressed,
      showWillNotFix: !opts.ignoreWillNotFix,
      showNotAffected: !opts.ignoreNotAffected,
      trivyImage: trivyImageSetting(),
      ignorePolicy: opts.ignorePolicy,
      ignoreFile: opts.ignoreFile,
      markUnderInvestigation: opts.markUnderInvestigation,
    });
    result.value = r;
    rememberScan(r);
    remember(image.value.trim(), r);
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

// rememberScan keeps the scan for the next reload. A result too big for the quota is dropped, not left stale.
function rememberScan(r) {
  const img = image.value.trim();
  lsSet(IMAGE_KEY, img);
  setHashImage(img);
  try {
    localStorage.setItem(RESULT_KEY, JSON.stringify({ forImage: img, result: r }));
  } catch {
    try {
      localStorage.removeItem(RESULT_KEY);
    } catch {
      /* ignore */
    }
  }
}

// restoreScan shows the remembered result when it belongs to the image being asked for, and
// otherwise reruns the scan when the URL hash names an image.
async function restoreScan() {
  const want = image.value.trim();
  if (!want) return;
  const saved = lsJSON(RESULT_KEY, null);
  if (saved?.result && saved.forImage === want) {
    result.value = saved.result;
    const { repo, tag } = splitRef(want);
    enterSplit(repo, tag);
    rerank();
    await loadVEX();
    setStatus(`Restored the last scan of ${want}.`);
  } else if (hashImage()) {
    runScan();
  }
}

export const cancel = () => ScanService.Cancel();

export function init() {
  // The Go side decides whether this build may update itself (release builds only).
  ScanService.UpdateInfo().then(
    (u) => (appInfo.value = u),
    () => {},
  );
  // Development builds replay recorded scans: say so, and prefill the inputs with something that works.
  ScanService.Mode().then(
    (m) => {
      mode.value = m;
      ensureTrivyTags(); // so the default can be the newest version
      if (!m.fixtures) return;
      if (!image.value) image.value = m.image;
      if (!cmpForm.b) cmpForm.b = m.tagB;
    },
    () => {},
  );
  refreshFootprint();
  initRules();
  restoreScan();
  ScanService.PodmanVersion().then(
    (v) => !result.value && !scanning.value && setStatus(v),
    (err) => setStatus(errText(err), { err: true }),
  );
}
