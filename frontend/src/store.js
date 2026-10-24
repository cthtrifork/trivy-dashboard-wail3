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
// Saved VEX assessments for the scanned image repo, finding key -> entry. Replaced, never mutated.
export const vex = shallowRef(new Map());

// Findings whose VEX editor the user has opened.
export const openVex = new Set();

export const status = reactive({ msg: "", err: false, busy: false });
export function setStatus(msg, { err = false, busy = false } = {}) {
  Object.assign(status, { msg, err, busy });
}

export const logText = ref("");
Events.On("scan:log", (ev) => {
  const line = Array.isArray(ev.data) ? ev.data[0] : ev.data;
  logText.value += line + "\n";
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
    await loadVEX();
    setStatus(`Scan complete: ${r.vulnerabilities.length} vulnerabilities, ${r.components.length} components.`);
  } catch (err) {
    setStatus(errText(err), { err: true });
  } finally {
    scanning.value = false;
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
  ScanService.PodmanVersion().then((v) => setStatus(v), (err) => setStatus(errText(err), { err: true }));
}
