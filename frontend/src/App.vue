<script setup>
import { computed, nextTick, onMounted, ref, watch } from "vue";
import {
  ScanService,
  sevStyle,
  result,
  image,
  recent,
  opts,
  saveTrivyImage,
  saveIgnorePolicy,
  loadIgnorePolicyFile,
  saveIgnoreFile,
  loadIgnoreFile,
  ignorePolicyError,
  ignoreFileError,
  scanning,
  comparing,
  status,
  logText,
  mode,
  appInfo,
  footprint,
  runScan,
  cancel,
  init,
  setStatus,
  errText,
} from "./store.js";
import { ago, bytes } from "./lib/format.js";
import PrioritiesPanel from "./components/PrioritiesPanel.vue";
import VulnsPanel from "./components/VulnsPanel.vue";
import DepsPanel from "./components/DepsPanel.vue";
import SbomPanel from "./components/SbomPanel.vue";
import ComparePanel from "./components/ComparePanel.vue";
import VexDialog from "./components/VexDialog.vue";
import VexDrawer from "./components/VexDrawer.vue";
import HelpDialog from "./components/HelpDialog.vue";

const tab = ref("prio");
const prio = ref(null);
const vexDialog = ref(null);
const helpDialog = ref(null);
const logEl = ref(null);

// Recent images under the input: filtered by what is typed, driven from the keyboard like a combobox.
const histOpen = ref(false);
const histIdx = ref(-1);
const history = computed(() => {
  const q = image.value.trim().toLowerCase();
  return recent.value.filter((e) => e.image.toLowerCase().includes(q) && e.image !== image.value.trim());
});
const showHistory = computed(() => histOpen.value && history.value.length > 0);
function onImageInput() {
  histOpen.value = true;
  histIdx.value = -1;
}
const closeHistory = () => {
  histOpen.value = false;
  histIdx.value = -1;
};
function pickRecent(e, rescan) {
  image.value = e.image;
  closeHistory();
  if (rescan && !scanning.value) runScan();
}
function imageKey(ev) {
  const n = history.value.length;
  if (ev.key === "Escape") return closeHistory();
  if (!n || (ev.key !== "ArrowDown" && ev.key !== "ArrowUp" && ev.key !== "Enter" && ev.key !== "Tab")) return;
  if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
    ev.preventDefault();
    histOpen.value = true;
    const step = ev.key === "ArrowDown" ? 1 : -1;
    histIdx.value = ((histIdx.value + 1 + step + n + 1) % (n + 1)) - 1; // -1 is the typed text
  } else if (histIdx.value >= 0 && showHistory.value) {
    if (ev.key === "Enter") ev.preventDefault();
    pickRecent(history.value[histIdx.value], ev.key === "Enter");
  }
}
const sevTag = (n, sev) => ({ n, sev, style: sevStyle(sev) });

const trivyPlaceholder = computed(() =>
  mode.value?.trivyImage
    ? "Trivy version or image (default " + mode.value.trivyImage.split("/").pop() + ")"
    : "Trivy version or image (default)",
);
const meta = computed(() => (result.value ? `${result.value.image}${result.value.os ? " · " + result.value.os : ""}` : ""));
const counts = computed(() => ({
  vulns: result.value?.vulnerabilities.length ?? 0,
  deps: Object.keys(result.value?.depNodes ?? {}).length,
  sbom: result.value?.components.length ?? 0,
}));

const footprintNote = computed(() => {
  const f = footprint.value;
  if (!f) return "";
  const cache = f.cacheBytes < 0 ? `Trivy cache in podman volume ${f.cacheLocation}` : `Trivy cache ${bytes(f.cacheBytes)}`;
  const mem =
    f.webviewBytes < 0
      ? `~${bytes(f.memoryBytes)} app memory (excl. webview and podman)`
      : `~${bytes(f.memoryBytes)} app + ~${bytes(f.webviewBytes)} webview memory (excl. podman)`;
  return `Footprint: ${cache} · ${mem}`;
});

// Updating is three clicks, never automatic: check, then download, then restart.
const update = ref({ step: "idle", version: "" }); // idle | available | ready
const updateBusy = ref(false);

async function updateStep(busyMsg, run) {
  updateBusy.value = true;
  setStatus(busyMsg, { busy: true });
  try {
    await run();
  } catch (err) {
    setStatus(errText(err), { err: true });
  } finally {
    updateBusy.value = false;
  }
}

const checkForUpdates = () =>
  updateStep("Checking for updates…", async () => {
    const r = await ScanService.CheckForUpdates();
    update.value = r.available ? { step: "available", version: r.version } : { step: "idle", version: "" };
    setStatus(r.available ? `Version ${r.version} is available.` : "You are on the latest version.");
  });

const installUpdate = () =>
  updateStep(`Downloading ${update.value.version}…`, async () => {
    await ScanService.InstallUpdate();
    update.value = { ...update.value, step: "ready" };
    setStatus(`Version ${update.value.version} is downloaded and verified. Restart to apply it.`);
  });

const restartToUpdate = () => updateStep("Restarting…", () => ScanService.RestartToUpdate());

const updateAction = computed(() => {
  const v = update.value.version;
  switch (update.value.step) {
    case "available":
      return { label: `Download ${v}`, run: installUpdate };
    case "ready":
      return { label: "Restart & apply", run: restartToUpdate };
    default:
      return { label: "Check for updates…", run: checkForUpdates };
  }
});

// Follow the log as it grows.
watch(logText, async () => {
  await nextTick();
  if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight;
});

onMounted(init);
</script>

<template>
  <header>
    <form id="scan-form" @submit.prevent="runScan">
      <div class="head-top">
        <strong class="brand">Trivy Scanner</strong>
        <div id="meta">{{ meta }}</div>
        <details id="opts">
          <summary>Options</summary>
          <div class="opts-body">
          <label><input type="checkbox" id="ignore-unfixed" v-model="opts.ignoreUnfixed" /> Ignore unfixed</label>
          <label title="Include findings suppressed by VEX or ignore files"
            ><input type="checkbox" id="show-suppressed" v-model="opts.showSuppressed" /> Show suppressed</label
          >
          <label title="Hide findings the vendor will not fix"
            ><input type="checkbox" id="ignore-will-not-fix" v-model="opts.ignoreWillNotFix" /> Ignore will_not_fix</label
          >
          <label title="Hide findings the vendor says do not affect the package"
            ><input type="checkbox" id="ignore-not-affected" v-model="opts.ignoreNotAffected" /> Ignore not_affected</label
          >
          <label title="Record an under investigation VEX statement for every finding that has none"
            ><input type="checkbox" id="mark-uninvestigated" v-model="opts.markUnderInvestigation" /> Mark all as under investigation</label
          >
          <input id="username" v-model="opts.username" placeholder="Registry username" autocomplete="off" />
          <input id="password" v-model="opts.password" type="password" placeholder="Registry password / token" autocomplete="off" />
          <input
            id="trivy-image"
            v-model="opts.trivyImage"
            :placeholder="trivyPlaceholder"
            autocomplete="off"
            spellcheck="false"
            title="Empty uses the default version. Enter a version such as 0.77.0, or a full image reference."
            @change="saveTrivyImage"
          />
          <label class="policy"
            >Ignore policy (Rego, <code>--ignore-policy</code>)
            <textarea
              id="ignore-policy"
              v-model="opts.ignorePolicy"
              rows="6"
              placeholder="package trivy&#10;&#10;ignore if input.PkgName == &quot;linux-libc-dev&quot;"
              autocomplete="off"
              spellcheck="false"
              title="Findings for which the policy defines ignore are left out of the scan. Empty means none."
              @change="saveIgnorePolicy"
            ></textarea>
            <span v-if="ignorePolicyError" class="field-err" id="ignore-policy-err">{{ ignorePolicyError }}</span>
          </label>
          <input
            id="ignore-policy-file"
            type="file"
            accept=".rego,text/plain"
            title="Load the policy from a .rego file"
            @change="loadIgnorePolicyFile($event.target.files[0])"
          />
          <label class="policy"
            >Ignore file (<code>.trivyignore.yaml</code>, <code>--ignorefile</code>)
            <textarea
              id="ignore-file"
              v-model="opts.ignoreFile"
              rows="6"
              placeholder="vulnerabilities:&#10;  - id: CVE-2024-12345&#10;    statement: Not reachable in our setup"
              autocomplete="off"
              spellcheck="false"
              title="Vulnerabilities listed here are left out of the scan. Empty means none."
              @change="saveIgnoreFile"
            ></textarea>
            <span v-if="ignoreFileError" class="field-err" id="ignore-file-err">{{ ignoreFileError }}</span>
          </label>
          <input
            id="ignore-file-file"
            type="file"
            accept=".yaml,.yml,text/yaml,text/plain"
            title="Load the ignore file from a .trivyignore.yaml file"
            @change="loadIgnoreFile($event.target.files[0])"
          />
          <div class="opts-update">
            <span class="kv">{{ appInfo ? "Version " + appInfo.version : "" }}</span>
            <button
              type="button"
              class="ghost"
              id="update-btn"
              :disabled="!appInfo?.enabled || updateBusy"
              :title="appInfo?.enabled ? '' : appInfo?.reason"
              @click="updateAction.run"
            >
              {{ updateAction.label }}
            </button>
          </div>
          </div>
        </details>
      </div>
      <div class="scan-row">
        <div class="image-wrap">
          <input
            id="image"
            v-model="image"
            role="combobox"
            aria-autocomplete="list"
            aria-controls="recent-list"
            :aria-expanded="showHistory"
            :aria-activedescendant="histIdx >= 0 ? 'recent-' + histIdx : undefined"
            placeholder="Container image, e.g. docker.io/library/nginx:1.27"
            autocomplete="off"
            spellcheck="false"
            required
            @focus="histOpen = true"
            @input="onImageInput"
            @blur="closeHistory"
            @keydown="imageKey"
          />
          <div id="recent-list" v-show="showHistory" role="listbox" aria-label="Recent images">
            <div class="recent-head" aria-hidden="true">Recent images</div>
            <div
              v-for="(e, i) in history"
              :id="'recent-' + i"
              :key="e.image"
              role="option"
              tabindex="-1"
              :aria-selected="i === histIdx"
              :class="{ active: i === histIdx }"
              @mousedown.prevent="pickRecent(e, true)"
            >
              <span class="recent-name">{{ e.image }}</span>
              <span class="recent-when">{{ ago(e.at) }}</span>
              <span v-for="t in [sevTag(e.crit, 'CRITICAL'), sevTag(e.high, 'HIGH')]" :key="t.sev" v-show="t.n" class="sev" :style="t.style"
                >{{ t.n }} {{ t.sev[0] }}</span
              >
            </div>
            <div class="recent-hint" aria-hidden="true">↑↓ to choose · Enter to rescan · Tab to fill the field</div>
          </div>
        </div>
        <button id="scan-btn" type="submit" :disabled="scanning">Scan</button>
        <button id="cancel-btn" type="button" v-show="scanning && !comparing" @click="cancel">Cancel</button>
      </div>
    </form>
    <button id="help-btn" type="button" class="ghost" title="Glossary and app configuration" aria-label="Help" @click="helpDialog.open()">
      ?
    </button>
  </header>

  <div id="mode-banner" v-if="mode?.fixtures">{{ mode.detail }}</div>

  <nav>
    <button type="button" :class="['tab', { active: tab === 'prio' }]" data-tab="prio" @click="tab = 'prio'">
      Priorities <span class="badge" id="prio-count" title="findings that need attention">{{ prio?.count ?? 0 }}</span>
    </button>
    <button type="button" :class="['tab', { active: tab === 'vulns' }]" data-tab="vulns" @click="tab = 'vulns'">
      Vulnerabilities <span class="badge" id="vuln-count">{{ counts.vulns }}</span>
    </button>
    <button type="button" :class="['tab', { active: tab === 'deps' }]" data-tab="deps" @click="tab = 'deps'">
      Dependencies <span class="badge" id="dep-count">{{ counts.deps }}</span>
    </button>
    <button type="button" :class="['tab', { active: tab === 'sbom' }]" data-tab="sbom" @click="tab = 'sbom'">
      SBOM <span class="badge" id="sbom-count">{{ counts.sbom }}</span>
    </button>
    <button type="button" :class="['tab', { active: tab === 'compare' }]" data-tab="compare" @click="tab = 'compare'">Compare</button>
    <button type="button" :class="['tab', 'right', { active: tab === 'log' }]" data-tab="log" @click="tab = 'log'">Log</button>
  </nav>

  <main>
    <section id="tab-prio" class="panel" :class="{ active: tab === 'prio' }">
      <PrioritiesPanel ref="prio" @export="vexDialog.open()" />
    </section>
    <section id="tab-vulns" class="panel" :class="{ active: tab === 'vulns' }"><VulnsPanel /></section>
    <section id="tab-deps" class="panel" :class="{ active: tab === 'deps' }"><DepsPanel /></section>
    <section id="tab-sbom" class="panel" :class="{ active: tab === 'sbom' }"><SbomPanel /></section>
    <section id="tab-compare" class="panel" :class="{ active: tab === 'compare' }"><ComparePanel /></section>
    <section id="tab-log" class="panel" :class="{ active: tab === 'log' }">
      <pre id="log" ref="logEl">{{ logText }}</pre>
    </section>
  </main>

  <VexDialog ref="vexDialog" />
  <VexDrawer />
  <HelpDialog ref="helpDialog" />
  <div id="status" :class="[status.err ? 'err' : '', status.busy ? 'spin' : '']">{{ status.msg }}</div>
  <footer id="footprint" v-if="footprintNote" :title="footprint.cacheLocation">{{ footprintNote }}</footer>
</template>
