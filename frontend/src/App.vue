<script setup>
import { computed, nextTick, onMounted, ref, watch } from "vue";
import {
  ScanService,
  sevStyle,
  result,
  vex,
  image,
  recent,
  split,
  imageRepo,
  imageTag,
  repoTags,
  ensureTags,
  ensureTrivyTags,
  trivyTags,
  trivyImageSetting,
  refreshFootprint,
  trivyNewest,
  setTag,
  clearAll,
  scanState,
  settingsChanged,
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
import CodeBox from "./components/CodeBox.vue";
import TagInput from "./components/TagInput.vue";
import PrioritiesPanel from "./components/PrioritiesPanel.vue";
import VulnsPanel from "./components/VulnsPanel.vue";
import DepsPanel from "./components/DepsPanel.vue";
import SbomPanel from "./components/SbomPanel.vue";
import ComparePanel from "./components/ComparePanel.vue";
import VexDialog from "./components/VexDialog.vue";
import VexImportDialog from "./components/VexImportDialog.vue";
import VexDrawer from "./components/VexDrawer.vue";
import HelpDialog from "./components/HelpDialog.vue";

const tab = ref("prio");
const prio = ref(null);
const vexDialog = ref(null);
const vexImport = ref(null);
const vexMenu = ref(false);
const closeVexMenu = () => (vexMenu.value = false);
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
function clearView() {
  clearAll();
  nextTick(() => document.getElementById("image")?.focus());
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

const trivyPlaceholder = computed(() => trivyNewest.value || mode.value?.trivyImage?.split(":").pop() || "Trivy version");
// What the Options popover shows without opening a section.
const activeCount = computed(
  () => [opts.ignoreUnfixed, opts.showSuppressed].filter(Boolean).length + opts.ignoreStatus.length,
);
const OPT_TABS = [
  { id: "findings", label: "Findings" },
  { id: "sources", label: "Sources" },
  { id: "scanner", label: "Scanner" },
  { id: "updates", label: "App updates" },
];
const optsTab = ref("findings");
const VENDOR_STATUSES = [
  { id: "will_not_fix", hint: "The vendor will not fix it" },
  { id: "not_affected", hint: "The vendor says the package is not affected" },
  { id: "affected", hint: "Affected, no fix yet" },
  { id: "fixed", hint: "Already fixed in this version" },
  { id: "under_investigation", hint: "The vendor is still looking into it" },
  { id: "fix_deferred", hint: "A fix is planned for later" },
  { id: "end_of_life", hint: "The vendor no longer supports this package" },
  { id: "unknown", hint: "No status reported" },
];
const toggleStatus = (id) => {
  const i = opts.ignoreStatus.indexOf(id);
  if (i < 0) opts.ignoreStatus.push(id);
  else opts.ignoreStatus.splice(i, 1);
};
const registrySummary = computed(() => opts.username.trim() || (mode.value?.registryToken ? mode.value.registryUser + " (token)" : "not set"));
const ignoreSummary = computed(() => [opts.ignorePolicy.trim() && "Rego", opts.ignoreFile.trim() && "ignore file"].filter(Boolean).join(" + ") || "none");
const meta = computed(() => (result.value ? `${result.value.image}${result.value.os ? " · " + result.value.os : ""}` : ""));
const counts = computed(() => ({
  vulns: result.value?.vulnerabilities.length ?? 0,
  deps: Object.keys(result.value?.depNodes ?? {}).length,
  sbom: result.value?.components.length ?? 0,
}));

const footprintNote = computed(() => {
  const f = footprint.value;
  if (!f || f.remote) return "";
  const where = `in podman volume ${f.cacheLocation}`;
  const cache = f.cacheBytes < 0 ? `Trivy cache ${where}` : `Trivy cache ${bytes(f.cacheBytes)}`;
  return `Disk usage: ${cache}`;
});

const footprintTitle = computed(() => {
  const f = footprint.value;
  if (!f) return "";
  const parts = (f.parts || []).map((p) => `${p.name}: ${bytes(p.bytes)}`);
  return [f.cacheLocation, ...parts].join("\n");
});

// Updating is three clicks, never automatic: check, then download, then restart.
const update = ref({ step: "idle", version: "" }); // idle | available | ready
const updateBusy = ref(false);
const dbBusy = ref(false);

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

// The DB is checked once after startup; this checks again now. Trivy downloads only if the cached one is out of date.
const updateDB = () =>
  updateStep("Updating the vulnerability database…", async () => {
    dbBusy.value = true;
    let downloaded;
    try {
      downloaded = await ScanService.UpdateDB(trivyImageSetting.value);
    } finally {
      dbBusy.value = false;
      refreshFootprint(); // a download changes the cache size shown in the footer
    }
    setStatus(downloaded ? "Downloaded a newer vulnerability database." : "No new database was downloaded: the local copy is current.");
  });

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
onMounted(() => {
  document.addEventListener("click", closeVexMenu);
  document.addEventListener("keydown", (e) => e.key === "Escape" && closeVexMenu());
});
</script>

<template>
  <header>
    <form id="scan-form" @submit.prevent="runScan">
      <div class="head-top">
        <strong class="brand">Trivy Scanner</strong>
        <div id="meta">{{ meta }}</div>
        <details id="opts">
          <summary>Options<span v-if="activeCount" class="opts-count"> · {{ activeCount }} active</span
          ><span v-if="settingsChanged" class="opts-count"> · rescan to apply</span></summary>
          <div class="opts-body">
            <div class="opts-tabs" role="tablist" aria-label="Options">
              <button
                v-for="t in OPT_TABS"
                :id="'opts-tab-' + t.id"
                :key="t.id"
                type="button"
                role="tab"
                class="opts-tab"
                :class="{ on: optsTab === t.id }"
                :aria-selected="optsTab === t.id"
                @click="optsTab = t.id"
              >
                {{ t.label }}
              </button>
            </div>
            <div v-show="optsTab === 'findings'" class="opts-pane" role="tabpanel">
              <div class="opts-label">Fix availability <code>--ignore-unfixed</code></div>
              <div class="seg">
                <button type="button" id="ignore-unfixed-off" :class="{ on: !opts.ignoreUnfixed }" :aria-pressed="!opts.ignoreUnfixed" @click="opts.ignoreUnfixed = false">All</button>
                <button
                  type="button"
                  id="ignore-unfixed"
                  :class="{ on: opts.ignoreUnfixed }"
                  :aria-pressed="opts.ignoreUnfixed"
                  title="Hide findings without a fix"
                  @click="opts.ignoreUnfixed = true"
                >
                  Fixable only
                </button>
              </div>
              <label class="opts-switch" title="Show findings that your ignore policy or ignore file would otherwise hide"
                ><span>Include suppressed <code>--show-suppressed</code></span><input type="checkbox" id="show-suppressed" v-model="opts.showSuppressed"
              /></label>
              <div class="opts-label">Hide vendor statuses <code>--ignore-status</code></div>

                  <div class="chips">
                    <button
                      v-for="st in VENDOR_STATUSES"
                      :key="st.id"
                      type="button"
                      class="chip"
                      :class="{ on: opts.ignoreStatus.includes(st.id) }"
                      :aria-pressed="opts.ignoreStatus.includes(st.id)"
                      :title="st.hint"
                      @click="toggleStatus(st.id)"
                    >
                      {{ st.id }}
                    </button>
                  </div>
            </div>
            <div v-show="optsTab === 'sources'" class="opts-pane" role="tabpanel">
              <div class="opts-label">Registry login</div>

                  <input id="username" v-model="opts.username" :placeholder="mode?.registryToken ? mode.registryUser + ' (GITHUB_TOKEN, ghcr.io)' : 'Registry username'" autocomplete="off" />
                  <input
                    id="password"
                    v-model="opts.password"
                    type="password"
                    :placeholder="mode?.registryToken ? '••••••••  GITHUB_TOKEN (ghcr.io)' : 'Registry password / token'"
                    autocomplete="off"
                  />
              <div class="opts-label">Ignore rules <span class="opts-val">{{ ignoreSummary }}</span></div>

                  <div class="policy">
                    <span>Ignore policy (Rego, <code>--ignore-policy</code>)</span>
                    <CodeBox
                      v-model="opts.ignorePolicy"
                      language="rego"
                      ta-id="ignore-policy"
                      :error="ignorePolicyError"
                      placeholder="package trivy&#10;&#10;ignore if input.PkgName == &quot;linux-libc-dev&quot;"
                      title="Findings matched by an ignore rule in this policy are left out. Empty means no rules."
                      @commit="saveIgnorePolicy"
                    />
                    <span v-if="ignorePolicyError" class="field-err" id="ignore-policy-err">{{ ignorePolicyError }}</span>
                  </div>
                  <label class="file-btn"
                    >Load policy from a .rego file…
                    <input id="ignore-policy-file" type="file" accept=".rego,text/plain" @change="loadIgnorePolicyFile($event.target.files[0])"
                  /></label>
                  <div class="policy">
                    <span>Ignore file (<code>.trivyignore.yaml</code>, <code>--ignorefile</code>)</span>
                    <CodeBox
                      v-model="opts.ignoreFile"
                      language="yaml"
                      ta-id="ignore-file"
                      :error="ignoreFileError"
                      placeholder="vulnerabilities:&#10;  - id: CVE-2024-12345&#10;    statement: Not reachable in our setup"
                      title="Vulnerabilities listed here are left out. Empty means none."
                      @commit="saveIgnoreFile"
                    />
                    <span v-if="ignoreFileError" class="field-err" id="ignore-file-err">{{ ignoreFileError }}</span>
                  </div>
                  <label class="file-btn"
                    >Load ignore file from a .yaml file…
                    <input id="ignore-file-file" type="file" accept=".yaml,.yml,text/yaml,text/plain" @change="loadIgnoreFile($event.target.files[0])"
                  /></label>
            </div>
            <div v-show="optsTab === 'scanner'" class="opts-pane" role="tabpanel">
              <div class="opts-label">Trivy version</div>

                  <TagInput
                    id="trivy-image"
                    v-model="opts.trivyImage"
                    :tags="trivyTags"
                    label="Trivy version"
                    :placeholder="trivyPlaceholder"
                    title="Leave empty to use the newest Trivy version, or enter one such as 0.77.0."
                    @update:model-value="saveTrivyImage"
                    @open="ensureTrivyTags"
                  />
              <div class="opts-label">Vulnerability database</div>
              <div class="opts-row-plain">
                <span class="kv">Checked automatically before the first scan after startup. Update it here to get the latest data right away.</span>
                <button
                  type="button"
                  class="ghost"
                  id="update-db-btn"
                  :disabled="scanning || updateBusy"
                  title="Download the latest vulnerability database if the local copy is out of date."
                  @click="updateDB"
                >
                  {{ dbBusy ? "Updating…" : "Update database" }}
                </button>
              </div>
            </div>
            <div v-show="optsTab === 'updates'" class="opts-pane" role="tabpanel">
              <div class="opts-label">Installed version</div>
              <div class="opts-row-plain">
                <strong id="app-version-opts">{{ appInfo ? appInfo.version : "" }}</strong>
                <button
                  type="button"
                  class="ghost"
                  id="update-btn"
                  :disabled="!appInfo?.enabled || updateBusy"
                  @click="updateAction.run"
                >
                  {{ updateAction.label }}
                </button>
              </div>
              <span class="kv">{{ appInfo?.enabled ? "Updates download from GitHub releases and are verified with SHA-256 before they are installed." : appInfo?.reason }}</span>
            </div>
          </div>
        </details>
      </div>
      <div class="scan-row">
        <div v-if="split" class="image-wrap image-split">
          <input id="image-repo" :value="imageRepo" readonly tabindex="-1" aria-label="Image repository" :title="imageRepo" />
          <TagInput
            id="image-tag"
            :model-value="imageTag"
            :tags="repoTags"
            :disabled="scanning"
            :class="{ changed: scanState === 'changed' }"
            @update:model-value="setTag"
            @open="ensureTags(imageRepo)"
          />
          <button type="button" class="ghost clear-btn" title="Clear the results and go back to the single image field" :disabled="scanning" @click="clearView">
            Clear
          </button>
        </div>
        <div v-else class="image-wrap">
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
        <button
          id="scan-btn"
          type="submit"
          :class="{ rescan: scanState === 'current' }"
          :disabled="scanning"
          :title="scanState === 'current' ? 'Scan this image again, e.g. when a floating tag has moved' : ''"
        >
          {{ scanState === "current" ? "Rescan" : "Scan" }}
        </button>
        <div id="vex-split" :class="{ solo: !vex.size }">
          <button
            v-if="vex.size"
            id="export-vex-btn"
            type="button"
            :disabled="!result"
            title="Edit and export VEX assessments"
            @click="vexDialog.open()"
          >
            Export VEX ({{ vex.size }})
          </button>
          <button v-else id="vex-import-btn" type="button" :disabled="!result" title="Import an OpenVEX file" @click="vexImport.open()">
            Import VEX
          </button>
          <button
            v-if="vex.size"
            id="vex-menu-btn"
            type="button"
            :disabled="!result"
            aria-haspopup="menu"
            :aria-expanded="vexMenu"
            title="More VEX actions"
            @click.stop="vexMenu = !vexMenu"
          >
            ▾
          </button>
          <div v-if="vexMenu" id="vex-menu" role="menu">
            <button id="vex-menu-import" type="button" role="menuitem" @click="vexImport.open(); vexMenu = false">Import / merge VEX…</button>
          </div>
        </div>
        <button id="cancel-btn" type="button" v-show="scanning && !comparing" @click="cancel">Cancel</button>
      </div>
      <p v-if="split && !scanning && scanState !== 'new'" id="scan-state" :class="scanState" role="status">
        <template v-if="scanState === 'current'">✓ Showing the scan of {{ result.image }}. Rescan to check it again.</template>
        <template v-else-if="scanState === 'settings'">● Options changed since this scan. Press Scan to apply them.</template>
        <template v-else>● Not scanned yet: the results below are for {{ result.image }}. Press Scan for {{ image }}.</template>
      </p>
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
      <PrioritiesPanel ref="prio" />
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
  <VexImportDialog ref="vexImport" />
  <VexDrawer />
  <HelpDialog ref="helpDialog" />
  <div id="status" :class="[status.err ? 'err' : '', status.busy ? 'spin' : '']">{{ status.msg }}</div>
  <footer id="footprint">
    <span id="app-version">{{ appInfo?.version ? "Version " + appInfo.version : "" }}</span>
    <span v-if="footprintNote" :title="footprintTitle">{{ footprintNote }}</span>
  </footer>
</template>
