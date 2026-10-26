<script setup>
import { computed, nextTick, onMounted, ref, watch } from "vue";
import {
  ScanService,
  result,
  image,
  opts,
  saveTrivyImage,
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
import { bytes } from "./lib/format.js";
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
      <input
        id="image"
        v-model="image"
        placeholder="Container image, e.g. docker.io/library/nginx:1.27"
        autocomplete="off"
        spellcheck="false"
        required
      />
      <button id="scan-btn" type="submit" :disabled="scanning">Scan</button>
      <button id="cancel-btn" type="button" v-show="scanning && !comparing" @click="cancel">Cancel</button>
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
    </form>
    <div id="meta">{{ meta }}</div>
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
