<script setup>
import { computed, nextTick, onMounted, reactive, ref, watch } from "vue";
import {
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
  setTag,
  clearAll,
  looksLikeRef,
  imageError,
  composing,
  startCompose,
  backToView,
  scanState,
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
  tab,
} from "./store.js";
import { ago, bytes } from "./lib/format.js";
import OptionsPanel from "./components/OptionsPanel.vue";
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
// Composing: the single box returns, focused, while the shown results stay (dimmed). The repository
// field enters it on click, and so does pasting a full reference into the repository or tag field.
function focusImage() {
  nextTick(() => {
    const el = document.getElementById("image");
    el?.focus();
    el?.select();
  });
}
function compose(ref) {
  startCompose(ref);
  closeHistory();
  focusImage();
}
// Pasted text loses the spaces and line breaks around it, which a copied reference often carries.
function insertTrimmed(ev) {
  const text = ev.clipboardData?.getData("text") ?? "";
  if (text === text.trim()) return;
  ev.preventDefault();
  const el = ev.target;
  if (el.readOnly) return;
  el.setRangeText(text.trim(), el.selectionStart, el.selectionEnd, "end");
  el.dispatchEvent(new Event("input", { bubbles: true }));
}
function pasteRef(ev) {
  const text = (ev.clipboardData?.getData("text") ?? "").trim();
  if (!looksLikeRef(text)) return insertTrimmed(ev);
  ev.preventDefault();
  compose(text);
}
function back() {
  backToView();
  closeHistory();
}
function imageKey(ev) {
  const n = history.value.length;
  if (ev.key === "Escape") return showHistory.value || !composing.value ? closeHistory() : back();
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

// Follow the log as it grows.
watch(logText, async () => {
  await nextTick();
  if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight;
});

// The tabs other than the first are mounted on their first visit, so the startup does not build the
// dependency graph, tables and compare form nobody has opened yet. Once seen they stay mounted.
const seen = reactive(new Set(["prio"]));
watch(tab, (t) => seen.add(t), { immediate: true });

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
        <OptionsPanel />
      </div>
      <div class="scan-row">
        <div v-if="split" class="image-wrap image-split">
          <div class="repo-wrap">
            <input
              id="image-repo"
              :value="imageRepo"
              readonly
              aria-label="Image repository, click to scan a different image"
              :title="imageRepo + '\nClick to scan a different image'"
              @focus="compose()"
              @click="compose()"
              @paste="pasteRef"
            />
            <span class="repo-edit" aria-hidden="true">✎</span>
          </div>
          <TagInput
            id="image-tag"
            :model-value="imageTag"
            :tags="repoTags"
            :disabled="scanning"
            :class="{ changed: scanState === 'changed' }"
            @update:model-value="setTag"
            @open="ensureTags(imageRepo)"
            @paste="pasteRef"
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
            :aria-invalid="!!imageError"
            :aria-describedby="imageError ? 'image-error' : undefined"
            :class="{ invalid: imageError }"
            @focus="histOpen = true"
            @input="onImageInput"
            @blur="closeHistory"
            @keydown="imageKey"
            @paste="insertTrimmed"
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
          :disabled="scanning || !!imageError"
          :title="scanState === 'current' ? 'Scan this image again, e.g. when a floating tag has moved' : ''"
        >
          {{ scanState === "current" ? "Rescan" : "Scan" }}
        </button>
        <button v-if="composing && !scanning" id="back-btn" type="button" class="ghost" @click="back">← Back to {{ result.image }}</button>
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
      <p v-if="imageError" id="image-error" role="alert">✗ {{ imageError }}</p>
      <p v-else-if="composing && !scanning" id="scan-state" class="changed" role="status">
        ● Still showing the scan of {{ result.image }}. Scan to replace it, or press Esc to go back.
      </p>
      <p v-else-if="split && !scanning && scanState !== 'new'" id="scan-state" :class="scanState" role="status">
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

  <main :class="{ dim: composing }">
    <section id="tab-prio" class="panel" :class="{ active: tab === 'prio' }">
      <PrioritiesPanel ref="prio" />
    </section>
    <section id="tab-vulns" class="panel" :class="{ active: tab === 'vulns' }"><VulnsPanel v-if="seen.has('vulns')" /></section>
    <section id="tab-deps" class="panel" :class="{ active: tab === 'deps' }"><DepsPanel v-if="seen.has('deps')" /></section>
    <section id="tab-sbom" class="panel" :class="{ active: tab === 'sbom' }"><SbomPanel v-if="seen.has('sbom')" /></section>
    <section id="tab-compare" class="panel" :class="{ active: tab === 'compare' }"><ComparePanel v-if="seen.has('compare')" /></section>
    <section id="tab-log" class="panel" :class="{ active: tab === 'log' }">
      <pre id="log" ref="logEl">{{ logText }}</pre>
    </section>
  </main>

  <VexDialog ref="vexDialog" />
  <VexImportDialog ref="vexImport" @generated="vexDialog.open()" />
  <VexDrawer />
  <HelpDialog ref="helpDialog" />
  <div id="status" :class="[status.err ? 'err' : '', status.busy ? 'spin' : '']">{{ status.msg }}</div>
  <footer id="footprint">
    <span id="app-version">{{ appInfo?.version ? "Version " + appInfo.version : "" }}</span>
    <span v-if="footprintNote" :title="footprintTitle">{{ footprintNote }}</span>
  </footer>
</template>
