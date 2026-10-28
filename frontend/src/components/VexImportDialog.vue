<script setup>
import JsonBox from "./JsonBox.vue";
import { computed, ref } from "vue";
import { ScanService, result, vex, loadVEX, errText, lsGet, KEYS } from "../store.js";

const emit = defineEmits(["generated"]);
const dlg = ref(null);
const paste = ref("");
// What happens to findings the file does not cover: "none", "ALL" or the lowest severity to mark.
const uncovered = ref("none");
const imported = ref(false);
const busy = ref(false);
const error = ref("");
// What the last import did, one line per event, newest import only.
const report = ref(null);

// Generate: how many findings the chosen severity limit covers.
const genSeverity = ref("");
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const findingCount = computed(() => {
  const min = SEV_RANK[genSeverity.value] ?? 0;
  const keys = new Set();
  for (const v of result.value?.vulnerabilities ?? []) if ((SEV_RANK[v.severity] ?? 0) >= min) keys.add(v.key);
  return keys.size;
});

const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

// Warnings arrive as strings from the Go side; "no finding in this scan" ones are statements
// that were kept, everything else is a statement that was rejected.
const log = computed(() => {
  const r = report.value;
  if (!r) return [];
  const lines = [];
  if (r.imported) lines.push({ kind: "ok", text: `${plural(r.imported, "assessment")} imported and matched to findings of this scan` });
  if (r.marked) lines.push({ kind: "info", text: `${plural(r.marked, "finding")} not covered by the file marked under investigation` });
  for (const w of r.warnings ?? []) {
    lines.push({ kind: w.includes("no finding in this scan") ? "skip" : "warn", text: w });
  }
  if (!lines.length) lines.push({ kind: "info", text: "Nothing to import." });
  return lines;
});

const ICON = { ok: "✓", info: "•", skip: "↷", warn: "!" };

function open() {
  error.value = "";
  report.value = null;
  paste.value = "";
  imported.value = false;
  dlg.value.showModal();
}

async function loadFile(ev) {
  const f = ev.target.files?.[0];
  if (f) {
    paste.value = await f.text();
    imported.value = false;
  }
  ev.target.value = "";
}

// The Go side matches the document's statements to this scan's findings and saves them as assessments.
async function apply() {
  const doc = paste.value.trim();
  if (!doc) {
    error.value = "Paste an OpenVEX document or choose a file first.";
    return;
  }
  busy.value = true;
  error.value = "";
  try {
    report.value = await ScanService.VEXImport(result.value.image, doc, uncovered.value !== "none", uncovered.value === "ALL" ? "" : uncovered.value);
    await loadVEX();
    imported.value = true;
  } catch (e) {
    error.value = errText(e);
  } finally {
    busy.value = false;
  }
}

// No assessments yet: start a VEX file from the scan itself, then hand over to the export dialog.
async function generate() {
  busy.value = true;
  error.value = "";
  try {
    await ScanService.VEXMarkUnassessed(result.value.image, lsGet(KEYS.vexAuthor), genSeverity.value);
    await loadVEX();
    dlg.value.close();
    emit("generated");
  } catch (e) {
    error.value = errText(e);
  } finally {
    busy.value = false;
  }
}

defineExpose({ open });
</script>

<template>
  <dialog id="vex-import-dialog" ref="dlg">
    <h3>Import VEX</h3>
    <p class="kv">
      Statements are matched to the findings of <b>{{ result?.image }}</b
      >, saved as assessments (replacing existing ones for the same finding; others are kept).
    </p>
    <JsonBox
      v-model="paste"
      vex
      ta-id="vex-paste"
      :rows="8"
      placeholder='{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [...]}'
    />
    <label class="inline-field"
      >Findings the file does not cover
      <select id="vex-uncovered" v-model="uncovered">
        <option value="none">Leave alone</option>
        <option value="ALL">Mark under investigation</option>
        <option value="CRITICAL">Mark Critical under investigation</option>
        <option value="HIGH">Mark High and above</option>
        <option value="MEDIUM">Mark Medium and above</option>
        <option value="LOW">Mark Low and above</option>
      </select></label
    >
    <div class="dlg-actions">
      <label class="ghost file-btn">Choose file…<input type="file" accept=".json,application/json" hidden @change="loadFile" /></label>
      <button type="button" id="vex-apply" :disabled="busy" @click="apply">{{ busy ? "Importing…" : imported ? "Reimport" : "Import" }}</button>
    </div>
    <div v-if="error" class="vex-log-line warn" id="vex-import-error">
      <span class="ico">!</span><span>{{ error }}</span>
    </div>
    <div v-if="report" id="vex-import-log">
      <div class="vex-stats">
        <div><b>{{ report.imported }}</b> imported</div>
        <div><b>{{ report.skipped }}</b> kept, no match</div>
        <div><b>{{ report.marked }}</b> marked</div>
        <div><b>{{ report.warnings?.length ?? 0 }}</b> warnings</div>
      </div>
      <ul class="vex-log">
        <li v-for="(l, i) in log" :key="i" :class="['vex-log-line', l.kind]">
          <span class="ico">{{ ICON[l.kind] }}</span><span>{{ l.text }}</span>
        </li>
      </ul>
    </div>
    <div class="dlg-actions"><button type="button" class="ghost" id="vex-import-close" @click="dlg.close()">Close</button></div>
    <div v-if="!vex.size" id="vex-generate" class="vex-generate">
      <span class="kv">No VEX file yet? Generate one from this scan.</span>
      <span class="vex-generate-ctl">
        <select id="vex-generate-min" v-model="genSeverity" aria-label="Findings to include">
          <option value="">All findings ({{ findingCount }})</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High and above</option>
          <option value="MEDIUM">Medium and above</option>
          <option value="LOW">Low and above</option>
        </select>
        <button type="button" id="vex-generate-btn" :disabled="busy || !findingCount" @click="generate">Generate…</button>
      </span>
    </div>
  </dialog>
</template>
