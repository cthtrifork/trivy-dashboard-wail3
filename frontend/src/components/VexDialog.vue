<script setup>
import { computed, reactive, ref, watch } from "vue";
import { ScanService, result, vex, loadVEX, errText, lsGet, lsSet } from "../store.js";

const dlg = ref(null);
const preview = ref(null);
const form = reactive({ author: lsGet("vex-author"), role: lsGet("vex-role") });
const text = ref("");
const msg = ref("");
const paste = ref("");
const markRest = ref(false);

// How much of the scan the assessments cover: every CVE should end up assessed, and the
// under_investigation ones are what is left to decide.
const coverage = computed(() => {
  const keys = new Set((result.value?.vulnerabilities ?? []).map((v) => v.key));
  let open = 0,
    done = 0;
  for (const k of keys) {
    const e = vex.value.get(k);
    if (!e) continue;
    e.status === "under_investigation" ? open++ : done++;
  }
  return { total: keys.size, open, done, none: keys.size - open - done };
});

async function refresh() {
  msg.value = "";
  try {
    text.value = await ScanService.VEXExport(result.value.image, form.author, form.role);
  } catch (e) {
    text.value = "";
    msg.value = errText(e);
  }
}
watch(form, refresh);

async function open() {
  msg.value = vex.value.size ? "" : "No assessments yet: open a finding and set a VEX status first.";
  text.value = "";
  paste.value = "";
  dlg.value.showModal();
  await refresh();
}

// Apply a pasted OpenVEX document: the Go side matches its statements to this scan's findings and
// saves them as assessments, then the lists and the preview pick them up.
async function apply() {
  const doc = paste.value.trim();
  if (!doc) {
    msg.value = "Paste an OpenVEX document first.";
    return;
  }
  try {
    const rep = await ScanService.VEXImport(result.value.image, doc, markRest.value);
    await loadVEX();
    await refresh();
    const w = rep.warnings?.length ?? 0;
    msg.value =
      `Imported ${rep.imported} assessment${rep.imported === 1 ? "" : "s"}` +
      (rep.skipped ? ` · ${rep.skipped} statement${rep.skipped === 1 ? "" : "s"} kept that match no finding of this scan` : "") +
      (rep.marked ? ` · ${rep.marked} more marked under investigation` : "") +
      (w ? ` · ${w} warning${w === 1 ? "" : "s"}: ${rep.warnings.join("; ")}` : "") +
      ".";
    paste.value = "";
  } catch (e) {
    msg.value = errText(e);
  }
}

// Cover every finding that has no assessment yet, so nothing is silently missing from the export.
async function markAll() {
  try {
    const n = await ScanService.VEXMarkUnassessed(result.value.image, form.author);
    await loadVEX();
    await refresh();
    msg.value = n ? `Marked ${n} finding${n === 1 ? "" : "s"} as under investigation.` : "Every finding already has an assessment.";
  } catch (e) {
    msg.value = errText(e);
  }
}

async function copy() {
  try {
    await navigator.clipboard.writeText(text.value);
  } catch {
    preview.value.select();
    document.execCommand("copy");
  }
  msg.value = "Copied.";
}

async function save() {
  lsSet("vex-author", form.author);
  lsSet("vex-role", form.role);
  try {
    const path = await ScanService.VEXSave(result.value.image, form.author, form.role);
    msg.value = path ? "Saved to " + path : "";
    return;
  } catch (e) {
    if (!text.value) {
      msg.value = errText(e);
      return;
    }
  }
  // No native dialog (e.g. server mode): fall back to a browser download.
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(new Blob([text.value], { type: "application/json" })),
    download: "vex.openvex.json",
  });
  a.click();
  msg.value = "Downloaded vex.openvex.json";
}

defineExpose({ open });
</script>

<template>
  <dialog id="vex-dialog" ref="dlg">
    <h3>Edit/Create VEX</h3>
    <p class="kv">
      One statement per assessed finding for <b>{{ result?.image }}</b
      >. Statements carry over to future scans of the same image.
    </p>
    <details id="vex-import">
      <summary>Import an existing OpenVEX file</summary>
      <p class="kv">
        Paste an OpenVEX document. Its statements are matched to this scan's findings, saved as assessments (replacing existing ones for the
        same finding; other assessments are kept), and the shortlist is updated.
      </p>
      <label class="chk"
        ><input id="vex-mark-rest" v-model="markRest" type="checkbox" /> Mark findings the file does not cover as under investigation</label
      >
      <textarea
        id="vex-paste"
        v-model="paste"
        rows="8"
        spellcheck="false"
        placeholder='{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [...]}'
      ></textarea>
      <div class="dlg-actions"><button type="button" id="vex-apply" @click="apply">Apply to scan</button></div>
    </details>
    <div id="vex-coverage" class="kv">
      {{ coverage.done }} of {{ coverage.total }} findings assessed · {{ coverage.open }} under investigation · {{ coverage.none }} without a
      statement
      <button v-if="coverage.none" type="button" class="ghost" id="vex-mark-all" @click="markAll">
        Mark the {{ coverage.none }} as under investigation
      </button>
    </div>
    <div class="form-grid">
      <label>Author <input id="vex-author" v-model="form.author" placeholder="Your name or organisation" /></label>
      <label>Role <input id="vex-role" v-model="form.role" placeholder="e.g. Security Engineer (optional)" /></label>
    </div>
    <textarea id="vex-preview" ref="preview" :value="text" readonly rows="14" spellcheck="false"></textarea>
    <div id="vex-msg" class="kv">{{ msg }}</div>
    <div class="dlg-actions">
      <button type="button" class="ghost" id="vex-copy" @click="copy">Copy</button>
      <button type="button" class="ghost" id="vex-close" @click="dlg.close()">Close</button>
      <button type="button" id="vex-save" @click="save">Save file…</button>
    </div>
  </dialog>
</template>
