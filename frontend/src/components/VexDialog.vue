<script setup>
import JsonBox from "./JsonBox.vue";
import { computed, reactive, ref, watch } from "vue";
import { ScanService, result, vex, loadVEX, errText, lsGet, lsSet } from "../store.js";

const dlg = ref(null);
const preview = ref(null);
const form = reactive({ author: lsGet("vex-author"), onlyCurrent: false });
const text = ref("");
const msg = ref("");

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
    text.value = await ScanService.VEXExport(result.value.image, form.author, "", form.onlyCurrent);
  } catch (e) {
    text.value = "";
    msg.value = errText(e);
  }
}
watch(form, refresh);

// An imported document's author wins over what was typed before: exporting with both
// empty makes the Go side use the imported ones, and the placeholder when there are none.
async function loadMeta() {
  try {
    const doc = JSON.parse(await ScanService.VEXExport(result.value.image, "", "", false));
    const imported = doc.author && doc.author !== "<author>";
    form.author = imported ? doc.author : lsGet("vex-author");
  } catch {
    /* no assessments yet: the stored values stay */
  }
}

async function open() {
  msg.value = vex.value.size ? "" : "No assessments yet: open a finding and set a VEX status first.";
  text.value = "";
  dlg.value.showModal();
  await loadMeta();
  await refresh();
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
  try {
    const path = await ScanService.VEXSave(result.value.image, form.author, "", form.onlyCurrent);
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
    <h3>Edit/Export VEX</h3>
    <p class="kv">
      One statement per assessed finding for <b>{{ result?.image }}</b
      >. Statements carry over to future scans of the same image.
    </p>
    <div id="vex-coverage" class="kv">
      {{ coverage.done }} of {{ coverage.total }} findings assessed · {{ coverage.open }} under investigation · {{ coverage.none }} without a
      statement
      <button v-if="coverage.none" type="button" class="ghost" id="vex-mark-all" @click="markAll">
        Mark the {{ coverage.none }} as under investigation
      </button>
    </div>
    <div class="form-grid one">
      <label>Author <input id="vex-author" v-model="form.author" placeholder="&lt;author&gt;" /></label>
    </div>
    <label class="chk"
      ><input id="vex-only-current" v-model="form.onlyCurrent" type="checkbox" /> Leave out statements that no longer match a finding</label
    >
    <JsonBox ta-id="vex-preview" ref="preview" :model-value="text" readonly :rows="14" />
    <div id="vex-msg" class="kv">{{ msg }}</div>
    <div class="dlg-actions">
      <button type="button" class="ghost" id="vex-copy" @click="copy">Copy</button>
      <button type="button" class="ghost" id="vex-close" @click="dlg.close()">Close</button>
      <button type="button" id="vex-save" @click="save">Save file…</button>
    </div>
  </dialog>
</template>
