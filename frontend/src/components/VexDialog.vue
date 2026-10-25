<script setup>
import { reactive, ref, watch } from "vue";
import { ScanService, result, vex, loadVEX, errText, lsGet, lsSet } from "../store.js";

const dlg = ref(null);
const preview = ref(null);
const form = reactive({ author: lsGet("vex-author"), role: lsGet("vex-role") });
const text = ref("");
const msg = ref("");
const paste = ref("");

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
    const rep = await ScanService.VEXImport(result.value.image, doc);
    await loadVEX();
    await refresh();
    const w = rep.warnings?.length ?? 0;
    msg.value =
      `Imported ${rep.imported} assessment${rep.imported === 1 ? "" : "s"}` +
      (w ? ` · ${w} warning${w === 1 ? "" : "s"}: ${rep.warnings.join("; ")}` : "") +
      ".";
    paste.value = "";
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
        same finding), and the shortlist is updated.
      </p>
      <textarea
        id="vex-paste"
        v-model="paste"
        rows="8"
        spellcheck="false"
        placeholder='{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [...]}'
      ></textarea>
      <div class="dlg-actions"><button id="vex-apply" @click="apply">Apply to scan</button></div>
    </details>
    <div class="form-grid">
      <label>Author <input id="vex-author" v-model="form.author" placeholder="Your name or organisation" /></label>
      <label>Role <input id="vex-role" v-model="form.role" placeholder="e.g. Security Engineer (optional)" /></label>
    </div>
    <textarea id="vex-preview" ref="preview" :value="text" readonly rows="14" spellcheck="false"></textarea>
    <div id="vex-msg" class="kv">{{ msg }}</div>
    <div class="dlg-actions">
      <button class="ghost" id="vex-copy" @click="copy">Copy</button>
      <button class="ghost" id="vex-close" @click="dlg.close()">Close</button>
      <button id="vex-save" @click="save">Save file…</button>
    </div>
  </dialog>
</template>
