<script setup>
import { reactive, ref, watch } from "vue";
import { ScanService, result, vex, errText, lsGet, lsSet } from "../store.js";

const dlg = ref(null);
const preview = ref(null);
const form = reactive({ author: lsGet("vex-author"), role: lsGet("vex-role") });
const text = ref("");
const msg = ref("");

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
  dlg.value.showModal();
  await refresh();
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
    if (!text.value) { msg.value = errText(e); return; }
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
    <h3>Export OpenVEX</h3>
    <p class="kv">One statement per assessed finding for <b>{{ result?.image }}</b>. Statements carry over to future scans of the same image.</p>
    <div class="form-grid">
      <label>Author <input id="vex-author" v-model="form.author" placeholder="Your name or organisation"></label>
      <label>Role <input id="vex-role" v-model="form.role" placeholder="e.g. Security Engineer (optional)"></label>
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
