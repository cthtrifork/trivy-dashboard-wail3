<script setup>
import { computed, defineAsyncComponent, ref } from "vue";
import {
  opts,
  saveIgnorePolicy,
  saveIgnoreFile,
  loadIgnorePolicyFile,
  loadIgnoreFile,
  ignorePolicyError,
  ignoreFileError,
} from "../store.js";

// CodeMirror is ~half of the bundle; keep it out of the first load.
const CodeBox = defineAsyncComponent(() => import("./CodeBox.vue"));
const loaded = ref(false); // mount the editor on first open, not at startup

// The large editor for the two ignore rule sets (Rego policy and .trivyignore.yaml), opened from
// Options → Sources like the VEX dialog. The text is the same `opts` state the scan sends; it is
// remembered when an editor loses focus and again when the dialog closes.
const dlg = ref(null);
const tab = ref("policy"); // policy | file

const SETS = {
  policy: {
    label: "Rego policy",
    flag: "--ignore-policy",
    language: "rego",
    taId: "ignore-policy",
    placeholder: 'package trivy\n\nignore if input.PkgName == "linux-libc-dev"',
    title: "Findings matched by an ignore rule in this policy are left out. Empty means no rules.",
    accept: ".rego,text/plain",
    load: loadIgnorePolicyFile,
    save: saveIgnorePolicy,
  },
  file: {
    label: "Ignore file (YAML)",
    flag: "--ignorefile",
    language: "yaml",
    taId: "ignore-file",
    placeholder: "vulnerabilities:\n  - id: CVE-2024-12345\n    statement: Not reachable in our setup",
    title: "Vulnerabilities listed here are left out. Empty means none.",
    accept: ".yaml,.yml,text/yaml,text/plain",
    load: loadIgnoreFile,
    save: saveIgnoreFile,
  },
};
const set = computed(() => SETS[tab.value]);
const text = computed({
  get: () => (tab.value === "policy" ? opts.ignorePolicy : opts.ignoreFile),
  set: (v) => (tab.value === "policy" ? (opts.ignorePolicy = v) : (opts.ignoreFile = v)),
});
const error = computed(() => (tab.value === "policy" ? ignorePolicyError.value : ignoreFileError.value));

function open(which = "policy") {
  loaded.value = true;
  tab.value = which;
  dlg.value.showModal();
}
function onClose() {
  saveIgnorePolicy();
  saveIgnoreFile();
}
async function pick(ev) {
  await set.value.load(ev.target.files[0]);
  ev.target.value = ""; // picking the same file again must still fire
}

defineExpose({ open });
</script>

<template>
  <dialog id="ignore-dialog" ref="dlg" @close="onClose">
    <h3>Edit ignore rules</h3>
    <p class="kv">Findings matched by these rules are left out of the scan. Scan again to apply changes.</p>
    <div class="seg" role="tablist" aria-label="Rule type">
      <button
        v-for="(s, id) in SETS"
        :id="'ignore-tab-' + id"
        :key="id"
        type="button"
        role="tab"
        :class="{ on: tab === id }"
        :aria-selected="tab === id"
        @click="tab = id"
      >
        {{ s.label }}
      </button>
    </div>
    <CodeBox
      v-if="loaded"
      :key="tab"
      v-model="text"
      :language="set.language"
      :ta-id="set.taId"
      :error="error"
      :rows="18"
      :placeholder="set.placeholder"
      :title="set.title"
      @commit="set.save"
    />
    <div class="kv ignore-status" :class="{ err: error }" role="status">
      <template v-if="error"
        ><span id="ignore-dialog-err" class="field-err">{{ error }}</span></template
      >
      <template v-else>{{ text.trim() ? "Looks valid. Trivy has the final say when it scans." : "Empty: no rules." }}</template>
      <code>{{ set.flag }}</code>
    </div>
    <div class="dlg-actions">
      <label class="file-btn"
        >Load from file…
        <input id="ignore-dialog-file" type="file" :accept="set.accept" @change="pick"
      /></label>
      <button type="button" id="ignore-close" @click="dlg.close()">Done</button>
    </div>
  </dialog>
</template>
