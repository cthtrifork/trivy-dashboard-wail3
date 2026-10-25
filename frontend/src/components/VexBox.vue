<script setup>
import { computed, reactive, ref, watch } from "vue";
import { ScanService, result, vex, openVex as openKeys, errText } from "../store.js";
import { STATUS_LABEL, JUSTIFICATIONS } from "../lib/format.js";

const props = defineProps({ v: { type: Object, required: true } });

const existing = computed(() => vex.value.get(props.v.key));
// openKeys remembers which boxes the user opened across list re-renders (a save reorders the priorities).
const open = ref(openKeys.has(props.v.key) || !!existing.value);
const form = reactive({ status: "", justification: "", impact: "", action: "" });
const err = ref("");

function load() {
  const e = existing.value;
  Object.assign(form, { status: e?.status || "", justification: e?.justification || "", impact: e?.impact || "", action: e?.action || "" });
}
load();
watch(existing, load);

function onToggle(ev) {
  open.value = ev.target.open;
  open.value ? openKeys.add(props.v.key) : openKeys.delete(props.v.key);
}

async function save() {
  err.value = "";
  if (!form.status) {
    err.value = "Choose a status.";
    return;
  }
  try {
    const saved = await ScanService.VEXSet(result.value.image, {
      vulnerability: props.v.id,
      package: props.v.package,
      version: props.v.installed,
      purl: props.v.purl,
      status: form.status,
      justification: form.justification,
      impact: form.impact,
      action: form.action,
    });
    openKeys.add(props.v.key);
    vex.value = new Map(vex.value).set(saved.key, saved);
  } catch (e) {
    err.value = errText(e);
  }
}

async function clear() {
  await ScanService.VEXDelete(result.value.image, props.v.key);
  openKeys.delete(props.v.key);
  const m = new Map(vex.value);
  m.delete(props.v.key);
  vex.value = m;
}
</script>

<template>
  <details class="vexbox" :open="open" @toggle="onToggle" @click.stop>
    <summary>{{ existing ? `VEX assessment: ${STATUS_LABEL[existing.status]}` : "Assess this finding (VEX)" }}</summary>
    <div class="vexform">
      <label
        >Status
        <select v-model="form.status">
          <option value="">— select status —</option>
          <option v-for="(label, k) in STATUS_LABEL" :key="k" :value="k">{{ label }}</option>
        </select>
      </label>
      <label v-show="form.status === 'not_affected'"
        >Justification (required unless an impact statement is given)
        <select v-model="form.justification">
          <option value="">— select justification —</option>
          <option v-for="(label, k) in JUSTIFICATIONS" :key="k" :value="k">{{ label }}</option>
        </select>
      </label>
      <label v-show="form.status"
        >Impact statement
        <textarea
          v-model="form.impact"
          rows="2"
          placeholder="Explain why (e.g. the service is not exposed, the code path is never loaded)"
        ></textarea>
      </label>
      <label v-show="form.status === 'affected'"
        >Action statement (required for affected)
        <textarea
          v-model="form.action"
          rows="2"
          placeholder="What will be done about it (e.g. upgrade to 3.1 in the next release)"
        ></textarea>
      </label>
      <div class="row">
        <button type="button" @click="save">Save</button>
        <button type="button" class="ghost" v-show="existing" @click="clear">Remove assessment</button>
      </div>
      <div class="vexerr">{{ err }}</div>
    </div>
  </details>
</template>
