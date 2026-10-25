<script setup>
import { computed, reactive, ref, watch } from "vue";
import { ScanService, result, vex, findingsById, openVex as openKeys, errText, lsGet, lsSet } from "../store.js";
import { STATUS_LABEL, JUSTIFICATIONS, isExpired } from "../lib/format.js";

const props = defineProps({ v: { type: Object, required: true } });

const existing = computed(() => vex.value.get(props.v.key));
// openKeys remembers which boxes the user opened across list re-renders (a save reorders the priorities).
const open = ref(openKeys.has(props.v.key) || !!existing.value);
const form = reactive({ status: "", justification: "", impact: "", action: "", author: lsGet("vex-author"), expires: "" });
const err = ref("");

// Other components with the same CVE, which the assessment can be applied to in one go.
const siblings = computed(() => [...(findingsById.value.get(props.v.id)?.values() ?? [])].filter((s) => s.key !== props.v.key));
const alsoKeys = ref(new Set());
const allChecked = computed(() => siblings.value.length > 0 && siblings.value.every((s) => alsoKeys.value.has(s.key)));
function toggleAll(ev) {
  alsoKeys.value = ev.target.checked ? new Set(siblings.value.map((s) => s.key)) : new Set();
}
function toggleOne(key, on) {
  const next = new Set(alsoKeys.value);
  on ? next.add(key) : next.delete(key);
  alsoKeys.value = next;
}

function load() {
  const e = existing.value;
  Object.assign(form, {
    status: e?.status || "", justification: e?.justification || "", impact: e?.impact || "", action: e?.action || "",
    author: e?.author || lsGet("vex-author"), expires: e?.expires || "",
  });
}
load();
watch(existing, load);

function onToggle(ev) {
  open.value = ev.target.open;
  open.value ? openKeys.add(props.v.key) : openKeys.delete(props.v.key);
}

async function save() {
  err.value = "";
  if (!form.status) { err.value = "Choose a status."; return; }
  try {
    const targets = [props.v, ...siblings.value.filter((s) => alsoKeys.value.has(s.key))];
    const next = new Map(vex.value);
    // The same statement is valid for every target, so a validation error shows up on the first call, before anything is written.
    for (const t of targets) {
      const saved = await ScanService.VEXSet(result.value.image, {
        vulnerability: t.id, package: t.package, version: t.installed, purl: t.purl,
        status: form.status, justification: form.justification, impact: form.impact, action: form.action,
        author: form.author, expires: form.expires,
      });
      next.set(saved.key, saved);
      openKeys.add(t.key);
    }
    lsSet("vex-author", form.author.trim());
    alsoKeys.value = new Set();
    vex.value = next;
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
    <summary>{{ existing ? `VEX assessment: ${STATUS_LABEL[existing.status]}${isExpired(existing) ? " (expired)" : ""}` : "Assess this finding (VEX)" }}</summary>
    <div class="vexform">
      <label>Status
        <select v-model="form.status">
          <option value="">— select status —</option>
          <option v-for="(label, k) in STATUS_LABEL" :key="k" :value="k">{{ label }}</option>
        </select>
      </label>
      <label v-show="form.status === 'not_affected'">Justification (required unless an impact statement is given)
        <select v-model="form.justification">
          <option value="">— select justification —</option>
          <option v-for="(label, k) in JUSTIFICATIONS" :key="k" :value="k">{{ label }}</option>
        </select>
      </label>
      <label v-show="form.status">Impact statement
        <textarea v-model="form.impact" rows="2" placeholder="Explain why (e.g. the service is not exposed, the code path is never loaded)"></textarea>
      </label>
      <label v-show="form.status === 'affected'">Action statement (required for affected)
        <textarea v-model="form.action" rows="2" placeholder="What will be done about it (e.g. upgrade to 3.1 in the next release)"></textarea>
      </label>
      <fieldset v-if="siblings.length" v-show="form.status" class="vexalso">
        <legend>Also apply to the other {{ siblings.length }} component{{ siblings.length === 1 ? "" : "s" }} with {{ v.id }}</legend>
        <label class="chk"><input type="checkbox" :checked="allChecked" @change="toggleAll"> Select all</label>
        <label v-for="s in siblings" :key="s.key" class="chk">
          <input type="checkbox" :checked="alsoKeys.has(s.key)" @change="toggleOne(s.key, $event.target.checked)">
          <span class="mono">{{ s.package }} {{ s.installed }}</span>
          <span v-if="vex.get(s.key)" class="kv">(has an assessment: {{ STATUS_LABEL[vex.get(s.key).status] }}, will be replaced)</span>
        </label>
      </fieldset>
      <div v-show="form.status" class="vexmeta">
        <label>Assessed by
          <input v-model="form.author" type="text" placeholder="Name or team (optional)">
        </label>
        <label>Review by
          <input v-model="form.expires" type="date">
        </label>
      </div>
      <div v-show="form.status && form.expires" class="kv">After this date the assessment stays on record but the finding is shown again.</div>
      <div class="row">
        <button type="button" @click="save">Save</button>
        <button type="button" class="ghost" v-show="existing" @click="clear">Remove assessment</button>
      </div>
      <div class="vexerr">{{ err }}</div>
    </div>
  </details>
</template>
