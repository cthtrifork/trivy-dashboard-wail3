<script setup>
import { computed, ref } from "vue";
import { cvssFloor, sourceName } from "../lib/format.js";

const props = defineProps({ v: { type: Object, required: true } });
const rows = computed(() => props.v.ratings || []);
// Sources that gave a severity but no score say little, so list the scored ones and keep the rest behind a toggle.
const scored = computed(() => rows.value.filter((r) => r.score));
const unscored = computed(() => rows.value.filter((r) => !r.score));
const showAll = ref(false);
const shown = computed(() => (showAll.value ? [...scored.value, ...unscored.value] : scored.value));
const top = computed(() => rows.value.reduce((a, r) => (r.score > (a?.score ?? 0) ? r : a), null));
// Why the headline score is what it is: preferred source (Red Hat, then NVD) or the highest published.
const basis = computed(() => {
  const v = props.v;
  if (!v.score) return cvssFloor(v.severity) ? `No source published a CVSS score. ~${cvssFloor(v.severity).toFixed(1)} is an estimate: the lowest score of ${v.severity} severity.` : "";
  const from = sourceName(v.scoreSource);
  const preferred = v.scoreSource === "redhat" || v.scoreSource === "nvd";
  const t = top.value;
  const higher = t && t.score > v.score ? `; ${t.score.toFixed(1)} highest (${sourceName(t.source)})` : "";
  return preferred ? `CVSS ${v.score.toFixed(1)} from ${from}${higher}` : `CVSS ${v.score.toFixed(1)} highest published (${from})`;
});
</script>

<template>
  <div v-if="rows.length || basis" class="ratings">
    <small>Ratings by source</small>
    <p v-if="basis" class="kv">{{ basis }}</p>
    <table v-if="shown.length">
      <tbody>
        <tr v-for="r in shown" :key="r.source" :class="{ used: r.source === v.scoreSource }">
          <td>{{ sourceName(r.source) }}</td>
          <td>
            <span v-if="r.severity" class="sev sevpill" :class="r.severity" :style="{ '--c': `var(--${r.severity})` }">{{ r.severity }}</span>
            <span v-else class="kv">—</span>
          </td>
          <td class="mono">{{ r.score ? r.score.toFixed(1) : "—" }}</td>
          <td class="kv">{{ r.source === v.scoreSource ? "score shown" : "" }}</td>
        </tr>
      </tbody>
    </table>
    <button v-if="unscored.length" type="button" class="link" :aria-expanded="showAll" @click="showAll = !showAll">
      {{ showAll ? "Hide sources without a score" : `Show ${unscored.length} more ${unscored.length === 1 ? "source" : "sources"} without a score` }}
    </button>
  </div>
</template>
