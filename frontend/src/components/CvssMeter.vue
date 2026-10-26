<script setup>
import { computed } from "vue";
import { COLUMN_HELP, cvssFloor } from "../lib/format.js";

const props = defineProps({ score: { type: Number, default: 0 }, severity: { type: String, default: "" } });
// No published score: fall back to the severity band floor and say so, so it is never read as reported.
const floor = computed(() => (props.score ? 0 : cvssFloor(props.severity)));
const est = computed(() => floor.value > 0);
</script>

<template>
  <span class="meter" :class="{ est }">
    <b :title="score ? 'Reported CVSS score' : est ? COLUMN_HELP.estimated : ''">{{ score ? score.toFixed(1) : est ? "~" + floor.toFixed(1) : "–" }}</b>
    <em v-if="est" :title="COLUMN_HELP.estimated">est.</em>
    <i :style="{ '--w': (score || floor) * 10 + '%' }"></i>
  </span>
</template>
