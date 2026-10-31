<script setup>
import { computed } from "vue";
import { COLUMN_HELP } from "../lib/format.js";

const props = defineProps({ score: { type: Number, default: 0 }, estimate: { type: Number, default: 0 } });
// No published score: show the estimate Go supplies (the severity band floor) and say so, so it is never read as reported.
const floor = computed(() => (props.score ? 0 : props.estimate));
const est = computed(() => floor.value > 0);
</script>

<template>
  <span class="meter" :class="{ est }">
    <b :title="score ? 'Reported CVSS score' : est ? COLUMN_HELP.estimated : ''">{{ score ? score.toFixed(1) : est ? "~" + floor.toFixed(1) : "–" }}</b>
    <i :style="{ '--w': (score || floor) * 10 + '%' }"></i>
  </span>
</template>
