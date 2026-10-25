<script setup>
import { SEVERITIES, sevStyle } from "../store.js";

// own: counts in this package; total: counts including everything it pulls in.
defineProps({ own: { type: Object, required: true }, total: { type: Object, required: true } });
const ABBR = { CRITICAL: "C", HIGH: "H", MEDIUM: "M", LOW: "L", UNKNOWN: "U" };
</script>

<template>
  <span class="sevs">
    <template v-for="s in SEVERITIES" :key="s">
      <span
        v-if="total[s]" :class="['sev', { dim: !own[s] }]" :style="sevStyle(s)"
        :title="`${s}: ${own[s] || 0} in this package, ${total[s]} including dependencies`"
      >{{ ABBR[s] }} {{ total[s] }}</span>
    </template>
  </span>
</template>
