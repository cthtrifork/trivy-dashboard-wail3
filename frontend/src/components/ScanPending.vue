<script setup>
// Placeholder for a view whose data arrives when the running scan (or compare) finishes.
// "rows" mimics the Priorities list, "table" a plain table with `cols` columns, "graph" the dependency graph.
import { computed } from "vue";
import { image, status, comparing, cmpForm, cmpBase } from "../store.js";

const props = defineProps({
  kind: { type: String, default: "rows" },
  cols: { type: Number, default: 5 },
  count: { type: Number, default: 6 },
});

const subject = computed(() => (comparing.value ? `${cmpBase.value.repo}:${cmpBase.value.tag} and ${cmpForm.b}` : image.value.trim()));
// Trivy's latest log line, as the status bar shows it.
const detail = computed(() => (status.busy ? status.msg : ""));
// Fixed width cycle, so the bars look like text without randomness (a re-render must not reshuffle them).
const width = (i, j = 0) => 38 + ((i * 17 + j * 29) % 5) * 11 + "%";
const rows = computed(() => Array.from({ length: props.count }, (_, i) => i));
</script>

<template>
  <div class="sp" :class="kind" role="status">
    <div class="sp-note spin">
      <span>Scanning {{ subject }}… results appear here when it finishes.</span>
      <span v-if="detail" class="sp-log mono">{{ detail }}</span>
    </div>
    <template v-if="kind === 'rows'">
      <div class="ptable-head" aria-hidden="true"><span>Severity</span><span>CVSS</span><span>Finding</span><span>Priority</span><span>Fix</span></div>
      <div v-for="i in rows" :key="i" class="sp-row" aria-hidden="true">
        <i class="sp-bar sp-pill"></i>
        <i class="sp-bar sp-meter"></i>
        <span class="sp-two"><i class="sp-bar" :style="{ width: width(i) }"></i><i class="sp-bar sp-small" :style="{ width: width(i, 1) }"></i></span>
        <i class="sp-bar sp-pill sp-wide"></i>
        <i class="sp-bar sp-fix"></i>
      </div>
    </template>
    <template v-else-if="kind === 'table'">
      <div v-for="i in rows" :key="i" class="sp-trow" :style="{ '--n': cols }" aria-hidden="true">
        <i v-for="j in cols" :key="j" class="sp-bar" :style="{ width: width(i, j) }"></i>
      </div>
    </template>
    <svg v-else class="sp-graph" viewBox="0 0 300 200" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
      <g class="sp-bar-line">
        <line x1="150" y1="100" x2="70" y2="50" />
        <line x1="150" y1="100" x2="230" y2="55" />
        <line x1="150" y1="100" x2="90" y2="155" />
        <line x1="150" y1="100" x2="225" y2="150" />
        <line x1="70" y1="50" x2="30" y2="95" />
        <line x1="230" y1="55" x2="270" y2="100" />
      </g>
      <g class="sp-bar-dot">
        <circle cx="150" cy="100" r="14" />
        <circle cx="70" cy="50" r="9" />
        <circle cx="230" cy="55" r="9" />
        <circle cx="90" cy="155" r="9" />
        <circle cx="225" cy="150" r="9" />
        <circle cx="30" cy="95" r="6" />
        <circle cx="270" cy="100" r="6" />
      </g>
    </svg>
  </div>
</template>
