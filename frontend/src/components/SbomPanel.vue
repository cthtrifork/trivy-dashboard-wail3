<script setup>
import { computed, reactive } from "vue";
import { result } from "../store.js";
import { sortRows, sortBy, sortClass } from "../lib/sorting.js";
import { useVirtualList } from "../lib/virtual.js";
import SummaryCard from "./SummaryCard.vue";

const state = reactive({ filter: "", sort: "name", dir: 1, hidden: new Set() });
const COLUMNS = [["name", "Name"], ["version", "Version"], ["type", "Type"], ["licenses", "License"], ["purl", "Package URL"]];

const toggle = (type) => (state.hidden.has(type) ? state.hidden.delete(type) : state.hidden.add(type));
const components = computed(() => result.value?.components ?? []);
const types = computed(() => Object.entries(result.value?.componentTypes ?? {}).sort((a, b) => b[1] - a[1]));
const rows = computed(() => {
  const q = state.filter.toLowerCase();
  const kept = components.value.filter(
    (c) => !state.hidden.has(c.type) && (!q || [c.name, c.version, c.purl, c.licenses.join(" ")].join(" ").toLowerCase().includes(q))
  );
  return sortRows(kept, state, (c, k) => (k === "licenses" ? c.licenses.join(", ") : c[k] ?? ""));
});
const { scroller, rows: visible, before, after, vMeasure } = useVirtualList(rows, { key: (_, i) => i });
</script>

<template>
  <p id="sbom-summary" class="summary" v-if="result?.summary?.text">{{ result.summary.text }}</p>
  <div id="type-cards" v-if="result">
    <!-- the "total" card is informational only -->
    <SummaryCard :count="components.length" label="total" color="var(--accent)" />
    <SummaryCard
      v-for="[type, n] in types" :key="type" clickable
      :count="n" :label="type" color="var(--accent)" :off="state.hidden.has(type)"
      @click="toggle(type)"
    />
  </div>
  <div class="toolbar">
    <input id="sbom-filter" v-model="state.filter" placeholder="Filter by name, version, license, purl…" autocomplete="off">
    <span id="sbom-shown">{{ rows.length }} shown<template v-if="result"> · {{ result.sbomFormat }}</template></span>
  </div>
  <div class="table-wrap" ref="scroller">
    <table id="sbom-table" class="vt">
      <colgroup><col style="width:28%"><col style="width:14%"><col style="width:10%"><col style="width:14%"><col></colgroup>
      <thead>
        <tr><th v-for="[col, label] in COLUMNS" :key="col" :class="sortClass(state, col)" @click="sortBy(state, col)">{{ label }}</th></tr>
      </thead>
      <tbody class="pad"><tr :style="{ height: before + 'px' }"><td colspan="5"></td></tr></tbody>
      <tbody v-for="{ item: c, index } in visible" :key="index" v-measure="index">
        <tr>
          <td class="mono">{{ (c.group ? c.group + "/" : "") + c.name }}</td>
          <td class="mono">{{ c.version || "—" }}</td>
          <td>{{ c.type }}</td>
          <td>{{ c.licenses.join(", ") || "—" }}</td>
          <td class="mono">{{ c.purl || "—" }}</td>
        </tr>
      </tbody>
      <tbody class="pad"><tr :style="{ height: after + 'px' }"><td colspan="5"></td></tr></tbody>
    </table>
    <div v-if="!rows.length" class="empty" id="sbom-empty">{{ result ? "No components match the filter." : "Run a scan to see the SBOM." }}</div>
  </div>
</template>
