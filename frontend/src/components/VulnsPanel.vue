<script setup>
import { computed, reactive } from "vue";
import { result, vulns, vex, SEVERITIES, sevStyle } from "../store.js";
import { tierStyle, pct } from "../lib/format.js";
import { sortRows, sortBy, sortClass } from "../lib/sorting.js";
import { useVirtualList } from "../lib/virtual.js";
import Chip from "./Chip.vue";
import SummaryCard from "./SummaryCard.vue";
import VexBox from "./VexBox.vue";

const state = reactive({ filter: "", sort: "priority", dir: 1, hidden: new Set() });
const expanded = reactive(new Set());
const COLUMNS = [
  ["priority", "Priority"],
  ["severity", "Severity"],
  ["id", "ID"],
  ["package", "Package"],
  ["installed", "Installed"],
  ["fixed", "Fixed in"],
  ["score", "CVSS"],
  ["epss", "EPSS"],
  ["signals", "Signals"],
  ["title", "Title"],
];

const toggle = (sev) => (state.hidden.has(sev) ? state.hidden.delete(sev) : state.hidden.add(sev));
const all = computed(() => vulns.value);
const rows = computed(() => {
  const q = state.filter.toLowerCase();
  const kept = all.value.filter(
    (v) => !state.hidden.has(v.severity) && (!q || [v.id, v.package, v.title, v.installed, v.fixed].join(" ").toLowerCase().includes(q)),
  );
  const signalRank = (v) => (v.kev ? 2 : 0) + (vex.value.has(v.key) ? 1 : 0);
  return sortRows(kept, state, (v, k) =>
    k === "severity"
      ? SEVERITIES.indexOf(v.severity)
      : k === "score"
        ? -v.score
        : k === "priority"
          ? -v.priority
          : k === "epss"
            ? -v.epss
            : k === "signals"
              ? -signalRank(v)
              : (v[k] ?? ""),
  );
});
const emptyText = computed(() => (all.value.length ? "No vulnerabilities match the filter." : "No vulnerabilities found 🎉"));
const rowKey = (v) => v.key + "|" + v.target;
const { scroller, rows: visible, before, after, vMeasure } = useVirtualList(rows, { key: (v) => rowKey(v) });
const isLink = (url) => /^https?:\/\//.test(url);
</script>

<template>
  <div id="sev-cards">
    <SummaryCard
      v-for="s in SEVERITIES"
      :key="s"
      clickable
      :count="result?.severityCounts[s] || 0"
      :label="s"
      :color="`var(${'--' + s})`"
      :off="state.hidden.has(s)"
      @click="toggle(s)"
    />
  </div>
  <div class="toolbar">
    <input id="vuln-filter" v-model="state.filter" placeholder="Filter by CVE, package, title…" autocomplete="off" />
    <span id="vuln-shown">{{ rows.length }} shown</span>
  </div>
  <div class="table-wrap" ref="scroller">
    <table id="vuln-table" class="vt">
      <colgroup>
        <col style="width: 110px" />
        <col style="width: 90px" />
        <col style="width: 140px" />
        <col style="width: 16%" />
        <col style="width: 100px" />
        <col style="width: 100px" />
        <col style="width: 56px" />
        <col style="width: 60px" />
        <col style="width: 150px" />
        <col />
      </colgroup>
      <thead>
        <tr>
          <th v-for="[col, label] in COLUMNS" :key="col" :class="sortClass(state, col)" @click="sortBy(state, col)">{{ label }}</th>
        </tr>
      </thead>
      <tbody class="pad">
        <tr :style="{ height: before + 'px' }">
          <td colspan="10"></td>
        </tr>
      </tbody>
      <tbody v-for="{ item: v } in visible" :key="rowKey(v)" v-measure="rowKey(v)">
        <tr class="row" @click="expanded.has(rowKey(v)) ? expanded.delete(rowKey(v)) : expanded.add(rowKey(v))">
          <td>
            <span class="sev tier" :style="tierStyle(v.tier)">{{ v.tier }} {{ v.priority }}</span>
          </td>
          <td>
            <span class="sev" :style="sevStyle(v.severity)">{{ v.severity }}</span>
          </td>
          <td class="mono" style="white-space: nowrap">{{ v.id }}</td>
          <td class="mono">{{ v.package }}</td>
          <td class="mono">{{ v.installed }}</td>
          <td class="mono">{{ v.fixed || "—" }}</td>
          <td>{{ v.score ? v.score.toFixed(1) : "—" }}</td>
          <td>{{ v.hasEpss ? pct(v.epss) : "—" }}</td>
          <td>
            <Chip v-if="v.kev" kind="hot" title="Known exploited (CISA)">KEV</Chip>{{ " " }}
            <Chip v-if="vex.get(v.key)" kind="vex">VEX: {{ vex.get(v.key).status.replace("_", " ") }}</Chip>
          </td>
          <td>{{ v.title }}</td>
        </tr>
        <tr v-if="expanded.has(rowKey(v))" class="detail">
          <td colspan="10">
            <p class="attack">{{ v.attack }}</p>
            {{ `Target: ${v.target}\nStatus: ${v.status || "—"}\n\n${v.description || "No description."}\n\n` }}
            <template v-if="isLink(v.url)"
              ><span class="mono">{{ v.url }}</span
              >{{ "\n" }}</template
            >
            <VexBox :v="v" />
          </td>
        </tr>
      </tbody>
      <tbody class="pad">
        <tr :style="{ height: after + 'px' }">
          <td colspan="10"></td>
        </tr>
      </tbody>
    </table>
    <div v-if="!rows.length" class="empty" id="vuln-empty">{{ result ? emptyText : "Run a scan to see vulnerabilities." }}</div>
  </div>
</template>
