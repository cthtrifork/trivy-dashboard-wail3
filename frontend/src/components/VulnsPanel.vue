<script setup>
import { computed, reactive } from "vue";
import { result, vulns, vex, SEVERITIES, sevStyle } from "../store.js";
import { tierStyle, pct, detailUrl, openUrl as open, COLUMN_HELP, cvssFloor } from "../lib/format.js";
import { sortRows, sortBy, sortClass } from "../lib/sorting.js";
import { useVirtualList } from "../lib/virtual.js";
import Chip from "./Chip.vue";
import SummaryCard from "./SummaryCard.vue";
import VexBox from "./VexBox.vue";

const state = reactive({ filter: "", vex: "", sort: "priority", dir: 1, hidden: new Set() });
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
  const vexOk = (v) => {
    const s = vex.value.get(v.key)?.status;
    return !state.vex || (state.vex === "none" ? !s : s === state.vex);
  };
  const kept = all.value.filter(
    (v) => !state.hidden.has(v.severity) && vexOk(v) && (!q || [v.id, v.package, v.title, v.installed, v.fixed].join(" ").toLowerCase().includes(q)),
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
    <select id="vuln-vex" v-model="state.vex" aria-label="Filter by VEX status">
      <option value="">Any VEX status</option>
      <option value="none">No statement</option>
      <option value="under_investigation">Under investigation</option>
      <option value="affected">Affected</option>
      <option value="not_affected">Not affected</option>
      <option value="fixed">Fixed</option>
    </select>
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
        <col style="width: 92px" />
        <col style="width: 60px" />
        <col style="width: 150px" />
        <col />
      </colgroup>
      <thead>
        <tr>
          <th v-for="[col, label] in COLUMNS" :key="col" :class="sortClass(state, col)" :title="COLUMN_HELP[col]" @click="sortBy(state, col)">{{ label }}</th>
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
            <span class="sev sevpill tier" :style="tierStyle(v.tier)" :title="v.tierWhy">{{ v.tier }} {{ v.priority }}</span>
          </td>
          <td>
            <span class="sev sevpill" :style="sevStyle(v.severity)">{{ v.severity }}</span>
          </td>
          <td class="mono" style="white-space: nowrap">
            <a v-if="detailUrl(v)" :href="detailUrl(v)" title="Open CVE details" @click.stop.prevent="open(detailUrl(v))">{{ v.id }}</a>
            <template v-else>{{ v.id }}</template>
          </td>
          <td class="mono">{{ v.package }}</td>
          <td class="mono">{{ v.installed }}</td>
          <td class="mono">{{ v.fixed || "—" }}</td>
          <td>
            <span class="meter" :class="{ est: !v.score && cvssFloor(v.severity) }" :style="sevStyle(v.severity)">
              <b :title="v.score ? 'Reported CVSS score' : COLUMN_HELP.estimated">{{ v.score ? v.score.toFixed(1) : cvssFloor(v.severity) ? "~" + cvssFloor(v.severity).toFixed(1) : "–" }}</b>
              <em v-if="!v.score && cvssFloor(v.severity)" :title="COLUMN_HELP.estimated">est.</em>
              <i :style="{ '--w': (v.score || cvssFloor(v.severity)) * 10 + '%' }"></i>
            </span>
          </td>
          <td>{{ v.hasEpss ? pct(v.epss) : "—" }}</td>
          <td>
            <Chip v-if="v.kev" kind="hot" title="Known exploited (CISA)">KEV</Chip>{{ " " }}
            <Chip v-if="vex.get(v.key)" kind="vex">VEX: {{ vex.get(v.key).status.replace("_", " ") }}</Chip>
          </td>
          <td>{{ v.title }}</td>
        </tr>
        <tr v-if="expanded.has(rowKey(v))" class="detail">
          <td colspan="10">
            <div class="vdetail">
              <p class="attack">{{ v.attack }}</p>
              <dl class="vmeta">
                <dt>Target</dt>
                <dd>{{ v.target }}</dd>
                <dt>Status</dt>
                <dd>{{ v.status || "—" }}</dd>
              </dl>
              <div class="vdesc">{{ v.description || "No description." }}</div>
              <p v-if="detailUrl(v)">
                <a class="mono" :href="detailUrl(v)" @click.prevent="open(detailUrl(v))">{{ detailUrl(v) }}</a>
              </p>
              <VexBox :v="v" />
            </div>
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
