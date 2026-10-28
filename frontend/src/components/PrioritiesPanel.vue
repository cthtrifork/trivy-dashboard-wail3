<script setup>
import { computed, reactive, ref } from "vue";
import { result, vulns, vex } from "../store.js";
import { suppresses, isExpired, TIER_COLOR, tierStyle, STATUS_LABEL, COLUMN_HELP, pct, detailUrl, openUrl } from "../lib/format.js";
import Chip from "./Chip.vue";
import CvssBreakdown from "./CvssBreakdown.vue";
import CvssMeter from "./CvssMeter.vue";
import Ratings from "./Ratings.vue";
import RulesEditor from "./RulesEditor.vue";
import VexBox from "./VexBox.vue";
import WhereItLives from "./WhereItLives.vue";
import SuppressedRow from "./SuppressedRow.vue";
import { cvssText } from "../lib/glance.js";
import { useVirtualList } from "../lib/virtual.js";
import { findingPath, indexNodes } from "../lib/where.js";

const prio = reactive({ top: 10, hideResolved: true, fixableOnly: false, groupBy: "none" });
const TIERS = Object.keys(TIER_COLOR);
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
// Empty set = no filter. Both are view filters that run after ranking, like the toolbar ones.
const sevFilter = reactive(new Set());
const tierFilter = reactive(new Set());
const expanded = reactive(new Set());
const collapsedGroups = reactive(new Set());
const flip = (set, x) => (set.has(x) ? set.delete(x) : set.add(x));
const sevStyle = (v) => ({ "--c": `var(--${SEVERITIES.includes(v.severity) ? v.severity : "UNKNOWN"})` });
const label = (s) => s[0] + s.slice(1).toLowerCase();
const AV = { N: "Network", A: "Adjacent", L: "Local", P: "Physical" };

const isResolved = (v) => suppresses(vex.value.get(v.key));
const all = computed(() => vulns.value);
const hidden = computed(() => all.value.filter((v) => prio.hideResolved && isResolved(v)));
const open = computed(() => all.value.filter((v) => !(prio.hideResolved && isResolved(v)) && (!prio.fixableOnly || v.fixed)));
// The suppressed list is not virtualised, so it is paged to keep the DOM small.
// One CVE hits several components (a module and its sub-packages, a library bundled twice): group by
// id so it appears once with the components as children. Pages count groups, not findings.
const SUPPRESSED_PAGE = 25;
const supPage = ref(0);
const supGroups = computed(() => {
  const m = new Map();
  for (const v of hidden.value) (m.get(v.id) ?? m.set(v.id, []).get(v.id)).push(v);
  return [...m].map(([id, items]) => ({ id, items }));
});
const supPages = computed(() => Math.max(1, Math.ceil(supGroups.value.length / SUPPRESSED_PAGE)));
// Clamp instead of resetting: removing the last row of a page must not jump back to page 1.
const supCurrent = computed(() => Math.min(supPage.value, supPages.value - 1));
const suppressedShown = computed(() => supGroups.value.slice(supCurrent.value * SUPPRESSED_PAGE, (supCurrent.value + 1) * SUPPRESSED_PAGE));
// Monitor findings are always listed (ranked last); the Priority filter narrows to a tier when asked.
const passTier = (v) => !tierFilter.size || tierFilter.has(v.tier);
const passSev = (v) => !sevFilter.size || sevFilter.has(v.severity);
const pool = computed(() => open.value.filter((v) => passTier(v) && passSev(v)));
const list = computed(() => (prio.top ? pool.value.slice(0, prio.top) : pool.value));
// Each filter's counts respect the other one, so a segment never promises rows the list will not show.
const tierCount = computed(() => Object.fromEntries(TIERS.map((t) => [t, open.value.filter((v) => passSev(v) && v.tier === t).length])));
const sevCount = computed(() => Object.fromEntries(SEVERITIES.map((s) => [s, open.value.filter((v) => passTier(v) && v.severity === s).length])));
const sevShown = computed(() => SEVERITIES.filter((s) => s !== "UNKNOWN" || sevCount.value.UNKNOWN || sevFilter.has(s)));
const actN = computed(() => open.value.filter((v) => v.tier === "Act now" || v.tier === "Fix soon").length);
const filtered = computed(() => sevFilter.size > 0 || tierFilter.size > 0);
const clearFilters = () => {
  sevFilter.clear();
  tierFilter.clear();
};
const kevN = computed(() => open.value.filter((v) => v.kev).length);

const note = computed(
  () =>
    `${all.value.length} findings → ${actN.value} worth acting on` +
    (kevN.value ? `, ${kevN.value} known exploited` : "") +
    (hidden.value.length ? ` · ${hidden.value.length} hidden by VEX` : ""),
);
const signals = computed(() => {
  const en = result.value?.enrichment || {};
  const notes = [];
  if (en.kev) notes.push(`CISA KEV ${en.kevDate}`);
  if (en.epss) notes.push("EPSS");
  return (
    `Ranked by exploitation evidence, then reachability and severity. Signals: ${notes.join(", ") || "CVSS only"}.` +
    (en.warnings?.length ? " ⚠ " + en.warnings.join("; ") + " — ranking uses CVSS only for the missing signals." : "")
  );
});
// "all" can be thousands of rows: render only the ones in view. Rows sit flush (no flex gap), so a
// spacer stands in for its rows with no correction; GAP stays so the spacer maths is the same as elsewhere.
const GAP = 0;
const cardKey = (v) => v.key + "|" + v.target;
// What the virtual list renders: findings with their rank, or, grouped by binary, a header row before each
// binary's findings. Rank is the position in the ranked list, so it survives grouping. Groups appear in the
// order of their best-ranked finding. Grouping runs after the top-N cut, so a group only counts what is shown.
const NO_BINARY = "Not in a binary (OS packages)";
const nodeIndex = computed(() => indexNodes(result.value?.depNodes));
const binaryOf = (v) => findingPath(result.value, nodeIndex.value, v)?.chain[0]?.name ?? NO_BINARY;
const displayed = computed(() => {
  if (prio.groupBy !== "binary") return list.value.map((v, i) => ({ v, rank: i + 1 }));
  const groups = new Map();
  list.value.forEach((v, i) => {
    const name = binaryOf(v);
    (groups.get(name) ?? groups.set(name, []).get(name)).push({ v, rank: i + 1 });
  });
  const out = [];
  for (const [name, items] of groups) {
    const worst = TIERS.find((t) => items.some((r) => r.v.tier === t));
    out.push({ head: { name, count: items.length, worst, off: collapsedGroups.has(name) } });
    if (!collapsedGroups.has(name)) out.push(...items);
  }
  return out;
});
const itemKey = (it) => (it.head ? "group|" + it.head.name : cardKey(it.v));
const { scroller, rows: visible, before, after, vMeasure } = useVirtualList(displayed, { key: itemKey, estimate: 46, gap: GAP });
const toggleRow = (v) => flip(expanded, cardKey(v));
const attackVector = (v) => /AV:([NALP])/.exec(v.vector)?.[1];

defineExpose({ count: computed(() => pool.value.length) });
</script>

<template>
  <div id="prio-filters">
    <span class="flabel">Severity</span>
    <div class="pseg" id="prio-sev">
      <button
        v-for="s in sevShown"
        :key="s"
        type="button"
        :class="{ on: sevFilter.has(s) }"
        :style="{ '--c': `var(--${s})` }"
        :aria-pressed="sevFilter.has(s)"
        @click="flip(sevFilter, s)"
      >
        <i></i>{{ label(s) }} <b>{{ sevCount[s] }}</b>
      </button>
    </div>
    <span class="flabel">Priority</span>
    <div class="pseg" id="prio-tier">
      <button
        v-for="t in TIERS"
        :key="t"
        type="button"
        :class="{ on: tierFilter.has(t) }"
        :style="{ '--c': `var(${TIER_COLOR[t]})` }"
        :aria-pressed="tierFilter.has(t)"
        @click="flip(tierFilter, t)"
      >
        <i></i>{{ t }} <b>{{ tierCount[t] }}</b>
      </button>
    </div>
    <button v-if="filtered" type="button" class="ghost" id="prio-clear" @click="clearFilters">Clear filters</button>
  </div>
  <RulesEditor />
  <div class="toolbar">
    <label class="chk"
      >Show
      <select id="prio-top" v-model.number="prio.top">
        <option :value="10">top 10</option>
        <option :value="25">top 25</option>
        <option :value="0">all</option>
      </select>
    </label>
    <label class="chk"><input type="checkbox" id="prio-hide" v-model="prio.hideResolved" /> Hide resolved by VEX</label>
    <label class="chk"><input type="checkbox" id="prio-fixable" v-model="prio.fixableOnly" /> Only with a fix</label>
    <label class="chk"
      >Group by
      <select id="prio-group" v-model="prio.groupBy" title="Binary: the program in the image that bundles the vulnerable package">
        <option value="none">none</option>
        <option value="binary">binary</option>
      </select>
    </label>
    <span id="prio-note">{{ note }}</span>
  </div>
  <div id="prio-list" class="scroll" ref="scroller">
    <div v-if="!result" class="empty">Run a scan to see what matters most.</div>
    <div v-else-if="!all.length" class="empty">No vulnerabilities found 🎉</div>
    <template v-else>
      <div class="kv">{{ signals }}</div>
      <div v-if="before > 0" class="pad" :style="{ height: before - GAP + 'px' }"></div>
      <div class="ptable-head" aria-hidden="true">
        <span :title="COLUMN_HELP.severity">Severity</span><span :title="COLUMN_HELP.score">CVSS</span><span title="Title, CVE id, and the affected package and installed version">Finding</span
        ><span :title="COLUMN_HELP.priority">Priority</span><span :title="COLUMN_HELP.fixed">Fix</span>
      </div>
      <template v-for="{ item: { head, v, rank } } in visible" :key="head ? 'group|' + head.name : cardKey(v)">
      <button
        v-if="head"
        v-measure="'group|' + head.name"
        type="button"
        class="pgroup"
        :aria-expanded="!head.off"
        @click="flip(collapsedGroups, head.name)"
      >
        <span class="pgroup-caret" aria-hidden="true">{{ head.off ? "▶" : "▼" }}</span>
        <span class="mono pgroup-name">{{ head.name }}</span>
        <span class="kv">{{ head.count }} {{ head.count === 1 ? "finding" : "findings" }}</span>
        <span class="sev sevpill tier" :style="tierStyle(head.worst)" title="Highest priority tier in this group">{{ head.worst }}</span>
      </button>
      <div v-else v-measure="cardKey(v)" class="prow" :class="{ open: expanded.has(cardKey(v)) }" :style="sevStyle(v)">
        <div class="prow-main">
          <span class="sev sevpill" :class="v.severity">{{ v.severity }}</span>
          <CvssMeter :score="v.score" :severity="v.severity" />
          <span class="pfind">
            <span class="ptitle"
              ><button type="button" class="pexpand" :aria-expanded="expanded.has(cardKey(v))" @click.stop="toggleRow(v)">{{ v.title || v.id }}</button></span
            >
            <span class="psub">
              <span class="rank">#{{ rank }}</span>
              <a v-if="detailUrl(v)" class="id" :href="detailUrl(v)" title="Open CVE details" @click.prevent.stop="openUrl(detailUrl(v))">{{ v.id }}</a>
              <span v-else class="id">{{ v.id }}</span>
              <span class="mono">{{ v.package }} {{ v.installed }}</span>
            </span>
          </span>
          <span class="ptier"
            ><span class="sev sevpill tier" :style="tierStyle(v.tier)" :title="v.tierWhy">{{ v.tier }} {{ v.priority }}</span
            ><Chip v-if="v.kev" kind="hot" :title="`Added to CISA KEV on ${v.kevAdded}; due ${v.kevDue}. ${v.kevAction}`">KEV</Chip></span
          >
          <span class="pfix" :title="v.fixed || undefined">{{ v.fixed || "None" }}</span>
        </div>
        <div v-if="expanded.has(cardKey(v))" class="pdetail">
          <div class="chips">
            <Chip v-if="v.kev && v.kevRansomware" kind="hot">Ransomware use</Chip>
            <Chip
              v-if="v.hasEpss"
              :kind="v.epss >= 0.1 ? 'warm' : ''"
              :title="`Exploitation probability in the next 30 days; percentile ${(v.epssPercentile * 100).toFixed(1)}`"
              >EPSS {{ pct(v.epss) }}</Chip
            >
            <Chip v-if="attackVector(v)" :kind="attackVector(v) === 'N' ? 'warm' : ''" :title="v.vector">{{ AV[attackVector(v)] }}</Chip>
            <Chip>{{ v.fixed ? "Fix: " + v.fixed : "No fix yet" }}</Chip>
            <Chip
              v-if="vex.get(v.key)"
              :kind="isExpired(vex.get(v.key)) ? 'warm' : 'vex'"
              :title="isExpired(vex.get(v.key)) ? `Expired ${vex.get(v.key).expires}: shown again until reassessed` : ''"
              >VEX: {{ STATUS_LABEL[vex.get(v.key).status] }}{{ isExpired(vex.get(v.key)) ? " · expired" : "" }}</Chip
            >
          </div>
          <Ratings :v="v" />
          <WhereItLives :v="v" />
          <div class="pmeans">
            <small>What it means</small>
            <p class="attack">
              <b>CVSS {{ cvssText(v) }}.</b> {{ v.attack }}
            </p>
            <CvssBreakdown :vector="v.vector" />
          </div>
          <div class="pfoot">
            <details class="scorebox">
              <summary>Score {{ v.priority }} · why</summary>
              <ul class="why">
                <li v-for="(r, j) in v.reasons" :key="j">
                  <span :class="['pts', { pos: r.points > 0 }]">{{ r.points > 0 ? "+" : "" }}{{ r.points }}</span>
                  <span
                    >{{ r.text }} <code class="rule" title="The rule that fired, with the current thresholds">{{ r.rule }}</code></span
                  >
                </li>
                <li class="tierwhy">
                  <span class="pts">tier</span><span>{{ v.tierWhy }}</span>
                </li>
              </ul>
            </details>
            <VexBox :v="v" />
          </div>
        </div>
      </div>
      </template>
      <div v-if="after > 0" class="pad" :style="{ height: after - GAP + 'px' }"></div>
      <div v-if="!list.length" class="empty">Nothing left to show with these filters.</div>
      <div v-else-if="pool.length > list.length" class="kv">{{ pool.length - list.length }} more findings not shown — they rank lower.</div>
      <details v-if="hidden.length" id="prio-suppressed" class="suppressed">
        <summary>Suppressed by VEX ({{ hidden.length }})</summary>
        <template v-for="g in suppressedShown" :key="g.id">
          <SuppressedRow v-if="g.items.length === 1" :v="g.items[0]" />
          <details v-else class="sup supgroup">
            <summary>
              <span class="id">{{ g.id }}</span>
              <Chip>{{ g.items.length }} components</Chip>
            </summary>
            <SuppressedRow v-for="v in g.items" :key="cardKey(v)" :v="v" child />
          </details>
        </template>
        <div v-if="supPages > 1" class="row pager">
          <button type="button" class="ghost" :disabled="supCurrent === 0" @click="supPage = supCurrent - 1">Previous</button>
          <span class="kv">Page {{ supCurrent + 1 }} of {{ supPages }}</span>
          <button type="button" class="ghost" :disabled="supCurrent >= supPages - 1" @click="supPage = supCurrent + 1">Next</button>
        </div>
      </details>
    </template>
  </div>
</template>
