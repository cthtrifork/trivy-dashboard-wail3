<script setup>
import { computed, reactive } from "vue";
import { result, vex } from "../store.js";
import { RESOLVED, TIER_COLOR, tierStyle, STATUS_LABEL, pct } from "../lib/format.js";
import Chip from "./Chip.vue";
import SummaryCard from "./SummaryCard.vue";
import VexBox from "./VexBox.vue";
import { useVirtualList } from "../lib/virtual.js";

const emit = defineEmits(["export"]);
const prio = reactive({ top: 10, hideResolved: true, fixableOnly: false, includeLow: false });
const TIERS = Object.keys(TIER_COLOR);
const AV = { N: "Network", A: "Adjacent", L: "Local", P: "Physical" };

const isResolved = (v) => RESOLVED.has(vex.value.get(v.key)?.status);
const all = computed(() => result.value?.vulnerabilities ?? []);
const hidden = computed(() => all.value.filter((v) => prio.hideResolved && isResolved(v)));
const open = computed(() => all.value.filter((v) => !(prio.hideResolved && isResolved(v)) && (!prio.fixableOnly || v.fixed)));
const lowN = computed(() => open.value.filter((v) => v.tier === "Monitor").length);
const pool = computed(() => (prio.includeLow ? open.value : open.value.filter((v) => v.tier !== "Monitor")));
const list = computed(() => (prio.top ? pool.value.slice(0, prio.top) : pool.value));
const tierCount = computed(() => Object.fromEntries(TIERS.map((t) => [t, open.value.filter((v) => v.tier === t).length])));
const kevN = computed(() => open.value.filter((v) => v.kev).length);

const note = computed(
  () =>
    `${all.value.length} findings → ${tierCount.value["Act now"] + tierCount.value["Fix soon"]} worth acting on` +
    (kevN.value ? `, ${kevN.value} known exploited` : "") +
    (hidden.value.length ? ` · ${hidden.value.length} hidden by VEX` : "") +
    (!prio.includeLow && lowN.value ? ` · ${lowN.value} low-risk not shown` : ""),
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
// "all" can be thousands of cards: render only the ones in view. The list is a flex column with a
// 10px gap, so a spacer stands in for its rows minus the one gap the flexbox adds next to it.
const GAP = 10;
const { scroller, rows: visible, before, after, vMeasure } = useVirtualList(list, { key: (v) => cardKey(v), estimate: 250, gap: GAP });
const cardKey = (v) => v.key + "|" + v.target;
const attackVector = (v) => /AV:([NALP])/.exec(v.vector)?.[1];

defineExpose({ count: computed(() => pool.value.length) });
</script>

<template>
  <div id="prio-summary">
    <SummaryCard v-for="t in TIERS" :key="t" :count="tierCount[t]" :label="t" :color="`var(${TIER_COLOR[t]})`" />
  </div>
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
    <label class="chk"><input type="checkbox" id="prio-low" v-model="prio.includeLow" /> Include low-risk (Monitor)</label>
    <label class="chk"><input type="checkbox" id="prio-fixable" v-model="prio.fixableOnly" /> Only with a fix</label>
    <button class="ghost" id="vex-export-btn" @click="emit('export')">Edit/Create VEX ({{ vex.size }})</button>
    <span id="prio-note">{{ note }}</span>
  </div>
  <div id="prio-list" class="scroll" ref="scroller">
    <div v-if="!result" class="empty">Run a scan to see what matters most.</div>
    <div v-else-if="!all.length" class="empty">No vulnerabilities found 🎉</div>
    <template v-else>
      <div class="kv">{{ signals }}</div>
      <div v-if="before > 0" class="pad" :style="{ height: before - GAP + 'px' }"></div>
      <div v-for="{ item: v, index } in visible" :key="cardKey(v)" v-measure="cardKey(v)" class="pcard" :style="tierStyle(v.tier)">
        <div class="rank">{{ index + 1 }}</div>
        <div class="pbody">
          <div class="phead">
            <span class="id">{{ v.id }}</span>
            <span class="sev tier" :style="tierStyle(v.tier)">{{ v.tier }}</span>
            <span class="mono">{{ v.package }} {{ v.installed }}</span>
          </div>
          <div class="chips">
            <Chip title="CVSS severity">{{ v.severity }}{{ v.score ? ` ${v.score.toFixed(1)}` : "" }}</Chip>
            <Chip v-if="v.kev" kind="hot" :title="`Added to CISA KEV on ${v.kevAdded}; due ${v.kevDue}. ${v.kevAction}`"
              >KEV{{ v.kevRansomware ? " · ransomware" : "" }}</Chip
            >
            <Chip
              v-if="v.hasEpss"
              :kind="v.epss >= 0.1 ? 'warm' : ''"
              :title="`Exploitation probability in the next 30 days; percentile ${(v.epssPercentile * 100).toFixed(1)}`"
              >EPSS {{ pct(v.epss) }}</Chip
            >
            <Chip v-if="attackVector(v)" :kind="attackVector(v) === 'N' ? 'warm' : ''" :title="v.vector">{{ AV[attackVector(v)] }}</Chip>
            <Chip>{{ v.fixed ? "Fix: " + v.fixed : "No fix yet" }}</Chip>
            <Chip v-if="vex.get(v.key)" kind="vex">VEX: {{ STATUS_LABEL[vex.get(v.key).status] }}</Chip>
          </div>
          <p class="attack">{{ v.attack }}</p>
          <div v-if="v.title" class="kv">{{ v.title }}</div>
          <ul class="why">
            <li v-for="(r, j) in v.reasons" :key="j">
              <span :class="['pts', { pos: r.points > 0 }]">{{ r.points > 0 ? "+" : "" }}{{ r.points }}</span>
              <span>{{ r.text }}</span>
            </li>
          </ul>
          <VexBox :v="v" />
        </div>
        <div class="score">
          <b>{{ v.priority }}</b
          >score
        </div>
      </div>
      <div v-if="after > 0" class="pad" :style="{ height: after - GAP + 'px' }"></div>
      <div v-if="!list.length" class="empty">Nothing left to show with these filters.</div>
      <div v-else-if="pool.length > list.length" class="kv">{{ pool.length - list.length }} more findings not shown — they rank lower.</div>
    </template>
  </div>
</template>
