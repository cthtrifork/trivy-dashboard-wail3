<script setup>
import { computed, reactive, ref } from "vue";
import { ScanService } from "../lib/api.js";
import {
  SEVERITIES,
  sevStyle,
  opts,
  cmpForm,
  cmpBase,
  repoTags,
  ensureTags,
  trivyImageSetting,
  rememberTrivyVersion,
  compareData as data,
  scanning,
  comparing,
  logText,
  setStatus,
  errText,
  lsSet,
  KEYS,
  cancel,
  refreshFootprint,
} from "../store.js";
import { pct } from "../lib/format.js";
import TagInput from "./TagInput.vue";
import Chip from "./Chip.vue";
import ScanPending from "./ScanPending.vue";
import { useVirtualList } from "../lib/virtual.js";

const CHG_COLOR = {
  added: "var(--CRITICAL)",
  removed: "#2fb344",
  unchanged: "var(--UNKNOWN)",
  upgraded: "var(--accent)",
  downgraded: "var(--HIGH)",
};
const CHG_SIGN = { added: "+", removed: "−", unchanged: "=", upgraded: "↑", downgraded: "↓" };
const chgStyle = (c) => ({ "--c": CHG_COLOR[c] });

const view = ref("vulns");
const show = reactive(new Set(["added", "removed"]));
const filter = ref("");

async function run() {
  const req = {
    repo: cmpBase.value.repo,
    tagA: cmpBase.value.tag,
    tagB: cmpForm.b,
    username: opts.username,
    password: opts.password,
    ignoreUnfixed: opts.ignoreUnfixed,
    showSuppressed: opts.showSuppressed,
    ignoreStatus: [...opts.ignoreStatus],
    trivyImage: trivyImageSetting.value,
    ignorePolicy: opts.ignorePolicy,
    ignoreFile: opts.ignoreFile,
  };
  lsSet(KEYS.cmpTarget, cmpForm.b);
  logText.value = "";
  comparing.value = scanning.value = true;
  refreshFootprint();
  setStatus("Scanning both images…", { busy: true });
  try {
    data.value = await ScanService.Compare(req);
    rememberTrivyVersion(req.trivyImage);
    setStatus("Comparison complete.");
  } catch (err) {
    setStatus(errText(err), { err: true });
  } finally {
    comparing.value = scanning.value = false;
    refreshFootprint();
  }
}

const sum = (m) => Object.values(m).reduce((x, y) => x + y, 0);
const net = computed(() => (data.value ? sum(data.value.added) - sum(data.value.removed) : 0));
const verdictColor = computed(() => (net.value < 0 ? "#2fb344" : net.value > 0 ? "var(--CRITICAL)" : "var(--mute)"));
const kinds = computed(() => (view.value === "vulns" ? ["added", "removed", "unchanged"] : ["added", "removed", "upgraded", "downgraded"]));
const counts = computed(() => {
  const c = {};
  for (const x of view.value === "vulns" ? data.value.vulns : data.value.packages) c[x.change] = (c[x.change] || 0) + 1;
  return c;
});
const vulnRows = computed(() => {
  const q = filter.value.toLowerCase();
  return data.value.vulns.filter(
    (x) => show.has(x.change) && (!q || [x.vuln.id, x.vuln.package, x.cause, x.vuln.title].join(" ").toLowerCase().includes(q)),
  );
});
const pkgRows = computed(() => {
  const q = filter.value.toLowerCase();
  return data.value.packages.filter((x) => show.has(x.change) && (!q || x.name.toLowerCase().includes(q)));
});
const current = computed(() => (!data.value ? [] : view.value === "vulns" ? vulnRows.value : pkgRows.value));
const rowCount = computed(() => current.value.length);
// Both tables can run to thousands of rows (a big base-image bump): render only the visible ones.
const { scroller, rows: visible, before, after, vMeasure } = useVirtualList(current, { key: (_, i) => i });

const arrow = (a, b) => (a && b ? `${a} → ${b}` : a || b || "—");
const delta = (a, b) => {
  const d = b - a;
  return { cls: d === 0 ? "flat" : d < 0 ? "good" : "bad", text: d === 0 ? "±0" : (d > 0 ? "+" : "−") + Math.abs(d) };
};
const toggle = (k) => (show.has(k) ? show.delete(k) : show.add(k));
</script>

<template>
  <form id="cmp-form" class="toolbar wrap" @submit.prevent="run">
    <input id="cmp-repo" :value="cmpBase.repo" readonly tabindex="-1" aria-label="Image repository" :title="cmpBase.repo" placeholder="Scan or enter an image above" />
    <label class="chk"
      >Base <input id="cmp-a" :value="cmpBase.tag" readonly tabindex="-1" placeholder="tag" title="The tag of the image at the top"
    /></label>
    <span class="kv">→</span>
    <span class="chk"
      >Target
      <TagInput id="cmp-b" v-model="cmpForm.b" :tags="repoTags" label="Target tag" :disabled="comparing" @open="ensureTags(cmpBase.repo)"
    /></span>
    <button id="cmp-go" type="submit" :disabled="comparing || !cmpBase.repo || !cmpBase.tag">Compare</button>
    <button id="cmp-cancel" type="button" v-show="comparing" @click="cancel">Cancel</button>
  </form>
  <div id="cmp-out" class="scroll">
    <ScanPending v-if="!data && comparing" kind="table" :cols="5" />
    <div v-else-if="!data" class="empty">
      Pick a target tag to compare the scanned image against and see what changed: vulnerabilities added and removed, and package changes.
    </div>
    <template v-else>
      <div class="sides">
        <div
          v-for="[title, s, other, isTarget] in [
            ['Base', data.a, data.b, false],
            ['Target', data.b, data.a, true],
          ]"
          :key="title"
          class="side"
        >
          <h4>{{ title }}: {{ s.ref }}</h4>
          <div class="kv">
            {{ s.os || "unknown OS" }} · {{ s.packages }} packages · {{ s.total }} vulnerabilities{{ s.kev ? ` · ${s.kev} KEV` : "" }}
          </div>
          <div v-for="sev in SEVERITIES" :key="sev" class="sevrow">
            <span class="sev" :style="sevStyle(sev)">{{ sev }}</span>
            <span class="n">{{ s.counts[sev] || 0 }}</span>
            <span v-if="isTarget" :class="['delta', delta(other.counts[sev] || 0, s.counts[sev] || 0).cls]">{{
              delta(other.counts[sev] || 0, s.counts[sev] || 0).text
            }}</span>
          </div>
        </div>
      </div>
      <div class="verdict" :style="{ '--c': verdictColor }">{{ data.verdict }}</div>
      <div class="cmp-controls">
        <div class="seg">
          <button type="button" :class="{ on: view === 'vulns' }" @click="view = 'vulns'">Vulnerabilities ({{ data.vulns.length }})</button>
          <button type="button" :class="{ on: view === 'pkgs' }" @click="view = 'pkgs'">Packages ({{ data.packages.length }})</button>
        </div>
        <label v-for="k in kinds" :key="k" class="chk">
          <input type="checkbox" :checked="show.has(k)" @change="toggle(k)" />
          <span class="chg" :style="chgStyle(k)">{{ CHG_SIGN[k] }}</span
          >{{ k }} ({{ counts[k] || 0 }})
        </label>
        <input v-model="filter" placeholder="Filter…" autocomplete="off" />
      </div>
      <div class="table-wrap cmp-table" id="cmp-table" ref="scroller">
        <table class="vt">
          <colgroup v-if="view === 'vulns'">
            <col style="width: 40px" />
            <col style="width: 90px" />
            <col style="width: 140px" />
            <col style="width: 20%" />
            <col style="width: 18%" />
            <col />
            <col style="width: 130px" />
          </colgroup>
          <colgroup v-else>
            <col style="width: 40px" />
            <col style="width: 30%" />
            <col style="width: 12%" />
            <col style="width: 22%" />
            <col />
          </colgroup>
          <thead v-if="view === 'vulns'">
            <tr>
              <th v-for="h in ['', 'Severity', 'ID', 'Package', 'Version', 'Why', 'Signals']" :key="h" style="cursor: default">{{ h }}</th>
            </tr>
          </thead>
          <thead v-else>
            <tr>
              <th v-for="h in ['', 'Package', 'Kind', 'Version', 'Vulnerabilities']" :key="h" style="cursor: default">{{ h }}</th>
            </tr>
          </thead>
          <tbody class="pad">
            <tr :style="{ height: before + 'px' }">
              <td :colspan="view === 'vulns' ? 7 : 5"></td>
            </tr>
          </tbody>
          <template v-if="view === 'vulns'">
            <tbody v-for="{ item: x, index } in visible" :key="index" v-measure="index">
              <tr>
                <td>
                  <span class="chg" :style="chgStyle(x.change)" :title="x.change">{{ CHG_SIGN[x.change] }}</span>
                </td>
                <td>
                  <span class="sev" :style="sevStyle(x.vuln.severity)">{{ x.vuln.severity }}</span>
                </td>
                <td class="mono">{{ x.vuln.id }}</td>
                <td class="mono">{{ x.vuln.package }}</td>
                <td class="mono">{{ arrow(x.versionA, x.versionB) }}</td>
                <td>{{ x.cause }}</td>
                <td>
                  <Chip v-if="x.vuln.kev" kind="hot">KEV</Chip>{{ " " }}
                  <Chip v-if="x.vuln.hasEpss && x.vuln.epss >= 0.1" kind="warm">EPSS {{ pct(x.vuln.epss) }}</Chip>
                </td>
              </tr>
            </tbody>
          </template>
          <template v-else>
            <tbody v-for="{ item: x, index } in visible" :key="index" v-measure="index">
              <tr>
                <td>
                  <span class="chg" :style="chgStyle(x.change)" :title="x.change">{{ CHG_SIGN[x.change] }}</span>
                </td>
                <td class="mono">{{ x.name }}</td>
                <td>{{ x.category === "OS" ? "OS" : x.type }}</td>
                <td class="mono">{{ arrow(x.versionA, x.versionB) }}</td>
                <td>
                  {{ x.vulnsA }} → {{ x.vulnsB }}
                  <span :class="['delta', delta(x.vulnsA, x.vulnsB).cls]">{{ delta(x.vulnsA, x.vulnsB).text }}</span>
                </td>
              </tr>
            </tbody>
          </template>
          <tbody class="pad">
            <tr :style="{ height: after + 'px' }">
              <td :colspan="view === 'vulns' ? 7 : 5"></td>
            </tr>
          </tbody>
        </table>
        <div v-if="!rowCount" class="empty">Nothing to show with these filters.</div>
      </div>
    </template>
  </div>
</template>
