<script setup>
import { computed, nextTick, onMounted, reactive, ref, watch } from "vue";
import { depsTarget, result, SEVERITIES, SEV_COLOR, sevStyle, showInPriorities, vex, vulns } from "../store.js";
import { Graph } from "../lib/graph.js";
import { STATUS_LABEL, suppresses, tierStyle } from "../lib/format.js";
import { blastRadius, routeTo } from "../lib/where.js";
import Chip from "./Chip.vue";
import SevBadges from "./SevBadges.vue";

const IMAGE_NODE = "__image__";
const MAX_NODES = 400;

const dep = reactive({ filter: "", cat: "all", vulnOnly: true, focus: 0, selected: null, vuln: null, labels: false });
// The search box redraws the graph, so wait for a pause in typing before applying it.
const typed = ref("");
let typing = 0;
watch(typed, (v) => {
  clearTimeout(typing);
  typing = setTimeout(() => (dep.filter = v), 150);
});
watch(
  () => dep.filter,
  (v) => {
    if (v !== typed.value) typed.value = v;
  },
); // reset by select()
const canvas = ref(null);
const shown = ref("");
const hover = ref("");
let graph = null;
let depth = null; // ref -> hops from the image root, for the layer bands

const nodes = computed(() => result.value?.depNodes ?? {});
const selectedNode = computed(() => (dep.selected && nodes.value[dep.selected]) || null);
const selectedVulns = computed(() => (selectedNode.value ? selectedNode.value.own.map((i) => result.value.vulnerabilities[i]) : []));
const shownVulns = computed(() => selectedVulns.value.slice(0, LIST_MAX));
// How the selection got into the image, and how far it reaches back up: both walk the requires-edges.
const route = computed(() => routeTo(result.value, selectedNode.value));
const radius = computed(() => (selectedNode.value ? blastRadius(nodes.value, dep.selected) : null));
const radiusShare = computed(() => (radius.value ? Math.round(((radius.value.hops.size - 1) / count.value) * 100) : 0));
// A hub such as stdlib can have hundreds of dependants or findings: list the first few.
const LIST_MAX = 100;
const more = (n) => (n > LIST_MAX ? n - LIST_MAX : 0);
const count = computed(() => Object.keys(nodes.value).length);

// Each finding's place in the Priorities ranking, for the card under a picked vulnerability. Resolved
// findings (VEX) are not ranked there, so they count for neither rank nor total.
const vkey = (v) => v.key + "|" + v.target;
const TOP = 10; // the Priorities tab's default list length
const ranking = computed(() => {
  const byKey = new Map();
  let n = 0;
  for (const v of vulns.value) byKey.set(vkey(v), { v, rank: suppresses(vex.value.get(v.key)) ? 0 : ++n });
  return { byKey, of: n };
});
const info = (v) => ranking.value.byKey.get(vkey(v));
const toPriorities = (v) => showInPriorities(v, { ref: dep.selected, label: `${selectedNode.value.name} ${selectedNode.value.version}` });

const total = (n) => SEVERITIES.reduce((t, s) => t + (n.totalCounts[s] || 0), 0);
const worst = (counts) => SEVERITIES.find((s) => counts[s]);
const cssVar = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const sevWeight = (n) => SEVERITIES.reduce((t, s, i) => t + (n.totalCounts[s] || 0) * [10000, 1000, 100, 10, 5][i], 0);
const query = () => dep.filter.trim().toLowerCase();

// Per scan, once: each component's search text and severity weight. Typing and the top-N cut
// then do not rebuild strings or re-sum counts for every component on every keystroke.
const index = computed(() => {
  const all = nodes.value;
  return Object.keys(all).map((ref) => {
    const n = all[ref];
    return { ref, text: (n.name + " " + n.version).toLowerCase(), weight: sevWeight(n), vulnerable: total(n) > 0, category: n.category };
  });
});

function computeDepths() {
  depth = new Map();
  const queue = [];
  for (const r of result.value.depRoots) {
    depth.set(r, 1);
    queue.push(r);
  }
  for (let i = 0; i < queue.length; i++) {
    for (const c of nodes.value[queue[i]].children) {
      if (!depth.has(c)) {
        depth.set(c, depth.get(queue[i]) + 1);
        queue.push(c);
      }
    }
  }
}

// Which components to draw: filters, search, or the neighbourhood of the selection.
function visibleRefs() {
  const all = nodes.value;
  const q = query();
  let refs;
  if (dep.focus === "up" && dep.selected && all[dep.selected]) {
    refs = [...radius.value.hops.keys()];
  } else if (dep.focus > 0 && dep.selected && all[dep.selected]) {
    const seen = new Map([[dep.selected, 0]]);
    const queue = [dep.selected];
    for (let i = 0; i < queue.length; i++) {
      const d = seen.get(queue[i]);
      if (d >= dep.focus) continue;
      const n = all[queue[i]];
      for (const x of [...n.children, ...n.parents])
        if (!seen.has(x)) {
          seen.set(x, d + 1);
          queue.push(x);
        }
    }
    refs = [...seen.keys()];
  } else if (q) {
    const hits = index.value.filter((e) => e.text.includes(q)).map((e) => e.ref);
    const set = new Set(hits);
    for (const r of hits) {
      all[r].children.forEach((c) => set.add(c));
      all[r].parents.forEach((p) => set.add(p));
    }
    refs = [...set];
  } else {
    refs = index.value.filter((e) => (dep.cat === "all" || e.category === dep.cat) && (!dep.vulnOnly || e.vulnerable)).map((e) => e.ref);
  }
  let truncated = 0;
  if (refs.length > MAX_NODES) {
    truncated = refs.length - MAX_NODES;
    const weight = new Map(index.value.map((e) => [e.ref, e.weight]));
    refs.sort((a, b) => weight.get(b) - weight.get(a));
    refs = refs.slice(0, MAX_NODES);
    if (dep.selected && !refs.includes(dep.selected) && all[dep.selected]) refs.push(dep.selected);
  }
  return { refs, truncated };
}

function renderGraph() {
  const all = nodes.value;
  if (!result.value || !count.value) return;
  if (!graph) {
    graph = new Graph(canvas.value, {
      onSelect: (id) => select(id === IMAGE_NODE ? null : id),
      onHover: (id) => (hover.value = describe(id)),
    });
    graph.showLabels = dep.labels ? "all" : "auto";
    window.__depGraph = graph; // handy for debugging in devtools, and used by scripts/screenshots.mjs
  }
  if (!depth) computeDepths();
  const { refs, truncated } = visibleRefs();
  const keep = new Set(refs);
  const q = query();
  const colors = Object.fromEntries(SEVERITIES.map((s) => [s, cssVar(SEV_COLOR[s])]));
  const labelled = new Set([...refs].sort((x, y) => sevWeight(all[y]) - sevWeight(all[x])).slice(0, 12));
  const gnodes = refs.map((r) => {
    const n = all[r];
    const own = worst(n.ownCounts),
      tot = worst(n.totalCounts);
    return {
      id: r,
      label: n.name,
      sub: n.version,
      depth: depth.get(r) ?? 1,
      r: 5 + Math.min(11, Math.sqrt(total(n)) * 1.6),
      fill: own ? colors[own] : n.category === "OS" ? "#6b7a99" : "#4a8f7a",
      ring: tot && !own ? colors[tot] : own ? colors[own] : null,
      shape: n.category === "OS" ? "square" : "circle",
      always: labelled.has(r) && total(n) > 0,
      hl: !!q && (n.name + " " + n.version).toLowerCase().includes(q),
    };
  });
  const edges = [];
  for (const r of refs) for (const c of all[r].children) if (keep.has(c)) edges.push([r, c]);
  gnodes.push({
    id: IMAGE_NODE,
    label: result.value.image,
    depth: 0,
    r: 10,
    fill: cssVar("--accent"),
    ring: null,
    shape: "square",
    always: true,
  });
  for (const r of result.value.depRoots) if (keep.has(r)) edges.push([IMAGE_NODE, r]);

  graph.setData(gnodes, edges);
  graph.select(dep.selected && keep.has(dep.selected) ? dep.selected : null);
  markRoute();
  shown.value =
    `${refs.length} of ${count.value} components` +
    (truncated ? ` · ${truncated} lower-risk hidden: search, filter or focus a node to see them` : "");
}

// Keep the selection's route from the image bright in the graph.
function markRoute() {
  graph?.setPath(route.value ? [IMAGE_NODE, ...route.value.chain.map((n) => n.ref)] : []);
}

function describe(id) {
  const n = id && nodes.value[id];
  return n ? `${n.name} ${n.version} — ${n.children.length} dependencies, required by ${n.parents.length}` : "";
}

// Select a component. If it is currently filtered out, relax the filters so it shows; the watcher
// below redraws, and the graph is told afterwards so it can centre on the result.
async function select(ref, center = false) {
  if (ref !== dep.selected) dep.vuln = null;
  dep.selected = ref;
  if (ref) {
    if (!visibleRefs().refs.includes(ref)) {
      dep.filter = "";
      dep.cat = "all";
      if (!total(nodes.value[ref])) dep.vulnOnly = false;
    }
  } else if (dep.focus) {
    dep.focus = 0;
  }
  await nextTick();
  graph?.select(ref, { center });
}

// Anything that changes which components are drawn; the selection only matters while focusing on it.
watch(() => [dep.filter, dep.cat, dep.vulnOnly, dep.focus, dep.focus ? dep.selected : null], renderGraph);
watch(route, markRoute);
watch(
  () => dep.labels,
  (on) => {
    if (graph) {
      graph.showLabels = on ? "all" : "auto";
      graph.draw();
    }
  },
);
watch(result, () => {
  dep.selected = null;
  dep.vuln = null;
  depth = null;
  renderGraph();
});
onMounted(renderGraph);
// "post": the tab has been switched to by then, so the canvas has a size to centre in.
watch(
  depsTarget,
  (t) => {
    if (t && nodes.value[t.ref]) select(t.ref, true);
  },
  { flush: "post" },
);

const links = (refs) => refs.slice(0, LIST_MAX).map((r) => [r, nodes.value[r]]);
</script>

<template>
  <div class="toolbar wrap">
    <input id="dep-filter" v-model="typed" placeholder="Find a package…" autocomplete="off" />
    <div class="seg" id="dep-cat">
      <button type="button"
        v-for="[cat, label] in [
          ['all', 'All'],
          ['OS', 'OS'],
          ['Application', 'Application'],
        ]"
        :key="cat"
        :class="{ on: dep.cat === cat }"
        @click="dep.cat = cat"
      >
        {{ label }}
      </button>
    </div>
    <label class="chk"><input type="checkbox" id="dep-vuln-only" v-model="dep.vulnOnly" /> Vulnerable paths only</label>
    <label class="chk"
      >Focus
      <select id="dep-focus" v-model.number="dep.focus">
        <option :value="0">whole graph</option>
        <option :value="1">selection ±1 hop</option>
        <option :value="2">selection ±2 hops</option>
        <option :value="3">selection ±3 hops</option>
        <option value="up">selection and all that require it</option>
      </select>
    </label>
    <label class="chk"><input type="checkbox" id="dep-labels" v-model="dep.labels" /> All labels</label>
    <button type="button" class="ghost" id="dep-fit" @click="graph?.fit()">Fit</button>
    <span id="dep-shown">{{ shown }}</span>
  </div>
  <div id="dep-split">
    <div class="graph-wrap" id="dep-graph">
      <canvas id="dep-canvas" ref="canvas"></canvas>
      <div id="dep-hover">{{ hover }}</div>
      <div id="dep-legend">
        <span><i class="lg sq"></i>OS package</span><span><i class="lg"></i>library / app</span>
        <span><i class="lg ring"></i>vulnerable via dependency</span><span>size = vulnerability count</span>
        <span class="kv">scroll to zoom · drag to pan · double-click to fit</span>
      </div>
    </div>
    <div class="table-wrap" id="dep-detail">
      <div v-if="!result" class="empty">Run a scan to explore dependencies. Click a node to inspect it.</div>
      <div v-else-if="!selectedNode" class="empty">Click a node to inspect it.</div>
      <template v-else>
        <h3>{{ selectedNode.name }} {{ selectedNode.version }}</h3>
        <div class="kv">{{ selectedNode.category }} · {{ selectedNode.type }}</div>
        <div class="kv mono">{{ selectedNode.purl }}</div>
        <h4>Path from image</h4>
        <ol v-if="route" class="dep-path">
          <li class="mono">{{ result.image }}</li>
          <li v-for="(n, i) in route.chain" :key="n.ref" :style="{ '--depth': i + 1 }">
            <span v-if="n.ref === dep.selected" class="mono dep-path-here">{{ n.name }} {{ n.version }}</span>
            <button v-else type="button" class="link mono" @click="select(n.ref, true)">{{ n.name }} {{ n.version }}</button>
          </li>
        </ol>
        <div v-else class="kv">not reachable from the image's direct dependencies</div>
        <div v-if="route?.others" class="kv">
          Also reached through {{ route.others }} other direct {{ route.others === 1 ? "dependency" : "dependencies" }} of the image.
        </div>
        <h4>Blast radius</h4>
        <template v-if="radius.hops.size > 1">
          <div class="kv">
            {{ radius.hops.size - 1 }} components ({{ radiusShare }}% of the image) require this, {{ radius.direct }} directly and
            {{ radius.transitive }} through others. {{ radius.findings }}
            {{ radius.findings === 1 ? "finding sits" : "findings sit" }} in them.
          </div>
          <button type="button" class="link" @click="dep.focus = dep.focus === 'up' ? 0 : 'up'">
            {{ dep.focus === "up" ? "Show the whole graph →" : "Show only the selection and what requires it →" }}
          </button>
        </template>
        <div v-else class="kv">nothing requires this component</div>
        <h4>
          Vulnerabilities ({{ selectedVulns.length
          }}{{ total(selectedNode) > selectedVulns.length ? `, ${total(selectedNode)} incl. dependencies` : "" }})
        </h4>
        <template v-for="v in shownVulns" :key="vkey(v)">
          <button
            type="button"
            class="vrow vpick"
            :class="{ sel: dep.vuln === vkey(v) }"
            :aria-expanded="dep.vuln === vkey(v)"
            @click="dep.vuln = dep.vuln === vkey(v) ? null : vkey(v)"
          >
            <span class="sev" :style="sevStyle(v.severity)">{{ v.severity }}</span>
            <span class="mono">{{ v.id }}</span>
            <span class="kv">{{ v.fixed ? `fixed in ${v.fixed}` : "no fix" }}</span>
            <span class="caret" aria-hidden="true">{{ dep.vuln === vkey(v) ? "▾" : "›" }}</span>
          </button>
          <div v-if="dep.vuln === vkey(v) && info(v)" class="vcard">
            <div class="vcard-title">{{ v.title || v.id }}</div>
            <div class="vcard-meta">
              <span v-if="info(v).rank" class="sev tier" :style="tierStyle(info(v).v.tier)">{{ info(v).v.tier }} {{ info(v).v.priority }}</span>
              <Chip v-else kind="vex">VEX: {{ STATUS_LABEL[vex.get(v.key).status] }}</Chip>
              <span v-if="info(v).rank"
                >Rank <b>#{{ info(v).rank }}</b> of {{ ranking.of }} in Priorities</span
              >
              <span v-else>Not ranked while resolved</span>
            </div>
            <button type="button" class="link" @click="toPriorities(v)">Show in Priorities →</button>
            <div v-if="!info(v).rank" class="kv">Opens the Suppressed by VEX list at this finding.</div>
            <div v-else-if="info(v).rank > TOP" class="kv">Ranked below the top {{ TOP }}; the list widens if it needs to.</div>
          </div>
        </template>
        <div v-if="more(selectedVulns.length)" class="kv">…and {{ more(selectedVulns.length) }} more</div>
        <div v-if="!selectedVulns.length" class="kv">none in this package</div>
        <template
          v-for="[title, refs] in [
            ['Depends on', selectedNode.children],
            ['Required by', selectedNode.parents],
          ]"
          :key="title"
        >
          <h4>{{ title }} ({{ refs.length }})</h4>
          <button v-for="[r, x] in links(refs)" :key="r" type="button" class="link" @click="select(r, true)">
            <span>{{ x.name }} {{ x.version }}</span>
            <SevBadges :own="x.ownCounts" :total="x.totalCounts" />
          </button>
          <div v-if="more(refs.length)" class="kv">…and {{ more(refs.length) }} more</div>
          <div v-if="!refs.length" class="kv">none</div>
        </template>
      </template>
    </div>
  </div>
</template>
