<script setup>
import { computed, reactive, ref, watch } from "vue";
import { ScanService, assessing, result, vex, findingsById, errText, lsGet, lsSet, KEYS } from "../store.js";
import { JUSTIFICATION_PLAIN, STATUS_LABEL, cvssFloor, detailUrl, openUrl, tierStyle } from "../lib/format.js";
import { glance } from "../lib/glance.js";
import Chip from "./Chip.vue";
import CopyId from "./CopyId.vue";
import CvssBreakdown from "./CvssBreakdown.vue";

const STATUSES = ["not_affected", "affected", "fixed", "under_investigation"];
const IMPACT_PLACEHOLDER = {
  not_affected: "Explain why, e.g. the service is not exposed or the code path is never loaded",
  affected: "Describe the impact, e.g. the service is internet-facing and processes untrusted input",
  fixed: "Describe the fix, e.g. upgraded to 3.1 and redeployed on 2026-10-20",
  under_investigation: "Say what you know so far and what is still being checked",
};
const JUSTIFICATION_PLACEHOLDER = {
  component_not_present: "Explain why, e.g. the package is only a build dependency and is removed from the final image",
  vulnerable_code_not_present: "Explain why, e.g. the affected function is compiled out or patched in our build",
  vulnerable_code_not_in_execute_path: "Explain why, e.g. we never call the affected API or load that module",
  vulnerable_code_cannot_be_controlled_by_adversary: "Explain why, e.g. the input only comes from our own trusted config",
  inline_mitigations_already_exist: "Describe the mitigation, e.g. a WAF rule or sandbox blocks the attack path",
};
const PRESETS = [
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
];

const dlg = ref(null);
const v = computed(() => assessing.value);
const form = reactive({ status: "", justification: "", impact: "", action: "", author: "", expires: "" });
const err = ref("");
const saving = ref(false);

const impactPlaceholder = computed(
  () => (form.status === "not_affected" && JUSTIFICATION_PLACEHOLDER[form.justification]) || IMPACT_PLACEHOLDER[form.status],
);
const existing = computed(() => (v.value ? vex.value.get(v.value.key) : undefined));
const meaning = computed(() => (v.value ? glance(v.value) : null));
const link = computed(() => (v.value ? detailUrl(v.value) : ""));

// Every component that carries this CVE, the one the drawer was opened from first.
const components = computed(() => {
  if (!v.value) return [];
  const others = [...(findingsById.value.get(v.value.id)?.values() ?? [])].filter((s) => s.key !== v.value.key);
  return [v.value, ...others];
});
// Keys of the other components ticked to receive the same assessment; the opened one is always included.
const alsoKeys = ref(new Set());
const others = computed(() => components.value.slice(1));
const allChecked = computed(() => others.value.length > 0 && others.value.every((s) => alsoKeys.value.has(s.key)));
const targetCount = computed(() => 1 + alsoKeys.value.size);
function toggleAll(ev) {
  alsoKeys.value = ev.target.checked ? new Set(others.value.map((s) => s.key)) : new Set();
}
function toggleOne(key, on) {
  const next = new Set(alsoKeys.value);
  on ? next.add(key) : next.delete(key);
  alsoKeys.value = next;
}

// A review date `days` from today, as the UTC YYYY-MM-DD the backend stores.
const inDays = (days) => new Date(Date.now() + days * 864e5).toISOString().slice(0, 10);
const reviewHint = computed(() =>
  form.expires ? `Shown again in the lists after ${form.expires}.` : "Stays resolved until you remove it.",
);

function load() {
  const e = existing.value;
  Object.assign(form, {
    status: e?.status || "",
    justification: e?.justification || "",
    impact: e?.impact || "",
    action: e?.action || "",
    author: e?.author || lsGet(KEYS.vexAuthor),
    expires: e?.expires || "",
  });
  alsoKeys.value = new Set();
  err.value = "";
}

watch(assessing, (next) => {
  if (!dlg.value) return;
  if (next) {
    load();
    if (!dlg.value.open) dlg.value.showModal();
  } else if (dlg.value.open) {
    dlg.value.close();
  }
});

const close = () => {
  assessing.value = null;
};
// A click on the backdrop lands on the dialog element itself, not on its content.
const onBackdrop = (ev) => {
  if (ev.target === dlg.value) close();
};

async function save() {
  err.value = "";
  if (!form.status) {
    err.value = "Choose a status.";
    return;
  }
  saving.value = true;
  try {
    const targets = components.value.filter((s) => s.key === v.value.key || alsoKeys.value.has(s.key));
    const next = new Map(vex.value);
    // The same statement is valid for every target, so a validation error shows up on the first call, before anything is written.
    for (const t of targets) {
      const saved = await ScanService.VEXSet(result.value.image, {
        vulnerability: t.id,
        package: t.package,
        version: t.installed,
        purl: t.purl,
        status: form.status,
        justification: form.status === "not_affected" ? form.justification : "",
        impact: form.impact,
        action: form.status === "affected" ? form.action : "",
        author: form.author,
        expires: form.expires,
      });
      next.set(saved.key, saved);
    }
    lsSet(KEYS.vexAuthor, form.author.trim());
    vex.value = next;
    close();
  } catch (e) {
    err.value = errText(e);
  } finally {
    saving.value = false;
  }
}

async function clear() {
  err.value = "";
  try {
    await ScanService.VEXDelete(result.value.image, v.value.key);
    const m = new Map(vex.value);
    m.delete(v.value.key);
    vex.value = m;
    close();
  } catch (e) {
    err.value = errText(e);
  }
}
</script>

<template>
  <dialog ref="dlg" class="drawer" aria-label="Assess finding" @close="close" @click="onBackdrop" @keydown.esc="close">
    <template v-if="v">
      <header class="drawer-head">
        <div class="drawer-top">
          <small>Assess finding</small>
          <button type="button" class="ghost drawer-x" aria-label="Close" @click="close">×</button>
        </div>
        <div class="drawer-id">
          <a v-if="link" class="id" :href="link" title="Open CVE details" @click.prevent="openUrl(link)">{{ v.id }} ↗</a>
          <span v-else class="id">{{ v.id }}</span>
          <CopyId :text="v.id" />
          <Chip title="CVSS severity">{{ v.severity }}{{ v.score ? ` ${v.score.toFixed(1)}` : cvssFloor(v.severity) ? ` ~${cvssFloor(v.severity).toFixed(1)} est.` : "" }}</Chip>
          <span class="sev tier" :style="tierStyle(v.tier)" :title="v.tierWhy">{{ v.tier }} · {{ v.priority }}</span>
          <a v-if="link" class="drawer-adv" :href="link" @click.prevent="openUrl(link)">Full advisory</a>
        </div>
        <div v-if="v.title" class="drawer-title">{{ v.title }}</div>
        <div class="glance">
          <small>What it means</small>
          <div class="glance-head">{{ meaning.headline }}</div>
          <div class="kv">Only matters if the component is running and reachable. If not, say so below.</div>
          <div class="glance-facts">
            <div v-for="f in meaning.facts" :key="f.label" :class="{ wide: f.label === 'Fix' }">
              <span>{{ f.label }}</span>
              <b :class="{ mono: f.mono }">{{ f.value }}</b>
            </div>
          </div>
          <CvssBreakdown :vector="v.vector" />
          <details v-if="v.attack" class="glance-more">
            <summary>Full explanation</summary>
            <p class="attack">{{ v.attack }}</p>
          </details>
        </div>
      </header>

      <div class="drawer-body">
        <fieldset class="drawer-group">
          <div class="drawer-row">
            <legend>
              Applies to <span class="kv">· {{ components.length }} component{{ components.length === 1 ? "" : "s" }} with this CVE</span>
            </legend>
            <label v-if="others.length" class="chk drawer-all"
              ><input type="checkbox" :checked="allChecked" @change="toggleAll" /> Select all</label
            >
          </div>
          <div class="comps">
            <label v-for="(s, i) in components" :key="s.key" :class="['comp', { on: i === 0 || alsoKeys.has(s.key) }]">
              <input
                type="checkbox"
                :checked="i === 0 || alsoKeys.has(s.key)"
                :disabled="i === 0"
                @change="toggleOne(s.key, $event.target.checked)"
              />
              <span class="comp-pkg">
                <span class="mono">{{ s.package }}</span>
                <span class="mono kv">{{ s.installed }}{{ s.fixed ? ` → ${s.fixed}` : " · no fix yet" }}</span>
              </span>
              <span v-if="i === 0" class="kv">This finding</span>
              <span v-else-if="vex.get(s.key)" class="kv">Has “{{ STATUS_LABEL[vex.get(s.key).status] }}”, will be replaced</span>
            </label>
          </div>
        </fieldset>

        <fieldset class="drawer-group">
          <legend>Status</legend>
          <div class="drawer-seg">
            <label v-for="s in STATUSES" :key="s" :class="{ on: form.status === s }">
              <input v-model="form.status" type="radio" name="vex-status" :value="s" />
              {{ STATUS_LABEL[s] }}
            </label>
          </div>
        </fieldset>

        <div v-if="form.status" class="drawer-cols">
          <fieldset v-if="form.status === 'not_affected'" class="drawer-group">
            <legend>Why not?</legend>
            <label v-for="(label, k) in JUSTIFICATION_PLAIN" :key="k" :class="['radio', { on: form.justification === k }]">
              <input v-model="form.justification" type="radio" name="vex-why" :value="k" /> {{ label }}
            </label>
          </fieldset>
          <div class="drawer-group">
            <label class="drawer-label" for="vex-impact"
              >In your words
              <span v-if="form.status === 'not_affected'" class="kv">(optional with a reason)</span></label
            >
            <textarea
              id="vex-impact"
              v-model="form.impact"
              rows="4"
              :placeholder="impactPlaceholder"
            ></textarea>
          </div>
        </div>
        <div v-if="form.status === 'affected'" class="drawer-group">
          <label class="drawer-label" for="vex-action">What will you do about it? <span class="kv">(required)</span></label>
          <textarea id="vex-action" v-model="form.action" rows="2" placeholder="e.g. upgrade to 3.1 in the next release"></textarea>
        </div>

        <div v-if="form.status" class="drawer-group">
          <div class="drawer-label">Review again</div>
          <div class="pills">
            <button type="button" :class="['pill', { on: !form.expires }]" @click="form.expires = ''">Never</button>
            <button
              v-for="p in PRESETS"
              :key="p.days"
              type="button"
              :class="['pill', { on: form.expires === inDays(p.days) }]"
              @click="form.expires = inDays(p.days)"
            >
              {{ p.label }}
            </button>
            <label class="pill-date"
              ><span class="kv">or</span>
              <input v-model="form.expires" type="date" aria-label="Review date"
            /></label>
          </div>
          <div class="kv">{{ reviewHint }}</div>
        </div>

        <label v-if="form.status" class="drawer-group drawer-label"
          >Assessed by <span class="kv">(optional)</span>
          <input v-model="form.author" type="text" placeholder="Name or team" />
        </label>
      </div>

      <footer class="drawer-foot">
        <div class="vexerr" role="alert">{{ err }}</div>
        <div class="drawer-actions">
          <button v-if="existing" type="button" class="ghost" @click="clear">Remove assessment</button>
          <span class="grow"></span>
          <button type="button" class="ghost" @click="close">Cancel</button>
          <button type="button" :disabled="saving || !form.status" @click="save">
            Save {{ targetCount === 1 ? "assessment" : `${targetCount} assessments` }}
          </button>
        </div>
      </footer>
    </template>
  </dialog>
</template>
