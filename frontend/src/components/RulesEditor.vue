<script setup>
import { computed, ref } from "vue";
import { rules, setRules, builtinPresets, userPresets, allPresets, activePreset, savePreset, deletePreset } from "../store.js";

const name = ref("");
const active = activePreset;
const isUser = computed(() => userPresets.value.some((p) => p.name === active.value));
const description = computed(
  () => allPresets.value.find((p) => p.name === active.value)?.description ?? "You changed a rule: save it as a preset to keep it.",
);

const set = (patch) => setRules(patch);
// Probabilities are stored as 0-1 and shown as percent.
const pctInput = (key) => (e) => {
  const n = parseFloat(e.target.value);
  if (!Number.isNaN(n)) set({ [key]: Math.min(Math.max(n, 0), 100) / 100 });
};
const intInput = (key) => (e) => {
  const n = parseInt(e.target.value, 10);
  if (!Number.isNaN(n)) set({ [key]: Math.min(Math.max(n, 0), 100) });
};
const pick = (e) => {
  const p = allPresets.value.find((x) => x.name === e.target.value);
  if (p) set(p.rules);
};
function save() {
  if (savePreset(name.value)) name.value = "";
}
</script>

<template>
  <details id="rules" v-if="builtinPresets.length">
    <summary>
      Scoring rules: <b>{{ active ?? "custom" }}</b>
    </summary>
    <div class="rules-body">
      <div class="toolbar wrap">
        <label class="chk"
          >Preset
          <select id="rules-preset" :value="active ?? ''" @change="pick">
            <option v-if="!active" value="" disabled>custom</option>
            <optgroup label="Built-in">
              <option v-for="p in builtinPresets" :key="p.name" :value="p.name">{{ p.name }}</option>
            </optgroup>
            <optgroup v-if="userPresets.length" label="Yours">
              <option v-for="p in userPresets" :key="p.name" :value="p.name">{{ p.name }}</option>
            </optgroup>
          </select>
        </label>
        <button type="button" class="ghost" v-if="isUser" @click="deletePreset(active)">Delete preset</button>
        <input id="rules-name" v-model="name" placeholder="Save these rules as…" maxlength="40" @keydown.enter.prevent="save" />
        <button type="button" class="ghost" :disabled="!name.trim()" @click="save">Save preset</button>
        <span>{{ description }}</span>
      </div>
      <p class="kv">
        A score is the sum of the points of the rules that apply, capped at 0–100. Points are fixed and printed on every finding; you choose
        which rules apply and where their thresholds are.
      </p>

      <div class="rule-row">
        <label class="chk"
          ><input type="checkbox" :checked="rules.kevEnabled" @change="set({ kevEnabled: $event.target.checked })" /> <b>KEV</b></label
        >
        <span>Listed in CISA's Known Exploited Vulnerabilities: +50, +10 more if used in ransomware.</span>
        <label class="chk sub"
          ><input
            type="checkbox"
            :checked="rules.kevForceNow"
            :disabled="!rules.kevEnabled"
            @change="set({ kevForceNow: $event.target.checked })"
          />
          always Act now</label
        >
      </div>

      <div class="rule-row">
        <label class="chk"
          ><input type="checkbox" :checked="rules.epssEnabled" @change="set({ epssEnabled: $event.target.checked })" /> <b>EPSS</b></label
        >
        <span>Exploitation probability: +10 from the cutoff, +22 from "high", +35 (and Fix soon) from "very high".</span>
        <span class="nums">
          <label
            >cutoff
            <input
              type="number"
              min="0"
              max="100"
              step="0.5"
              :value="+(rules.epssCutoff * 100).toFixed(2)"
              :disabled="!rules.epssEnabled"
              @change="pctInput('epssCutoff')($event)"
            />%</label
          >
          <label
            >high
            <input
              type="number"
              min="0"
              max="100"
              step="0.5"
              :value="+(rules.epssHigh * 100).toFixed(2)"
              :disabled="!rules.epssEnabled"
              @change="pctInput('epssHigh')($event)"
            />%</label
          >
          <label
            >very high
            <input
              type="number"
              min="0"
              max="100"
              step="0.5"
              :value="+(rules.epssVeryHigh * 100).toFixed(2)"
              :disabled="!rules.epssEnabled"
              @change="pctInput('epssVeryHigh')($event)"
            />%</label
          >
        </span>
      </div>

      <div class="rule-row">
        <label class="chk"
          ><input type="checkbox" :checked="rules.severityEnabled" @change="set({ severityEnabled: $event.target.checked })" />
          <b>Severity</b></label
        >
        <span>CVSS severity: critical +30, high +25, medium +10, low +3, unknown +5.</span>
      </div>

      <div class="rule-row">
        <label class="chk"
          ><input type="checkbox" :checked="rules.vectorEnabled" @change="set({ vectorEnabled: $event.target.checked })" />
          <b>Attack vector</b></label
        >
        <span>Network +10, adjacent +4, physical −2; low complexity +3; no privileges +5; no user interaction +4.</span>
      </div>

      <div class="rule-row">
        <label class="chk"
          ><input type="checkbox" :checked="rules.fixEnabled" @change="set({ fixEnabled: $event.target.checked })" />
          <b>Fix availability</b></label
        >
        <span>Fix exists +5, none yet −3, vendor will not fix −5.</span>
        <label class="chk sub"
          ><input type="checkbox" :checked="rules.fixedOnly" @change="set({ fixedOnly: $event.target.checked })" /> fixed only: findings
          without a fix score 0 (Monitor)</label
        >
      </div>

      <div class="rule-row">
        <b>Tiers</b>
        <span>A finding lands in the first tier whose minimum score it reaches.</span>
        <span class="nums">
          <label>Act now ≥ <input type="number" min="0" max="100" :value="rules.tierNow" @change="intInput('tierNow')($event)" /></label>
          <label>Fix soon ≥ <input type="number" min="0" max="100" :value="rules.tierSoon" @change="intInput('tierSoon')($event)" /></label>
          <label>Plan ≥ <input type="number" min="0" max="100" :value="rules.tierPlan" @change="intInput('tierPlan')($event)" /></label>
        </span>
      </div>
    </div>
  </details>
</template>
