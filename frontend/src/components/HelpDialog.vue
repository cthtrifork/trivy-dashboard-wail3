<script setup>
import { computed, ref } from "vue";
import { ScanService, mode, errText } from "../store.js";

const dlg = ref(null);
const tab = ref("glossary");
const cfg = ref(null);
const cfgErr = ref("");

const glossary = [
  { group: "Vulnerability data", items: [
    ["CVE", "Common Vulnerabilities and Exposures: the public ID (CVE-YYYY-NNNN) of one known security flaw."],
    ["CVSS", "Common Vulnerability Scoring System: a 0-10 score for how bad a flaw is if exploited. The vector string (AV:N/AC:L/...) says how it is attacked: network or local, how complex, what privileges and user interaction are needed."],
    ["Severity", "Trivy's CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN bucket, derived from CVSS and distro advisories."],
    ["Fixed version", "The first package version that contains the patch. Without one, the fix is not available yet."],
    ["End of life / will not fix", "The vendor has declared it will not patch this. Plan mitigation or replacement."],
  ]},
  { group: "Prioritisation signals", items: [
    ["KEV", "CISA's Known Exploited Vulnerabilities catalog: CVEs with documented exploitation in the wild. The strongest signal; a ransomware flag adds more."],
    ["EPSS", "Exploit Prediction Scoring System (FIRST): the probability that a CVE is exploited in the next 30 days. The percentile compares it with all CVEs."],
    ["Priority tier", "Act now, Fix soon, Plan or Monitor. Every score is a sum of readable reasons (KEV, EPSS, Severity, Vector, Fix), so you can see why a finding ranks where it does."],
    ["Attack assessment", "A plain-English reading of the CVSS vector and advisory wording: how it is attacked and what the likely outcome is."],
  ]},
  { group: "VEX (exploitability statements)", items: [
    ["VEX", "Vulnerability Exploitability eXchange: a statement saying whether a CVE actually affects your product. It silences findings that are present but not exploitable."],
    ["OpenVEX", "The open JSON format (v0.2.0) used for import and export of VEX statements."],
    ["affected", "The product is vulnerable; action is recommended."],
    ["not_affected", "The product is not vulnerable. Needs a justification or an impact statement."],
    ["fixed", "The issue was remediated in this version."],
    ["under_investigation", "Not yet decided."],
    ["Justification", "Why something is not_affected: for example the component is not present, the vulnerable code is not in the execute path, or an inline mitigation exists."],
  ]},
  { group: "Supply chain", items: [
    ["SBOM", "Software Bill of Materials: the list of packages and libraries inside the image (the SBOM tab)."],
    ["Dependency graph", "Which components pull in which, to trace a vulnerable package back to the thing that included it."],
    ["Compare", "Scans two tags of one image repository side by side to show what was fixed, added or left unchanged."],
  ]},
  { group: "Runtime", items: [
    ["Trivy", "Aqua Security's open source scanner. It runs in a throwaway container and prints JSON that this app turns into the shortlist."],
    ["podman", "The container engine that runs Trivy. The app needs only the client; the engine can be remote."],
    ["Trivy DB", "The vulnerability database Trivy downloads and keeps in its cache, so later scans are fast."],
    ["Server (headless) mode", "A build without a native window that serves the UI on loopback. Reach it through an SSH tunnel."],
  ]},
];

const behaviour = computed(() => [
  ["Mode", mode.value?.fixtures ? "Demo (recorded data)" : "Real podman"],
  ["Version", cfg.value?.version],
  ["Platform", cfg.value?.platform + (cfg.value?.headless ? " · server mode" : "")],
  ["Scanner image", mode.value?.trivyImage || "default"],
  ["Podman", cfg.value ? cfg.value.podman + (cfg.value.remote ? " (remote)" : " (local)") : ""],
].filter(([, v]) => v));

// Resolved by the Go side each time, so it reflects this process's real environment.
async function load() {
  cfgErr.value = "";
  try { cfg.value = await ScanService.Config(); } catch (e) { cfgErr.value = errText(e); }
}

function open() { dlg.value.showModal(); load(); }
defineExpose({ open });
</script>

<template>
  <dialog id="help-dialog" ref="dlg" @click.self="dlg.close()">
    <div class="help-head">
      <h3>Help</h3>
      <button type="button" class="ghost" id="help-close" @click="dlg.close()" aria-label="Close">✕</button>
    </div>
    <div class="help-tabs">
      <button type="button" :class="['tab', { active: tab === 'glossary' }]" @click="tab = 'glossary'">Glossary</button>
      <button type="button" :class="['tab', { active: tab === 'config' }]" @click="tab = 'config'">App config</button>
    </div>
    <div class="help-body">
      <template v-if="tab === 'glossary'">
        <section v-for="g in glossary" :key="g.group">
          <h4>{{ g.group }}</h4>
          <dl>
            <template v-for="[term, def] in g.items" :key="term">
              <dt>{{ term }}</dt><dd>{{ def }}</dd>
            </template>
          </dl>
        </section>
      </template>
      <template v-else>
        <p v-if="cfgErr" class="vexerr">{{ cfgErr }}</p>
        <p v-else-if="!cfg" class="kv">Loading…</p>
        <template v-else>
          <section>
            <h4>Current behaviour</h4>
            <dl><template v-for="[k, v] in behaviour" :key="k"><dt>{{ k }}</dt><dd>{{ v }}</dd></template></dl>
          </section>
          <section>
            <h4>Files and locations (this machine)</h4>
            <dl><template v-for="p in cfg.paths" :key="p.label"><dt>{{ p.label }}</dt><dd><code>{{ p.value }}</code><div class="kv" v-if="p.note">{{ p.note }}</div></dd></template></dl>
          </section>
          <section>
            <h4>Environment variables</h4>
            <dl><template v-for="e in cfg.env" :key="e.name"><dt><code>{{ e.name }}</code></dt><dd>
              <span :class="['envstate', { on: e.set }]">{{ e.set ? "set" : "not set" }}</span>
              <code v-if="e.set && e.value"> {{ e.value }}</code>
              <div>{{ e.desc }}</div>
              <div class="kv">Default: {{ e.default }}</div>
            </dd></template></dl>
          </section>
        </template>
      </template>
    </div>
  </dialog>
</template>
