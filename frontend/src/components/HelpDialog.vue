<script setup>
import { computed, ref } from "vue";
import { footprint, mode } from "../store.js";

const dlg = ref(null);
const tab = ref("glossary");

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

const envVars = [
  ["TRIVY_SCANNER_CACHE", "Trivy cache source: a podman volume name or an absolute directory on the podman host.", "<user cache dir>/trivy-scanner/trivy (local podman); volume trivy-cache (remote podman or Windows)"],
  ["TRIVY_SCANNER_VEX_FILE", "Where VEX assessments are stored.", "<user config dir>/trivy-scanner/vex.json"],
  ["TRIVY_SCANNER_EPSS_URL", "EPSS API endpoint, for an air-gapped mirror.", "api.first.org EPSS API"],
  ["TRIVY_SCANNER_KEV_URL", "CISA KEV feed URL, for an air-gapped mirror.", "cisa.gov known_exploited_vulnerabilities.json"],
  ["TRIVY_DB_REPOSITORY", "Trivy vulnerability DB mirror, forwarded into the scanner container when set.", "Trivy default"],
  ["TRIVY_JAVA_DB_REPOSITORY", "Trivy Java DB mirror, forwarded into the scanner container when set.", "Trivy default"],
  ["PODMAN", "Path of the podman binary.", "podman"],
  ["CONTAINER_HOST / DOCKER_HOST", "Remote podman socket. Switches the cache default to a named volume.", "unset (local podman)"],
  ["WAILS_SERVER_HOST", "Listen address in server mode. Keep it on loopback.", "127.0.0.1 (container image)"],
  ["WAILS_SERVER_PORT", "Listen port in server mode.", "8080 (container image)"],
  ["XDG_CACHE_HOME / XDG_CONFIG_HOME", "Move the user cache and config dirs used above (Linux).", "~/.cache, ~/.config"],
  ["TRIVY_SCANNER_FAKE_PODMAN", "Demo mode on recorded data. Dev builds only; ignored in production builds.", "unset"],
  ["TRIVY_SCANNER_UPDATE_API_URL", "Update API base URL for testing. Dev builds only.", "api.github.com"],
];

const paths = computed(() => [
  ["Trivy cache (this run)", footprint.value?.cacheLocation || "unknown", "Vulnerability DB; a plain directory or a podman volume"],
  ["Enrichment cache", "<user cache dir>/trivy-scanner/", "Downloaded EPSS data and kev.json, reused between scans"],
  ["VEX assessments", "<user config dir>/trivy-scanner/vex.json", "Overridable with TRIVY_SCANNER_VEX_FILE"],
  ["Scanner container", "trivy-scanner-<random>", "Removed on cancel and on quit"],
  ["Container deployment data", "/data (vex.json, cache/)", "Volume of the Containerfile image"],
  ["Podman socket (container deployment)", "/run/podman/podman.sock", "CONTAINER_HOST in the Containerfile"],
  ["Cache mount inside Trivy", "/root/.cache/trivy", "Passed to Trivy as --cache-dir"],
]);

const behaviour = computed(() => [
  ["Mode", mode.value?.fixtures ? "Demo (recorded data)" : "Real podman"],
  ["Scanner", mode.value?.trivyImage || "default"],
]);

function open() { dlg.value.showModal(); }
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
        <section>
          <h4>Current behaviour</h4>
          <dl><template v-for="[k, v] in behaviour" :key="k"><dt>{{ k }}</dt><dd>{{ v }}</dd></template></dl>
        </section>
        <section>
          <h4>Files and locations</h4>
          <dl><template v-for="[k, v, note] in paths" :key="k"><dt>{{ k }}</dt><dd><code>{{ v }}</code><div class="kv">{{ note }}</div></dd></template></dl>
        </section>
        <section>
          <h4>Environment variables</h4>
          <dl><template v-for="[k, desc, def] in envVars" :key="k"><dt><code>{{ k }}</code></dt><dd>{{ desc }}<div class="kv">Default: {{ def }}</div></dd></template></dl>
        </section>
      </template>
    </div>
  </dialog>
</template>
