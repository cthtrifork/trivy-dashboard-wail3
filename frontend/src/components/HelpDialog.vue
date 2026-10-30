<script setup>
import { computed, reactive, ref } from "vue";
import { ScanService, mode, errText } from "../store.js";

const dlg = ref(null);
const body = ref(null);
const section = ref("glossary");
const cfg = ref(null);
const cfgErr = ref("");

// Grouped by the question each group answers; `format` picks how the group is laid out.
const glossary = [
  {
    title: "How bad is it?",
    caption: "Vulnerability data",
    format: "table",
    legend: "severity",
    items: [
      ["CVE", "Common Vulnerabilities and Exposures: the public ID (CVE-YYYY-NNNN) of one known security flaw."],
      [
        "CVSS",
        "Common Vulnerability Scoring System: a 0-10 score for how bad a flaw is if exploited. The vector string (AV:N/AC:L/...) says how it is attacked: network or local, how complex, what privileges and user interaction are needed.",
      ],
      [
        "Attack assessment",
        "A plain-English reading of the CVSS vector and advisory wording: how it is attacked and what the likely outcome is.",
      ],
      ["Severity", "Trivy's CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN bucket, derived from CVSS and distro advisories."],
    ],
  },
  {
    title: "What to fix first?",
    caption: "Prioritisation signals",
    format: "cards",
    legend: "tiers",
    items: [
      [
        "KEV",
        "CISA's Known Exploited Vulnerabilities catalog: CVEs with documented exploitation in the wild. The strongest signal; a ransomware flag adds more.",
      ],
      [
        "EPSS",
        "Exploit Prediction Scoring System (FIRST): the probability that a CVE is exploited in the next 30 days. The percentile compares it with all CVEs.",
      ],
      [
        "Priority tier",
        "Act now, Fix soon, Plan or Monitor. Every score is a sum of readable reasons (KEV, EPSS, Severity, Vector, Fix), so you can see why a finding ranks where it does. Open Scoring rules to switch rules on or off, move thresholds and save presets.",
        "wide",
      ],
    ],
  },
  {
    title: "Is a fix coming?",
    caption: "Vulnerability data",
    format: "cards",
    items: [
      ["Fixed version", "The first package version that contains the patch. Without one, the fix is not available yet.", "good"],
      ["End of life / will not fix", "The vendor has declared it will not patch this. Plan mitigation or replacement.", "warn"],
    ],
  },
  {
    title: "VEX (exploitability statements)",
    format: "vex",
    items: [
      [
        "VEX",
        "Vulnerability Exploitability eXchange: a statement saying whether a CVE actually affects your product. It silences findings that are present but not exploitable.",
      ],
      ["OpenVEX", "The open JSON format (v0.2.0) used for import and export of VEX statements."],
    ],
    statuses: [
      ["affected", "The product is vulnerable; action is recommended."],
      ["not_affected", "The product is not vulnerable. Needs a justification or an impact statement."],
      ["fixed", "The issue was remediated in this version."],
      ["under_investigation", "Not yet decided."],
    ],
    note: [
      "Justification",
      "Why something is not_affected: for example the component is not present, the vulnerable code is not in the execute path, or an inline mitigation exists.",
    ],
  },
  {
    title: "Supply chain",
    format: "cols",
    items: [
      ["SBOM", "Software Bill of Materials: the list of packages and libraries inside the image (the SBOM tab)."],
      ["Dependency graph", "Which components pull in which, to trace a vulnerable package back to the thing that included it."],
      ["Compare", "Scans two tags of one image repository side by side to show what was fixed, added or left unchanged."],
    ],
  },
  {
    title: "Runtime",
    format: "cards",
    items: [
      [
        "Trivy",
        "Aqua Security's open source scanner. It runs in a throwaway container and prints JSON that this app turns into the shortlist.",
      ],
      ["podman", "The container engine that runs Trivy. The app needs only the client; the engine can be remote."],
      ["Trivy DB", "The vulnerability database Trivy downloads and keeps in its cache, so later scans are fast."],
      ["Server (headless) mode", "A build without a native window that serves the UI on loopback. Reach it through an SSH tunnel."],
    ],
  },
];

// Quick-reference legends above two groups; the full text stays in the group below them.
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const TIERS = ["Act now", "Fix soon", "Plan", "Monitor"];

// What every scan passes to `trivy image` (see internal/trivy). The Options menu toggles the last three.
const trivyFlags = [
  ["--scanners vuln", "Vulnerabilities only; the SBOM is a separate CycloneDX run."],
  ["--skip-version-check", "No lookup for a newer Trivy: the version is pinned by this app."],
  ["--disable-telemetry", "Trivy sends no usage data."],
  ["--offline-scan", "No API requests to identify dependencies; only the DB download uses the network."],
  ["--vuln-severity-source redhat,auto", "Prefer Red Hat's severity, then the vendor default."],
  ["--ignore-status will_not_fix,not_affected", "On by default. Open Hide vendor statuses in Options to choose which of the eight statuses to hide."],
  ["--show-suppressed", "Off by default. Tick Show suppressed findings in Options to also list the ones your ignore policy or ignore file hides (Sources tab). VEX statements are not sent to Trivy."],
  ["--ignore-unfixed", "Off by default. Choose Fixable only in Options to hide findings without a fix."],
];
const everyScan = trivyFlags.slice(0, 5);
// The leading "On by default." / "Off by default." sentence becomes a badge so the state reads first.
const optionFlags = trivyFlags.slice(5).map(([flag, desc]) => {
  const m = /^(On|Off) by default\.\s*(.*)$/.exec(desc);
  return { flag, on: m?.[1] === "On", state: m ? `${m[1]} by default` : "", text: m ? m[2] : desc };
});

// The environment variables the Go side reports, grouped by what they control. Anything not listed lands in "Other".
const ENV_GROUPS = [
  ["Cache and mirrors", "list", ["TRIVY_SCANNER_CACHE", "TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY"]],
  ["Proxy and certificates", "cards", ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "TRIVY_SCANNER_CA_BUNDLE"]],
  ["Podman", "cards3", ["PODMAN", "CONTAINER_HOST", "DOCKER_HOST"]],
  ["Data sources", "list", ["TRIVY_SCANNER_VEX_FILE", "TRIVY_SCANNER_EPSS_URL", "TRIVY_SCANNER_KEV_URL"]],
  ["Server mode and user dirs", "cards", ["WAILS_SERVER_HOST", "WAILS_SERVER_PORT", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"]],
];

const behaviour = computed(() =>
  [
    ["Mode", mode.value?.fixtures ? "Demo (recorded data)" : "Real podman"],
    ["Version", cfg.value?.version],
    ["Platform", cfg.value?.platform + (cfg.value?.headless ? " · server mode" : "")],
    ["Scanner image", mode.value?.trivyImage || "default"],
    ["Podman", cfg.value ? cfg.value.podman + (cfg.value.remote ? " (remote)" : " (local)") : ""],
  ].filter(([, v]) => v),
);

// Locations with a note are data the app keeps; the rest say where it runs.
const runsFrom = computed(() => (cfg.value?.paths ?? []).filter((p) => !p.note));
const keeps = computed(() => (cfg.value?.paths ?? []).filter((p) => p.note));

// Variables that are set show up front; the others sit behind "Show" and are grouped by what they control.
const envSet = computed(() => (cfg.value?.env ?? []).filter((e) => e.set));
const envUnset = computed(() => (cfg.value?.env ?? []).filter((e) => !e.set));

const envGroups = computed(() => {
  const byName = new Map(envUnset.value.map((e) => [e.name, e]));
  const groups = ENV_GROUPS.map(([title, format, names]) => ({
    title,
    format,
    vars: names.map((n) => byName.get(n)).filter(Boolean),
  }));
  const listed = new Set(ENV_GROUPS.flatMap(([, , names]) => names));
  groups.push({ title: "Other", format: "list", vars: envUnset.value.filter((e) => !listed.has(e.name)) });
  return groups.filter((g) => g.vars.length);
});

// Config sections start collapsed; each one opens to its full content.
const opened = reactive({ flags: false, files: false, env: false });
const toggle = (key) => {
  opened[key] = !opened[key];
};

// Resolved by the Go side each time, so it reflects this process's real environment.
async function load() {
  cfgErr.value = "";
  try {
    cfg.value = await ScanService.Config();
  } catch (e) {
    cfgErr.value = errText(e);
  }
}

// Two tabs, one visible at a time: each panel scrolls on its own and nothing scrolls between them.
function go(id) {
  section.value = id;
  body.value.scrollTop = 0;
}

function open() {
  dlg.value.showModal();
  body.value.scrollTop = 0;
  section.value = "glossary";
  Object.assign(opened, { flags: false, files: false, env: false });
  load();
}
defineExpose({ open });
</script>

<template>
  <dialog id="help-dialog" ref="dlg" @click.self="dlg.close()">
    <div class="help-head">
      <h3>Help</h3>
      <button type="button" class="ghost" id="help-close" @click="dlg.close()" aria-label="Close">✕</button>
    </div>
    <div class="help-nav" role="tablist" aria-label="Help sections">
      <button type="button" role="tab" :aria-selected="section === 'glossary'" :class="['tab', { active: section === 'glossary' }]" @click="go('glossary')">Glossary</button>
      <button type="button" role="tab" :aria-selected="section === 'config'" :class="['tab', { active: section === 'config' }]" @click="go('config')">App config</button>
    </div>
    <div ref="body" class="help-body">
      <div v-show="section === 'glossary'" id="help-glossary" role="tabpanel">
        <section v-for="g in glossary" :key="g.title" class="hgroup">
          <header>
            <b>{{ g.title }}</b>
            <small v-if="g.caption">{{ g.caption }}</small>
          </header>
          <div class="hbody">
            <div v-if="g.legend === 'severity'" class="hsev" aria-hidden="true">
              <span v-for="sev in SEVERITIES" :key="sev" :style="{ background: `var(--${sev})`, color: `var(--on-${sev})` }">{{ sev }}</span>
            </div>
            <div v-else-if="g.legend === 'tiers'" class="hladder" aria-hidden="true">
              <span v-for="t in TIERS" :key="t">{{ t }}</span>
            </div>
            <dl v-if="g.format === 'table'" class="htable">
              <template v-for="[term, def] in g.items" :key="term">
                <dt>{{ term }}</dt>
                <dd>{{ def }}</dd>
              </template>
            </dl>
            <div v-else-if="g.format === 'cards'" class="hcards">
              <div v-for="[term, def, kind] in g.items" :key="term" :class="['hcard', kind]">
                <h5>{{ term }}</h5>
                <p>{{ def }}</p>
              </div>
            </div>
            <div v-else-if="g.format === 'cols'" class="hcols">
              <div v-for="[term, def] in g.items" :key="term">
                <h5>{{ term }}</h5>
                <p>{{ def }}</p>
              </div>
            </div>
            <template v-else-if="g.format === 'vex'">
              <dl class="htable">
                <template v-for="[term, def] in g.items" :key="term">
                  <dt>{{ term }}</dt>
                  <dd>{{ def }}</dd>
                </template>
              </dl>
              <dl class="hstatus">
                <template v-for="[name, def] in g.statuses" :key="name">
                  <dt><i :class="['mk', name]" aria-hidden="true"></i><code>{{ name }}</code></dt>
                  <dd>{{ def }}</dd>
                </template>
              </dl>
              <p class="hnote">
                <b>{{ g.note[0] }}</b> {{ g.note[1] }}
              </p>
            </template>
          </div>
        </section>
      </div>

      <div v-show="section === 'config'" id="help-config" role="tabpanel">
        <p v-if="cfgErr" class="vexerr">{{ cfgErr }}</p>
        <p v-else-if="!cfg" class="kv hload">Loading…</p>
        <template v-else>
          <section class="hgroup">
            <header>
              <b>Current behaviour</b>
              <small>App config</small>
            </header>
            <div class="hbody">
              <dl class="htable">
                <template v-for="[k, v] in behaviour" :key="k">
                  <dt>{{ k }}</dt>
                  <dd>{{ v }}</dd>
                </template>
              </dl>
            </div>
          </section>

          <section class="hgroup">
            <header>
              <b>Trivy flags</b>
              <small>{{ trivyFlags.length }} flags</small>
            </header>
            <div class="hbody">
              <button type="button" class="hsum" :aria-expanded="opened.flags" @click="toggle('flags')">
                <span v-if="!opened.flags"><b>{{ everyScan.length }}</b> passed on every scan · <b>{{ optionFlags.length }}</b> changed in Options</span>
                <span v-else class="kv">Passed on every scan</span>
                <span class="htoggle">{{ opened.flags ? "Hide ▾" : "Show ▸" }}</span>
              </button>
              <dl v-if="opened.flags" class="hflags">
                <template v-for="[flag, desc] in everyScan" :key="flag">
                  <dt>
                    <code>{{ flag }}</code>
                  </dt>
                  <dd>{{ desc }}</dd>
                </template>
              </dl>
            </div>
          </section>

          <section v-if="opened.flags" class="hgroup">
            <header>
              <b>Changed in Options</b>
              <small>Trivy flags</small>
            </header>
            <div class="hbody hoptions">
              <div v-for="f in optionFlags" :key="f.flag" class="hoption">
                <div class="hoption-top">
                  <code>{{ f.flag }}</code>
                  <span v-if="f.state" class="hdefault">
                    <span class="hseg" role="img" :aria-label="f.state">
                      <i :class="{ on: f.on }">On</i>
                      <i :class="{ on: !f.on }">Off</i>
                    </span>
                    <span class="kv">by default</span>
                  </span>
                </div>
                <p>{{ f.text }}</p>
              </div>
            </div>
          </section>

          <section class="hgroup">
            <header>
              <b>Files and locations (this machine)</b>
              <small>{{ runsFrom.length + keeps.length }} locations</small>
            </header>
            <div class="hbody">
              <button type="button" class="hsum" :aria-expanded="opened.files" @click="toggle('files')">
                <span><b>Where it runs</b> {{ runsFrom.length }} · <b>Data it keeps</b> {{ keeps.length }}</span>
                <span class="htoggle">{{ opened.files ? "Hide ▾" : "Show ▸" }}</span>
              </button>
              <template v-if="opened.files">
                <template v-if="runsFrom.length">
                  <h5 class="hsub">Where it runs</h5>
                  <dl class="hpaths">
                    <template v-for="p in runsFrom" :key="p.label">
                      <dt>{{ p.label }}</dt>
                      <dd>
                        <code>{{ p.value }}</code>
                      </dd>
                    </template>
                  </dl>
                </template>
                <template v-if="keeps.length">
                  <h5 class="hsub">Data it keeps</h5>
                  <div class="hcards one">
                    <div v-for="p in keeps" :key="p.label" class="hcard">
                      <h5>{{ p.label }}</h5>
                      <code>{{ p.value }}</code>
                      <div class="kv">{{ p.note }}</div>
                    </div>
                  </div>
                </template>
              </template>
            </div>
          </section>

          <section class="hgroup">
            <header>
              <b>Environment variables</b>
              <small>{{ envSet.length }} of {{ cfg.env.length }} set</small>
            </header>
            <div class="hbody">
              <dl v-if="envSet.length" class="henv">
                <template v-for="e in envSet" :key="e.name">
                  <dt>
                    <code>{{ e.name }}</code>
                  </dt>
                  <dd>
                    <span class="envstate on">set</span>
                    <code v-if="e.value"> {{ e.value }}</code>
                    <div>{{ e.desc }}</div>
                    <div class="kv">Default: {{ e.default }}</div>
                  </dd>
                </template>
              </dl>
              <button v-if="envUnset.length" type="button" :class="['hsum', { split: envSet.length }]" :aria-expanded="opened.env" @click="toggle('env')">
                <span><b>{{ envUnset.length }}</b> not set, using their defaults</span>
                <span class="htoggle">{{ opened.env ? "Hide ▾" : "Show ▸" }}</span>
              </button>
            </div>
          </section>

          <template v-if="opened.env">
            <section v-for="g in envGroups" :key="g.title" class="hgroup">
              <header>
                <b>{{ g.title }}</b>
                <small>Environment variables</small>
              </header>
              <div class="hbody">
                <dl v-if="g.format === 'list'" class="henv">
                  <template v-for="e in g.vars" :key="e.name">
                    <dt>
                      <code>{{ e.name }}</code>
                    </dt>
                    <dd>
                      <span class="envstate">not set</span>
                      <div>{{ e.desc }}</div>
                      <div class="kv">Default: {{ e.default }}</div>
                    </dd>
                  </template>
                </dl>
                <div v-else :class="['hcards', { three: g.format === 'cards3' }]">
                  <div v-for="e in g.vars" :key="e.name" class="hcard">
                    <h5>
                      <code>{{ e.name }}</code>
                    </h5>
                    <span class="envstate">not set</span>
                    <p>{{ e.desc }}</p>
                    <div class="kv">Default: {{ e.default }}</div>
                  </div>
                </div>
              </div>
            </section>
          </template>
        </template>
      </div>
    </div>
  </dialog>
</template>
