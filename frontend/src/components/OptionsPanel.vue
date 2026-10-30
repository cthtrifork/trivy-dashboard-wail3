<script setup>
import { computed, ref } from "vue";
import { ScanService } from "../lib/api.js";
import {
  opts,
  trivyImageSetting,
  trivyTags,
  trivyNewest,
  ensureTrivyTags,
  saveTrivyImage,
  loadIgnorePolicyFile,
  loadIgnoreFile,
  ignorePolicyError,
  ignoreFileError,
  settingsChanged,
  scanning,
  mode,
  appInfo,
  refreshFootprint,
  setStatus,
  errText,
} from "../store.js";
import IgnoreRulesDialog from "./IgnoreRulesDialog.vue";
import TagInput from "./TagInput.vue";

// The Options popover: tabs for what findings to show, where the scan gets credentials and ignore rules,
// the Trivy version and database, and app updates.
const trivyPlaceholder = computed(() => trivyNewest.value || mode.value?.trivyImage?.split(":").pop() || "Trivy version");
// What the Options popover shows without opening a section.
const activeCount = computed(
  () => [opts.ignoreUnfixed, opts.showSuppressed].filter(Boolean).length + opts.ignoreStatus.length,
);
const OPT_TABS = [
  { id: "findings", label: "Findings" },
  { id: "sources", label: "Sources" },
  { id: "scanner", label: "Scanner" },
  { id: "updates", label: "App updates" },
];
const optsTab = ref("findings");
const VENDOR_STATUSES = [
  { id: "will_not_fix", hint: "The vendor will not fix it" },
  { id: "not_affected", hint: "The vendor says the package is not affected" },
  { id: "affected", hint: "Affected, no fix yet" },
  { id: "fixed", hint: "Already fixed in this version" },
  { id: "under_investigation", hint: "The vendor is still looking into it" },
  { id: "fix_deferred", hint: "A fix is planned for later" },
  { id: "end_of_life", hint: "The vendor no longer supports this package" },
  { id: "unknown", hint: "No status reported" },
];
const toggleStatus = (id) => {
  const i = opts.ignoreStatus.indexOf(id);
  if (i < 0) opts.ignoreStatus.push(id);
  else opts.ignoreStatus.splice(i, 1);
};
const ignoreSummary = computed(() => [opts.ignorePolicy.trim() && "Rego", opts.ignoreFile.trim() && "ignore file"].filter(Boolean).join(" + ") || "none");
// The two rule sets as rows: what is set, with the editing in the IgnoreRulesDialog. Counts are a quick read of the text.
const ignoreDialog = ref(null);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const ignoreRows = computed(() => {
  const policy = opts.ignorePolicy.trim();
  const file = opts.ignoreFile.trim();
  const regoRules = (policy.match(/^\s*ignore\b/gm) ?? []).length;
  const entries = (file.match(/^\s*-\s+id\s*:/gm) ?? []).length;
  return [
    {
      id: "ignore-policy",
      tab: "policy",
      name: "Ignore policy (Rego)",
      flag: "--ignore-policy",
      count: policy ? plural(regoRules, "rule", "rules") : "empty",
      error: ignorePolicyError.value,
      upload: "Upload .rego…",
      accept: ".rego,text/plain",
      load: loadIgnorePolicyFile,
    },
    {
      id: "ignore-file",
      tab: "file",
      name: "Ignore file (.trivyignore.yaml)",
      flag: "--ignorefile",
      count: file ? plural(entries, "entry", "entries") : "empty",
      error: ignoreFileError.value,
      upload: "Upload .yaml…",
      accept: ".yaml,.yml,text/yaml,text/plain",
      load: loadIgnoreFile,
    },
  ];
});
async function uploadRules(row, ev) {
  await row.load(ev.target.files[0]);
  ev.target.value = ""; // picking the same file again must still fire
}
// Updating is three clicks, never automatic: check, then download, then restart.
const update = ref({ step: "idle", version: "" }); // idle | available | ready
const updateBusy = ref(false);
const dbBusy = ref(false);

async function updateStep(busyMsg, run) {
  updateBusy.value = true;
  setStatus(busyMsg, { busy: true });
  try {
    await run();
  } catch (err) {
    setStatus(errText(err), { err: true });
  } finally {
    updateBusy.value = false;
  }
}

// The DB is checked once after startup; this checks again now. Trivy downloads only if the cached one is out of date.
const updateDB = () =>
  updateStep("Updating the vulnerability database…", async () => {
    dbBusy.value = true;
    let downloaded;
    try {
      downloaded = await ScanService.UpdateDB(trivyImageSetting.value);
    } finally {
      dbBusy.value = false;
      refreshFootprint(); // a download changes the cache size shown in the footer
    }
    setStatus(downloaded ? "Downloaded a newer vulnerability database." : "No new database was downloaded: the local copy is current.");
  });

const checkForUpdates = () =>
  updateStep("Checking for updates…", async () => {
    const r = await ScanService.CheckForUpdates();
    update.value = r.available ? { step: "available", version: r.version } : { step: "idle", version: "" };
    setStatus(r.available ? `Version ${r.version} is available.` : "You are on the latest version.");
  });

const installUpdate = () =>
  updateStep(`Downloading ${update.value.version}…`, async () => {
    await ScanService.InstallUpdate();
    update.value = { ...update.value, step: "ready" };
    setStatus(`Version ${update.value.version} is downloaded and verified. Restart to apply it.`);
  });

const restartToUpdate = () => updateStep("Restarting…", () => ScanService.RestartToUpdate());

const updateAction = computed(() => {
  const v = update.value.version;
  switch (update.value.step) {
    case "available":
      return { label: `Download ${v}`, run: installUpdate };
    case "ready":
      return { label: "Restart & apply", run: restartToUpdate };
    default:
      return { label: "Check for updates…", run: checkForUpdates };
  }
});

</script>

<template>
<details id="opts">
  <summary>Options<span v-if="activeCount" class="opts-count"> · {{ activeCount }} active</span
  ><span v-if="settingsChanged" class="opts-count"> · rescan to apply</span></summary>
  <div class="opts-body">
    <div class="opts-tabs" role="tablist" aria-label="Options">
      <button
        v-for="t in OPT_TABS"
        :id="'opts-tab-' + t.id"
        :key="t.id"
        type="button"
        role="tab"
        class="opts-tab"
        :class="{ on: optsTab === t.id }"
        :aria-selected="optsTab === t.id"
        @click="optsTab = t.id"
      >
        {{ t.label }}
      </button>
    </div>
    <div v-show="optsTab === 'findings'" class="opts-pane" role="tabpanel">
      <div class="opts-label">Fix availability <code>--ignore-unfixed</code></div>
      <div class="opts-seg">
        <button type="button" id="ignore-unfixed-off" :class="{ on: !opts.ignoreUnfixed }" :aria-pressed="!opts.ignoreUnfixed" @click="opts.ignoreUnfixed = false">All</button>
        <button
          type="button"
          id="ignore-unfixed"
          :class="{ on: opts.ignoreUnfixed }"
          :aria-pressed="opts.ignoreUnfixed"
          title="Hide findings without a fix"
          @click="opts.ignoreUnfixed = true"
        >
          Fixable only
        </button>
      </div>
      <label class="opts-switch" title="Show findings that your ignore policy or ignore file would otherwise hide"
        ><span>Show suppressed findings <code>--show-suppressed</code></span><input type="checkbox" id="show-suppressed" v-model="opts.showSuppressed"
      /></label>
      <div class="opts-label">Hide vendor statuses <code>--ignore-status</code></div>

          <div class="chips">
            <button
              v-for="st in VENDOR_STATUSES"
              :key="st.id"
              type="button"
              class="chip"
              :class="{ on: opts.ignoreStatus.includes(st.id) }"
              :aria-pressed="opts.ignoreStatus.includes(st.id)"
              :title="st.hint"
              @click="toggleStatus(st.id)"
            >
              {{ st.id }}
            </button>
          </div>
    </div>
    <div v-show="optsTab === 'sources'" class="opts-pane" role="tabpanel">
      <div class="opts-label">Registry login</div>

          <input id="username" v-model="opts.username" :placeholder="mode?.registryToken ? mode.registryUser + ' (GITHUB_TOKEN, ghcr.io)' : 'Registry username'" autocomplete="off" />
          <input
            id="password"
            v-model="opts.password"
            type="password"
            :placeholder="mode?.registryToken ? '••••••••  GITHUB_TOKEN (ghcr.io)' : 'Registry password / token'"
            autocomplete="off"
          />
      <div class="opts-label">Ignore rules <span class="opts-val">{{ ignoreSummary }}</span></div>
      <div v-for="r in ignoreRows" :key="r.id" class="ignore-row">
        <div class="ignore-top">
          <span class="ignore-name">{{ r.name }}</span>
          <span class="ignore-count" :class="{ err: r.error }">{{ r.error ? "has an error" : r.count }}</span>
        </div>
        <code>{{ r.flag }}</code>
        <div class="ignore-acts">
          <label class="file-btn"
            >{{ r.upload }}
            <input :id="r.id + '-file'" type="file" :accept="r.accept" @change="uploadRules(r, $event)"
          /></label>
          <button type="button" class="ghost" :id="'edit-' + r.id" @click="ignoreDialog.open(r.tab)">Edit…</button>
        </div>
      </div>
    </div>
    <div v-show="optsTab === 'scanner'" class="opts-pane" role="tabpanel">
      <div class="opts-label">Trivy version</div>

          <TagInput
            id="trivy-image"
            v-model="opts.trivyImage"
            :tags="trivyTags"
            label="Trivy version"
            :placeholder="trivyPlaceholder"
            title="Leave empty to use the newest Trivy version, or enter one such as 0.77.0."
            @update:model-value="saveTrivyImage"
            @open="ensureTrivyTags"
          />
      <div class="opts-label">Vulnerability database</div>
      <div class="opts-row-plain">
        <span class="kv">Checked automatically before the first scan after startup. Update it here to get the latest data right away.</span>
        <button
          type="button"
          class="ghost"
          id="update-db-btn"
          :disabled="scanning || updateBusy"
          title="Download the latest vulnerability database if the local copy is out of date."
          @click="updateDB"
        >
          {{ dbBusy ? "Updating…" : "Update database" }}
        </button>
      </div>
    </div>
    <div v-show="optsTab === 'updates'" class="opts-pane" role="tabpanel">
      <div class="opts-label">Installed version</div>
      <div class="opts-row-plain">
        <strong id="app-version-opts">{{ appInfo ? appInfo.version : "" }}</strong>
        <button
          type="button"
          class="ghost"
          id="update-btn"
          :disabled="!appInfo?.enabled || updateBusy"
          @click="updateAction.run"
        >
          {{ updateAction.label }}
        </button>
      </div>
      <span class="kv">{{ appInfo?.enabled ? "Updates download from GitHub releases and are verified with SHA-256 before they are installed." : appInfo?.reason }}</span>
    </div>
  </div>
</details>
<IgnoreRulesDialog ref="ignoreDialog" />
</template>
