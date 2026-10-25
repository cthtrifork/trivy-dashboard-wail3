<script setup>
import { computed } from "vue";
import { assessing, vex } from "../store.js";
import { RESOLVED, STATUS_LABEL, isExpired } from "../lib/format.js";

// Opens the assess drawer for this finding; the form itself lives in VexDrawer.
const props = defineProps({ v: { type: Object, required: true } });
const existing = computed(() => vex.value.get(props.v.key));
const expired = computed(() => isExpired(existing.value));
// Resolved statements read green, an open one orange, "under investigation" blue; an expired one warns.
const tone = computed(() => {
  const s = existing.value?.status;
  return expired.value ? "warm" : RESOLVED.has(s) ? "ok" : s === "affected" ? "warm" : "info";
});
</script>

<template>
  <button
    type="button"
    :class="['vexbtn', existing ? `set ${tone}` : 'add']"
    :title="existing ? 'Edit this VEX assessment' : 'Record a VEX assessment for this finding'"
    @click.stop="assessing = v"
  >
    <template v-if="existing">
      VEX: {{ STATUS_LABEL[existing.status] }}{{ expired ? " · expired" : "" }}
      <span class="vexedit" aria-hidden="true"
        ><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"
          ><path d="M4 20h4l10-10-4-4L4 16v4zM13 7l4 4" /></svg
      ></span>
      <span class="sr">Edit</span>
    </template>
    <template v-else>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"
        ><path d="M12 5v14M5 12h14" /></svg
      >Add VEX assessment
    </template>
  </button>
</template>
