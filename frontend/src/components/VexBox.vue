<script setup>
import { computed } from "vue";
import { assessing, vex } from "../store.js";
import { STATUS_LABEL, isExpired } from "../lib/format.js";

// Opens the assess drawer for this finding; the form itself lives in VexDrawer.
const props = defineProps({ v: { type: Object, required: true } });
const existing = computed(() => vex.value.get(props.v.key));
</script>

<template>
  <button type="button" class="ghost vexbtn" :class="{ set: existing }" @click.stop="assessing = v">
    {{
      existing
        ? `VEX assessment: ${STATUS_LABEL[existing.status]}${isExpired(existing) ? " (expired)" : ""} · Edit`
        : "Assess this finding (VEX)"
    }}
  </button>
</template>
