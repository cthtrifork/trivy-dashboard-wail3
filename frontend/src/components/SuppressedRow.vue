<script setup>
import { vex } from "../store.js";
import { JUSTIFICATIONS, STATUS_LABEL } from "../lib/format.js";
import Chip from "./Chip.vue";
import VexBox from "./VexBox.vue";

// One finding hidden by VEX. `child` rows sit under a CVE shared by several components, so the id is left to the parent.
defineProps({ v: { type: Object, required: true }, child: Boolean });
</script>

<template>
  <div :class="child ? 'sup child' : 'sup'">
    <div class="phead">
      <span v-if="!child" class="id">{{ v.id }}</span>
      <span class="mono">{{ v.package }} {{ v.installed }}</span>
      <Chip kind="vex">{{ STATUS_LABEL[vex.get(v.key).status] }}</Chip>
      <Chip v-if="vex.get(v.key).expires" title="The finding reappears after this date">until {{ vex.get(v.key).expires }}</Chip>
      <Chip v-if="vex.get(v.key).author">{{ vex.get(v.key).author }}</Chip>
    </div>
    <div class="kv">
      {{ [JUSTIFICATIONS[vex.get(v.key).justification], vex.get(v.key).impact].filter(Boolean).join(" — ") }}
    </div>
    <VexBox :v="v" />
  </div>
</template>
