<script setup>
import { computed } from "vue";
import { result } from "../store.js";
import { findingPath, indexNodes } from "../lib/where.js";

const props = defineProps({ v: { type: Object, required: true } });
const index = computed(() => indexNodes(result.value?.depNodes));
const found = computed(() => findingPath(result.value, index.value, props.v));
const label = (n) => (n.version ? `${n.name} ${n.version}` : n.name);
</script>

<template>
  <div v-if="found" class="pmeans pwhere">
    <small>Where it lives</small>
    <ol class="chain">
      <li class="chain-image mono">{{ result.image }}</li>
      <li v-for="(n, i) in found.chain" :key="n.ref" :class="{ vulnerable: i === found.chain.length - 1 }" :style="{ '--depth': i + 1 }">
        <span class="mono">{{ label(n) }}</span>
        <span v-if="i === 0" class="kv">{{ n.category === "OS" ? "OS package" : "direct dependency of the image" }}</span>
        <span v-else-if="i === found.chain.length - 1" class="kv">{{ v.fixed ? "vulnerable, fixed in " + v.fixed.split(",")[0] : "vulnerable, no fix yet" }}</span>
      </li>
    </ol>
    <p v-if="found.others" class="kv">Also reached through {{ found.others }} other direct {{ found.others === 1 ? "dependency" : "dependencies" }} of the image.</p>
  </div>
</template>
