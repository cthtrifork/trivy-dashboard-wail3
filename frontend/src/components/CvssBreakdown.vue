<script setup>
import { computed } from "vue";
import { breakdown } from "../lib/cvss.js";

const props = defineProps({ vector: { type: String, default: "" } });
const rows = computed(() => breakdown(props.vector));
</script>

<template>
  <div v-if="rows.length" class="cvss-break">
    <code class="rawvector">{{ vector }}</code>
    <dl>
      <div v-for="r in rows" :key="r.code">
        <dt>
          <code>{{ r.code }}</code>
        </dt>
        <dd>
          {{ r.label }}: <b>{{ r.value }}</b>
        </dd>
      </div>
    </dl>
  </div>
</template>
