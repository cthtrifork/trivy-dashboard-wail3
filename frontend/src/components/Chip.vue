<script setup>
defineProps({ kind: { type: String, default: "" }, title: { type: String, default: "" } });
</script>

<template>
  <span :class="['chip', kind]" :title="title"><slot /></span>
</template>
