<script setup>
// A count with a label, coloured by --c. Clickable cards toggle a filter; the rest are informational.
defineProps({ count: [Number, String], label: String, color: { type: String, default: "" }, off: Boolean, clickable: Boolean });
</script>

<template>
  <div class="card" :class="{ off }" :style="{ '--c': color, cursor: clickable ? 'pointer' : 'default' }">
    <b>{{ count }}</b
    ><span>{{ label }}</span>
  </div>
</template>
