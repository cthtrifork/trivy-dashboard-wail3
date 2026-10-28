<script setup>
import { onBeforeUnmount, ref } from "vue";

const props = defineProps({ text: { type: String, required: true } });
const done = ref(false);
let timer;

async function copy() {
  try {
    await navigator.clipboard.writeText(props.text);
  } catch {
    // WebKitGTK can refuse the async clipboard API; fall back to a throwaway textarea.
    const ta = document.createElement("textarea");
    ta.value = props.text;
    ta.style.cssText = "position:fixed;opacity:0";
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  done.value = true;
  clearTimeout(timer);
  timer = setTimeout(() => (done.value = false), 1500);
}

onBeforeUnmount(() => clearTimeout(timer));
</script>

<template>
  <button type="button" :class="['copy-id', { ok: done }]" :aria-label="'Copy ' + text" @click.stop.prevent="copy">
    <svg v-if="!done" viewBox="0 0 16 16" aria-hidden="true">
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
      <path d="M10.5 3.5v-.5A1.5 1.5 0 0 0 9 1.5H3A1.5 1.5 0 0 0 1.5 3v6A1.5 1.5 0 0 0 3 10.5h.5" />
    </svg>
    <svg v-else viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3.2 3L13 4.5" /></svg>
    <span class="copy-tip" role="status">{{ done ? "Copied" : "" }}</span>
  </button>
</template>
