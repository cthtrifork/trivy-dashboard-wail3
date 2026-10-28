<script setup>
import { computed, nextTick, ref } from "vue";

// Tag combobox: the five newest tags until something is typed, then every loaded tag that matches.
const props = defineProps({
  modelValue: { type: String, default: "" },
  tags: { type: Array, default: () => [] }, // newest first
  disabled: Boolean,
  id: { type: String, default: "tag" },
  label: { type: String, default: "Tag" },
  placeholder: { type: String, default: "tag or digest" },
});
const emit = defineEmits(["update:modelValue", "open"]);

const TAG_LATEST = 5,
  TAG_MAX = 50;
const open = ref(false);
const idx = ref(-1);
const typed = ref(false);
const options = computed(() => {
  const q = props.modelValue.trim().toLowerCase();
  if (!typed.value || !q) return props.tags.slice(0, TAG_LATEST);
  return props.tags.filter((t) => t.toLowerCase().includes(q)).slice(0, TAG_MAX);
});
const shown = computed(() => open.value && options.value.length > 0);

function show(ev) {
  typed.value = false;
  open.value = true;
  emit("open");
  ev?.target?.select?.();
}
function close() {
  open.value = false;
  idx.value = -1;
}
function onInput(ev) {
  typed.value = true;
  open.value = true;
  idx.value = -1;
  emit("update:modelValue", ev.target.value);
}
function pick(t) {
  emit("update:modelValue", t);
  close();
}
function onKey(ev) {
  const n = options.value.length;
  if (ev.key === "Escape") return close();
  if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
    ev.preventDefault();
    if (!shown.value) return show();
    const step = ev.key === "ArrowDown" ? 1 : -1;
    idx.value = ((idx.value + 1 + step + n + 1) % (n + 1)) - 1; // -1 is the typed text
    nextTick(() => document.getElementById(props.id + "-opt-" + idx.value)?.scrollIntoView({ block: "nearest" }));
  } else if (ev.key === "Enter" && shown.value && idx.value >= 0) {
    ev.preventDefault(); // picking an option; the next Enter submits
    pick(options.value[idx.value]);
  }
}
</script>

<template>
  <div class="tag-wrap">
    <input
      :id="id"
      class="tag-input"
      :value="modelValue"
      :title="modelValue"
      role="combobox"
      aria-autocomplete="list"
      :aria-controls="id + '-list'"
      :aria-label="label"
      :aria-expanded="shown"
      :aria-activedescendant="idx >= 0 ? id + '-opt-' + idx : undefined"
      :placeholder="placeholder"
      autocomplete="off"
      spellcheck="false"
      :disabled="disabled"
      @focus="show"
      @click="open = true"
      @input="onInput"
      @blur="close"
      @keydown="onKey"
    />
    <button type="button" class="tag-toggle" tabindex="-1" aria-label="Show tags" :disabled="disabled" @mousedown.prevent="open ? close() : show()">
      ▾
    </button>
    <div :id="id + '-list'" class="tag-list" v-show="shown" role="listbox" :aria-label="label + 's'">
      <div class="recent-head" aria-hidden="true">{{ typed && modelValue.trim() ? "Matching tags" : "Latest tags" }}</div>
      <div
        v-for="(t, i) in options"
        :id="id + '-opt-' + i"
        :key="t"
        role="option"
        tabindex="-1"
        :aria-selected="i === idx"
        :class="{ active: i === idx }"
        @mousedown.prevent="pick(t)"
      >
        <span class="recent-name">{{ t }}</span>
      </div>
    </div>
  </div>
</template>
