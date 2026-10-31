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
  images: { type: Array, default: () => [] }, // whole image references offered under the tags (Compare's "Recently scanned"): { value, meta }
  hint: { type: String, default: "" }, // a closing line in the list that is not an option
});
const emit = defineEmits(["update:modelValue", "open"]);

const TAG_LATEST = 5,
  TAG_MAX = 50,
  IMAGE_MAX = 3;
const open = ref(false);
const idx = ref(-1);
const typed = ref(false);
const query = computed(() => (typed.value ? props.modelValue.trim().toLowerCase() : ""));
const tagOptions = computed(() =>
  query.value ? props.tags.filter((t) => t.toLowerCase().includes(query.value)).slice(0, TAG_MAX) : props.tags.slice(0, TAG_LATEST),
);
const imageEntries = computed(() => (query.value ? props.images.filter((e) => e.value.toLowerCase().includes(query.value)) : props.images).slice(0, IMAGE_MAX));
const imageOptions = computed(() => imageEntries.value.map((e) => e.value));
// The note shown beside an option: only the image entries have one.
const metaOf = (i) => imageEntries.value[i - tagOptions.value.length]?.meta;
// One flat list so the arrow keys walk both groups; the template shows a heading before each.
const options = computed(() => [...tagOptions.value, ...imageOptions.value]);
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
  if (ev.key === "Escape") {
    if (shown.value) ev.preventDefault(); // closes only the list; a second Esc reaches the Options popover
    return close();
  }
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
      <div v-if="tagOptions.length" class="recent-head" aria-hidden="true">{{ query ? "Matching tags" : "Latest tags" }}</div>
      <template v-for="(t, i) in options" :key="(i >= tagOptions.length ? 'i:' : 't:') + t">
        <div v-if="i === tagOptions.length" class="recent-head" aria-hidden="true">Recently scanned</div>
        <div
          :id="id + '-opt-' + i"
          role="option"
          tabindex="-1"
          :aria-selected="i === idx"
          :class="{ active: i === idx }"
          @mousedown.prevent="pick(t)"
        >
          <span class="recent-name">{{ t }}</span>
          <span v-if="metaOf(i)" class="recent-when">{{ metaOf(i) }}</span>
        </div>
      </template>
      <div v-if="hint" class="recent-head hint" aria-hidden="true">{{ hint }}</div>
    </div>
  </div>
</template>
