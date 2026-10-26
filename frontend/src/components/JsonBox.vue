<script setup>
import { computed, ref, watch } from "vue";

// A textarea with JSON syntax highlighting: the text is drawn in a <pre> underneath and the
// textarea on top is transparent, so editing, selection and copy stay native.
const props = defineProps({
  modelValue: { type: String, default: "" },
  readonly: Boolean,
  rows: { type: Number, default: 8 },
  placeholder: { type: String, default: "" },
  taId: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue"]);

const code = ref(props.modelValue);
watch(
  () => props.modelValue,
  (v) => (code.value = v),
);
const ta = ref(null);
const pre = ref(null);

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}[\],:])/g;

const html = computed(() => {
  let out = "";
  let last = 0;
  const s = code.value;
  for (const m of s.matchAll(TOKEN)) {
    out += esc(s.slice(last, m.index));
    const [all, str, colon, lit, num, punct] = m;
    if (str) out += `<span class="${colon ? 'j-key' : 'j-str'}">${esc(str)}</span>${colon ? `<span class="j-p">${colon}</span>` : ""}`;
    else if (lit) out += `<span class="j-lit">${lit}</span>`;
    else if (num) out += `<span class="j-num">${num}</span>`;
    else if (punct) out += `<span class="j-p">${punct}</span>`;
    last = m.index + all.length;
  }
  // A trailing newline would collapse in the <pre>, so the last line gets a space to keep heights equal.
  return out + esc(s.slice(last)) + "\n ";
});

const sync = () => {
  pre.value.scrollTop = ta.value.scrollTop;
  pre.value.scrollLeft = ta.value.scrollLeft;
};
// Fires for user typing and for scripts that set .value and dispatch "input".
function onInput(e) {
  code.value = e.target.value;
  emit("update:modelValue", code.value);
}

defineExpose({ select: () => ta.value.select() });
</script>

<template>
  <div class="json-box" :style="{ '--rows': rows }">
    <pre ref="pre" aria-hidden="true" v-html="html"></pre>
    <textarea
      :id="taId || undefined"
      ref="ta"
      :value="modelValue"
      :readonly="readonly"
      :placeholder="placeholder"
      spellcheck="false"
      wrap="off"
      @input="onInput"
      @scroll="sync"
    ></textarea>
  </div>
</template>
