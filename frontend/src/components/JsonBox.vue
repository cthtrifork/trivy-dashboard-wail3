<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import { EditorState } from "@codemirror/state";
import { EditorView, placeholder as cmPlaceholder } from "@codemirror/view";
import { basicSetup } from "codemirror";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { syntaxHighlighting } from "@codemirror/language";
import { linter, lintGutter } from "@codemirror/lint";
import { highlight, theme } from "../lib/codemirror.js";

// A JSON editor (CodeMirror 6) with syntax highlighting and inline syntax errors. With `vex` set it
// also checks that the document looks like OpenVEX, so a wrong file is flagged before importing.
const props = defineProps({
  modelValue: { type: String, default: "" },
  readonly: Boolean,
  rows: { type: Number, default: 8 },
  placeholder: { type: String, default: "" },
  taId: { type: String, default: "" },
  vex: Boolean,
});
const emit = defineEmits(["update:modelValue"]);

const root = ref(null);
let view = null;

// An empty box is not an error: the placeholder explains what to paste.
const parseLint = jsonParseLinter();
const syntaxLint = (v) => (v.state.doc.length ? parseLint(v) : []);

// Structural OpenVEX checks, run only once the text parses as JSON (jsonParseLinter reports the rest).
function vexLint(v) {
  const text = v.state.doc.toString();
  if (!text.trim()) return [];
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  const at = (message) => ({ from: 0, to: Math.min(1, text.length), severity: "error", message });
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return [at("An OpenVEX document is a JSON object.")];
  const out = [];
  if (!String(doc["@context"] ?? "").includes("openvex")) out.push(at('Missing "@context": expected https://openvex.dev/ns/v0.2.0.'));
  if (!Array.isArray(doc.statements) || !doc.statements.length) {
    out.push(at('"statements" must be a non-empty array.'));
  } else {
    doc.statements.forEach((s, i) => {
      if (!s?.vulnerability?.name) out.push(at(`statements[${i}]: missing vulnerability.name.`));
      if (!s?.status) out.push(at(`statements[${i}]: missing status.`));
    });
  }
  return out;
}

onMounted(() => {
  const extensions = [
    basicSetup,
    json(),
    syntaxHighlighting(highlight),
    theme,
    lintGutter(),
    linter(syntaxLint, { delay: 200 }),
    EditorView.contentAttributes.of({ "aria-label": props.taId || "JSON" }),
    EditorState.readOnly.of(props.readonly),
    EditorView.updateListener.of((u) => {
      if (u.docChanged) emit("update:modelValue", u.state.doc.toString());
    }),
  ];
  if (props.vex) extensions.push(linter(vexLint, { delay: 200 }));
  if (props.placeholder) extensions.push(cmPlaceholder(props.placeholder));
  view = new EditorView({ parent: root.value, state: EditorState.create({ doc: props.modelValue, extensions }) });
  root.value.__cm = view; // lets scripts/screenshots.mjs read and pin the text
});
onBeforeUnmount(() => view?.destroy());

watch(
  () => props.modelValue,
  (v) => {
    if (view && v !== view.state.doc.toString()) view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: v } });
  },
);

defineExpose({ select: () => view?.dispatch({ selection: { anchor: 0, head: view.state.doc.length } }) });
</script>

<template>
  <div :id="taId || undefined" ref="root" class="json-box" :style="{ '--rows': rows }"></div>
</template>
