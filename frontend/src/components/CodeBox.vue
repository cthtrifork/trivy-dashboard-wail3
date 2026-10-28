<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import { EditorState } from "@codemirror/state";
import { EditorView, placeholder as cmPlaceholder } from "@codemirror/view";
import { basicSetup } from "codemirror";
import { yaml } from "@codemirror/lang-yaml";
import { syntaxHighlighting } from "@codemirror/language";
import { setDiagnostics } from "@codemirror/lint";
import { highlight, rego, theme } from "../lib/codemirror.js";

// An editable YAML or Rego box (CodeMirror 6) with syntax highlighting. `error` is the message the Go side
// found for the text; the box underlines the line it names (or the first line of code when it names none).
const props = defineProps({
  modelValue: { type: String, default: "" },
  language: { type: String, default: "yaml" }, // yaml | rego
  error: { type: String, default: "" },
  rows: { type: Number, default: 6 },
  placeholder: { type: String, default: "" },
  taId: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue", "commit"]);

const root = ref(null);
let view = null;
let dirty = false;

function errorLine(doc) {
  const named = /line (\d+)/.exec(props.error);
  if (named) return Math.min(Number(named[1]), doc.lines);
  if (props.language === "rego") {
    for (let n = 1; n <= doc.lines; n++) {
      const text = doc.line(n).text.trim();
      if (text && !text.startsWith("#")) return n;
    }
  }
  return 1;
}

function showError() {
  if (!view) return;
  const doc = view.state.doc;
  if (!props.error || !doc.length) {
    view.dispatch(setDiagnostics(view.state, []));
    return;
  }
  const line = doc.line(errorLine(doc));
  const to = Math.max(line.to, line.from + 1);
  view.dispatch(setDiagnostics(view.state, [{ from: line.from, to: Math.min(to, doc.length), severity: "error", message: props.error }]));
}

onMounted(() => {
  const extensions = [
    basicSetup,
    props.language === "rego" ? rego : yaml(),
    syntaxHighlighting(highlight),
    theme,
    EditorView.contentAttributes.of({ "aria-label": props.taId || props.language }),
    EditorView.updateListener.of((u) => {
      if (u.docChanged) {
        dirty = true;
        emit("update:modelValue", u.state.doc.toString());
      }
    }),
    EditorView.domEventHandlers({
      blur: () => {
        if (dirty) emit("commit");
        dirty = false;
      },
    }),
  ];
  if (props.placeholder) extensions.push(cmPlaceholder(props.placeholder));
  view = new EditorView({ parent: root.value, state: EditorState.create({ doc: props.modelValue, extensions }) });
  root.value.__cm = view; // lets scripts read and pin the text, as for JsonBox
  showError();
});
onBeforeUnmount(() => view?.destroy());

watch(
  () => props.modelValue,
  (v) => {
    if (view && v !== view.state.doc.toString()) view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: v } });
  },
);
// The text can change after the message was computed (it arrives ~300 ms later), so redraw on both.
watch(() => [props.error, props.modelValue], showError);
</script>

<template>
  <div :id="taId || undefined" ref="root" class="code-box" :style="{ '--rows': rows }"></div>
</template>
