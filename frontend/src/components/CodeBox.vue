<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import { EditorState } from "@codemirror/state";
import { EditorView, placeholder as cmPlaceholder } from "@codemirror/view";
import { basicSetup } from "codemirror";
import { yaml } from "@codemirror/lang-yaml";
import { ensureSyntaxTree, syntaxHighlighting } from "@codemirror/language";
import { setDiagnostics } from "@codemirror/lint";
import { rego } from "codemirror-lang-rego";
import { highlight, theme } from "../lib/codemirror.js";

// An editable YAML or Rego box (CodeMirror 6) with syntax highlighting. `error` is the message the Go side
// found for the text; the box underlines the line it names (or the first line of code when it names none).
// Rego also gets warnings from the grammar for spots that do not parse.
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

// The Rego grammar is young: it flags some valid rules (a one-line `x := v if cond`, `every` blocks). So its
// findings are only warnings, a few at most, and the wording says the check can be wrong.
const SYNTAX_WARNING = "Possible Rego syntax problem here. This check can be wrong on valid policies: Trivy has the final say.";
const MAX_SYNTAX_WARNINGS = 5;

function syntaxWarnings(state) {
  const doc = state.doc;
  const found = [];
  if (props.language !== "rego" || !doc.length) return found;
  ensureSyntaxTree(state, doc.length, 50)?.iterate({
    enter: (node) => {
      if (!node.type.isError || found.length >= MAX_SYNTAX_WARNINGS) return;
      const from = Math.min(node.from, doc.length - 1);
      found.push({ from, to: Math.min(Math.max(node.to, from + 1), doc.length), severity: "warning", message: SYNTAX_WARNING });
    },
  });
  return found;
}

function showError() {
  if (!view) return;
  const doc = view.state.doc;
  const diagnostics = syntaxWarnings(view.state);
  if (props.error && doc.length) {
    const line = doc.line(errorLine(doc));
    const to = Math.min(Math.max(line.to, line.from + 1), doc.length);
    diagnostics.unshift({ from: line.from, to, severity: "error", message: props.error });
  }
  view.dispatch(setDiagnostics(view.state, diagnostics));
}

onMounted(() => {
  const extensions = [
    basicSetup,
    props.language === "rego" ? rego() : yaml(),
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
