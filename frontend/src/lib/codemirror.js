import { EditorView } from "@codemirror/view";
import { HighlightStyle } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";

// Shared look of the CodeMirror boxes (JSON, YAML, Rego): app colours, so light and dark both work.
export const highlight = HighlightStyle.define([
  { tag: [t.propertyName, t.definition(t.propertyName)], color: "var(--accent)" },
  { tag: [t.string, t.content], color: "var(--ok)" },
  { tag: [t.number, t.bool, t.null, t.atom], color: "var(--HIGH)" },
  { tag: [t.keyword, t.meta], color: "var(--MEDIUM)" },
  { tag: [t.comment, t.lineComment], color: "var(--mute)", fontStyle: "italic" },
  { tag: [t.brace, t.squareBracket, t.separator, t.operator], color: "var(--mute)" },
  { tag: [t.labelName, t.typeName, t.function(t.variableName)], color: "var(--LOW)" },
]);

export const theme = EditorView.theme({
  "&": { height: "100%", backgroundColor: "var(--bg)", color: "var(--text)", fontSize: "13px" },
  "&.cm-focused": { outline: "2px solid var(--accent)" },
  ".cm-scroller": { fontFamily: "ui-monospace, monospace", lineHeight: "1.45" },
  ".cm-gutters": { backgroundColor: "var(--panel)", color: "var(--mute)", border: "0", borderRight: "1px solid var(--line)" },
  ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "transparent" },
  ".cm-cursor": { borderLeftColor: "var(--text)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": {
    backgroundColor: "color-mix(in srgb, var(--accent) 35%, transparent)",
  },
  ".cm-tooltip": { backgroundColor: "var(--panel)", color: "var(--text)", border: "1px solid var(--line)" },
  ".cm-placeholder": { color: "var(--mute)" },
});
