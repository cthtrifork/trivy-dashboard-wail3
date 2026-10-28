import { EditorView } from "@codemirror/view";
import { HighlightStyle, StreamLanguage } from "@codemirror/language";
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

const REGO_KEYWORDS = new Set(["package", "import", "default", "not", "some", "every", "in", "if", "contains", "else", "with", "as"]);
const REGO_ATOMS = new Set(["true", "false", "null"]);

// Rego has no CodeMirror package: a small tokenizer covers comments, strings, numbers, keywords and calls.
// Syntax errors are not found here; the Go side checks `package trivy` and Trivy parses the rest.
export const rego = StreamLanguage.define({
  name: "rego",
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.match("#")) {
      stream.skipToEnd();
      return "comment";
    }
    if (stream.match('"')) {
      let escaped = false;
      for (let c = stream.next(); c != null; c = stream.next()) {
        if (c === '"' && !escaped) break;
        escaped = !escaped && c === "\\";
      }
      return "string";
    }
    if (stream.match("`")) {
      if (!stream.skipTo("`")) stream.skipToEnd();
      else stream.next();
      return "string";
    }
    if (stream.match(/^-?\d+(\.\d+)?([eE][+-]?\d+)?/)) return "number";
    if (stream.match(/^[A-Za-z_][\w.]*/)) {
      const word = stream.current();
      if (REGO_KEYWORDS.has(word)) return "keyword";
      if (REGO_ATOMS.has(word)) return "atom";
      return stream.peek() === "(" ? "variableName.function" : "variableName";
    }
    if (stream.match(/^(:=|==|!=|<=|>=|[=<>+\-*/%|&])/)) return "operator";
    stream.next();
    return null;
  },
  languageData: { commentTokens: { line: "#" } },
});
