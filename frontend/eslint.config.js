import js from "@eslint/js";
import pluginVue from "eslint-plugin-vue";
import globals from "globals";

export default [
  { ignores: ["dist/", "bindings/", "node_modules/"] },
  js.configs.recommended,
  ...pluginVue.configs["flat/essential"],
  {
    files: ["src/**/*.{js,vue}"],
    languageOptions: { globals: globals.browser },
    // Chip.vue is a deliberate single-word name.
    rules: { "vue/multi-word-component-names": "off" },
  },
  {
    files: ["vite.config.js"],
    languageOptions: { globals: globals.node },
  },
];
