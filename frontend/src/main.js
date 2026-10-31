import { createApp } from "vue";
import App from "./App.vue";
import "./styles/index.css";

import { loadVocabulary } from "./store.js";

// The severity and tier lists come from Go; load them first so the first render already has them.
try {
  await loadVocabulary();
} catch (err) {
  console.error("Could not load the vocabulary from the backend:", err);
}
createApp(App).mount("#app");
