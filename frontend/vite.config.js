import { writeFileSync } from "node:fs";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import wails from "@wailsio/runtime/plugins/vite";

// Vite empties dist/ on every build. The Go side embeds it, so `go vet` and `go test` need the
// directory to exist even when nobody has built the frontend; keep the committed placeholder.
const keepPlaceholder = () => ({
  name: "keep-dist-placeholder",
  closeBundle() {
    writeFileSync("dist/.gitkeep", "");
  },
});

export default defineConfig({
  server: {
    host: "127.0.0.1",
    port: Number(process.env.WAILS_VITE_PORT) || 9245,
    strictPort: true,
  },
  build: {
    rollupOptions: {
      output: {
        // Framework code changes far less often than the app; its own chunk stays cached across releases
        // (assets are served immutable, see internal/app/assets.go). CodeMirror is split off by the
        // dynamic imports of the editor components.
        manualChunks: (id) => (/node_modules\/(vue|@vue|@wailsio)\//.test(id) ? "vendor" : undefined),
      },
    },
  },
  plugins: [vue(), wails("./bindings"), keepPlaceholder()],
});
