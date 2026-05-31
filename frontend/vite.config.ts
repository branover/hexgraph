import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build the SPA into the Python package so FastAPI serves it as static assets.
// In dev, proxy the JSON API + SSE to the loopback backend.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../src/hexgraph/web/dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8765",
      "/graph": "http://127.0.0.1:8765",
      "/health": "http://127.0.0.1:8765",
    },
  },
});
