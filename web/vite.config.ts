import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api/v1 to the Go API so the browser never needs CORS.
// Override the target with VITE_API_TARGET when the API runs elsewhere.
const apiTarget = process.env.VITE_API_TARGET ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api/v1": {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
});
