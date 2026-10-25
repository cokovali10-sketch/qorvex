import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 8421,
    proxy: {
      "/api": "http://localhost:8420",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});