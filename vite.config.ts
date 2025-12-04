import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// IMPORTANT: base = имя репозитория
export default defineConfig({
  plugins: [vue()],
  base: "/wireshark-viewer/",
  build: {
    outDir: "docs", // чтобы GitHub Pages мог брать из /docs
  },
});
