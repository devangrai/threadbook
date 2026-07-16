import { fileURLToPath, URL } from "node:url";

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const e2e = mode === "e2e";
  if (e2e && process.env.WARDROBE_E2E !== "1") {
    throw new Error("e2e mode requires WARDROBE_E2E=1");
  }

  return {
    plugins: [react()],
    clearScreen: false,
    resolve: {
      alias: {
        "@wardrobe/invoke-transport": fileURLToPath(
          new URL(
            e2e
              ? "./src/e2e/invoke-transport.ts"
              : "./src/invoke-transport.ts",
            import.meta.url,
          ),
        ),
      },
    },
    server: {
      host: "127.0.0.1",
      port: 1420,
      strictPort: true,
    },
    preview: {
      host: "127.0.0.1",
      port: 4173,
      strictPort: true,
    },
  };
});
