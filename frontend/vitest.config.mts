import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// TSX: React 18 automatic runtime, as Next compiles it.

export default defineConfig({
  esbuild: { jsx: "automatic" },
  resolve: { alias: { "@": fileURLToPath(new URL(".", import.meta.url)) } },
  test: { environment: "node", include: ["**/*.test.ts", "**/*.test.tsx"], exclude: ["node_modules/**", ".next/**"] },
});
