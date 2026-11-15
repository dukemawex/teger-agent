import { defineConfig } from "vitest/config";
import path from "node:path";
export default defineConfig({ test: { environment: "node", include: ["eval/**/*.eval.ts"], testTimeout: 120_000, fileParallelism: false }, resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } } });
