import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
	plugins: [
		cloudflareTest({
			remoteBindings: false,
			wrangler: { configPath: "./wrangler.jsonc" },
			miniflare: { bindings: { IPSCANNER_API_KEY: "test-key" } },
		}),
	],
	test: {
		include: ["test/**/*.test.ts"],
	},
});
