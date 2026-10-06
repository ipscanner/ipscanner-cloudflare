import { defineConfig } from "@playwright/test";

export default defineConfig({
	testDir: "./playwright-tests",
	use: { baseURL: "http://localhost:8788" },
	webServer: {
		command: "npm run dev -- --port 8788",
		url: "http://localhost:8788",
		reuseExistingServer: false,
		timeout: 60_000,
	},
});
