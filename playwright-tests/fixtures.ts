import { test as base } from "@playwright/test";

export const test = base.extend<{ templateUrl: string }>({
	templateUrl: async ({ baseURL }, use) => {
		await use(baseURL ?? "http://localhost:8788");
	},
});

export { expect } from "@playwright/test";
