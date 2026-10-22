import {
	createExecutionContext,
	waitOnExecutionContext,
} from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { clearPolicyMemo, VERSION } from "../src/ipscanner";

const API = "https://ipscanner.io";

const human = {
	class: "human",
	confidence: 0.92,
	action: "allow",
	signals: { network_origin: "residential_clean", anonymized: false },
};
const cleanNetwork = {
	networkClass: "residential_clean",
	anonymized: false,
	riskScore: 3,
	provider: "Deutsche Telekom",
	vpnProvider: null,
	country: "DE",
	asn: 3320,
	asnName: "Deutsche Telekom AG",
};

const edgeHuman = {
	class: "human",
	agent: human,
	network: cleanNetwork,
	site: { id: "site_test", mode: "monitor", policyVersion: 1 },
};

// The edge check without a site, as the legacy path gets it.
function legacyEdge(extra: Record<string, unknown> = {}) {
	return {
		class: "human",
		agent: human,
		network: cleanNetwork,
		site: null,
		...extra,
	};
}

function blockingAgent(agentClass = "malicious_automation") {
	return { ...human, class: agentClass, action: "block" };
}

function sitePolicy(
	site: string,
	mode: "monitor" | "enforce",
	policy: Record<string, string>,
	version = 1,
) {
	return { site, mode, policy, version, updatedAt: "2026-10-08T00:00:00Z" };
}

function edgeVerdict(trafficClass: string, agentClass = trafficClass) {
	return {
		...edgeHuman,
		class: trafficClass,
		agent: { ...human, class: agentClass, action: "flag" },
	};
}

interface Recorded {
	url: string;
	method: string;
	headers: Headers;
	body: string;
}

let calls: Recorded[];
let logs: unknown[][];
let edgeReply: () => Promise<Response>;
let policyReply: (site: string) => Promise<Response>;

function json(body: unknown, status = 200): Promise<Response> {
	return Promise.resolve(Response.json(body, { status }));
}

function hang(signal?: AbortSignal | null): Promise<Response> {
	return new Promise((_, reject) =>
		signal?.addEventListener("abort", () => reject(signal.reason)),
	);
}

beforeEach(() => {
	calls = [];
	edgeReply = () => json(legacyEdge());
	policyReply = (site) => json(sitePolicy(site, "monitor", {}));
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const req = new Request(input, init);
		calls.push({
			url: req.url,
			method: req.method,
			headers: req.headers,
			body: await req.clone().text(),
		});
		if (req.url === `${API}/v1/edge/check`) return edgeReply();
		const policy = req.url.match(/^https:\/\/[^/]+\/v1\/sites\/([^/]+)\/policy$/);
		if (policy) return policyReply(decodeURIComponent(policy[1]));
		return new Response("origin ok", { headers: { "X-Origin": "1" } });
	});
	logs = [];
	vi.spyOn(console, "log").mockImplementation((...args) => {
		logs.push(args);
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

function apiCalls(): Recorded[] {
	return calls.filter((c) => c.url.startsWith(API));
}

function originCall(): Recorded | undefined {
	return calls.find((c) => !c.url.startsWith(API));
}

function apiPaths(): string[] {
	return apiCalls().map((c) => new URL(c.url).pathname);
}

function lastLog(): Record<string, unknown> {
	const lines = logs
		.map(([line]) => JSON.parse(String(line)))
		.filter((l) => "decision" in l);
	return lines[lines.length - 1];
}

async function send(
	path: string,
	opts: { ip?: string; vars?: Partial<Env>; init?: RequestInit } = {},
): Promise<Response> {
	const headers = new Headers(opts.init?.headers);
	headers.set("CF-Connecting-IP", opts.ip ?? "203.0.113.10");
	if (!headers.has("User-Agent")) headers.set("User-Agent", "Mozilla/5.0 test");
	const request = new Request(`https://example.com${path}`, {
		...opts.init,
		headers,
	});
	const ctx = createExecutionContext();
	const res = await worker.fetch(
		request as Request<unknown, IncomingRequestCfProperties>,
		{ ...env, ...opts.vars },
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return res;
}

describe("monitor mode", () => {
	it("adds verdict headers to the origin request", async () => {
		const res = await send("/", { ip: "203.0.113.1" });
		expect(res.status).toBe(200);
		expect(await res.text()).toBe("origin ok");
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-status")).toBe("ok");
		expect(h.get("x-ipscanner-class")).toBe("human");
		expect(h.get("x-ipscanner-action")).toBe("allow");
		expect(h.get("x-ipscanner-confidence")).toBe("0.92");
		expect(h.get("x-ipscanner-network-class")).toBe("residential_clean");
		expect(h.get("x-ipscanner-anonymized")).toBe("false");
		expect(h.get("x-ipscanner-risk")).toBe("3");
		expect(h.get("x-ipscanner-country")).toBe("DE");
	});

	it("does not block in monitor mode", async () => {
		edgeReply = () =>
			json(legacyEdge({ class: "malicious_automation", agent: blockingAgent() }));
		const res = await send("/", { ip: "203.0.113.2" });
		expect(res.status).toBe(200);
		expect(originCall()!.headers.get("x-ipscanner-action")).toBe("block");
		expect(lastLog().decision).toBe("would_block");
	});

	it("sends one edge check without a site", async () => {
		await send("/", {
			ip: "203.0.113.3",
			init: {
				headers: {
					"Accept-Language": "en",
					"Sec-Fetch-Mode": "navigate",
					Cookie: "secret=1",
					"CF-Ray": "ray3",
				},
			},
		});
		expect(apiPaths()).toEqual(["/v1/edge/check"]);
		const edge = apiCalls()[0];
		expect(edge.method).toBe("POST");
		expect(edge.headers.get("authorization")).toBe("Bearer test-key");
		expect(edge.headers.get("content-type")).toBe("application/json");
		expect(edge.headers.get("x-ipscanner-source")).toBe("cloudflare_worker");
		expect(edge.headers.get("user-agent")).toBe(`ipscanner-cloudflare/${VERSION}`);
		expect(JSON.parse(edge.body)).toEqual({
			ip: "203.0.113.3",
			user_agent: "Mozilla/5.0 test",
			headers: {
				"accept-language": "en",
				"sec-fetch-mode": "navigate",
			},
			request_id: "ray3",
		});
	});
});

describe("enforce mode", () => {
	const enforce = { MODE: "enforce" };

	it("blocks when agentscan says block", async () => {
		edgeReply = () =>
			json(legacyEdge({ class: "ai_agent", agent: blockingAgent("ai_agent") }));
		const res = await send("/", {
			ip: "203.0.113.4",
			vars: enforce,
			init: { headers: { "CF-Ray": "abc123" } },
		});
		expect(res.status).toBe(403);
		const body = await res.text();
		expect(body).toContain("Blocked by IPScanner edge guard");
		expect(body).toContain("abc123");
		expect(originCall()).toBeUndefined();
		expect(lastLog().decision).toBe("block");
	});

	it("blocks classes listed in BLOCK_CLASSES", async () => {
		edgeReply = () =>
			json(
				legacyEdge({
					class: "ai_agent",
					agent: { ...human, class: "ai_agent", action: "flag" },
				}),
			);
		const res = await send("/", {
			ip: "203.0.113.5",
			vars: { ...enforce, BLOCK_CLASSES: "ai_agent, malicious_automation" },
		});
		expect(res.status).toBe(403);
	});

	it("allows verified crawlers", async () => {
		edgeReply = () =>
			json(
				legacyEdge({
					class: "verified_bot",
					agent: {
						class: "known_bot",
						confidence: 0.99,
						action: "block",
						signals: { allowlist_verified: true, allowlist_type: "search" },
					},
				}),
			);
		const res = await send("/", { ip: "203.0.113.6", vars: enforce });
		expect(res.status).toBe(200);
		expect(originCall()!.headers.get("x-ipscanner-class")).toBe("known_bot");
	});

	it("blocks anonymized traffic when BLOCK_ANONYMIZED is on", async () => {
		edgeReply = () =>
			json(
				legacyEdge({
					class: "vpn",
					network: { ...cleanNetwork, networkClass: "vpn", anonymized: true },
				}),
			);
		const vars = { ...enforce, BLOCK_ANONYMIZED: "true" };
		expect((await send("/", { ip: "203.0.113.7", vars })).status).toBe(403);
		expect((await send("/", { ip: "203.0.113.7", vars: enforce })).status).toBe(
			200,
		);
	});

	it("leaves anonymized hosting and private relays alone", async () => {
		const vars = { ...enforce, BLOCK_ANONYMIZED: "true" };
		for (const [ip, networkClass] of [
			["203.0.113.30", "hosting"],
			["203.0.113.31", "relay"],
		]) {
			edgeReply = () =>
				json(
					legacyEdge({
						class: networkClass,
						network: { ...cleanNetwork, networkClass, anonymized: true },
					}),
				);
			expect((await send("/", { ip, vars })).status).toBe(200);
		}
	});
});

describe("api mode without a site", () => {
	const enforce = { MODE: "enforce" };

	it("never blocks when the api answers monitor", async () => {
		const cases: [string, Record<string, unknown>, Partial<Env>][] = [
			["203.0.113.40", { agent: blockingAgent() }, enforce],
			[
				"203.0.113.41",
				{ agent: { ...human, class: "ai_agent", action: "flag" } },
				{ ...enforce, BLOCK_CLASSES: "ai_agent" },
			],
			[
				"203.0.113.42",
				{ network: { ...cleanNetwork, networkClass: "vpn", anonymized: true } },
				{ ...enforce, BLOCK_ANONYMIZED: "true" },
			],
		];
		for (const [ip, verdict, vars] of cases) {
			edgeReply = () => json(legacyEdge({ ...verdict, mode: "monitor" }));
			calls = [];
			const res = await send("/", { ip, vars });
			expect(res.status).toBe(200);
			expect(originCall()).toBeDefined();
			expect(originCall()!.headers.get("x-ipscanner-status")).toBe("ok");
			expect(lastLog()).toMatchObject({ decision: "would_block", mode: "monitor" });
		}
	});

	it("blocks when the api answers enforce", async () => {
		edgeReply = () =>
			json(legacyEdge({ agent: blockingAgent(), mode: "enforce" }));
		const res = await send("/", { ip: "203.0.113.43", vars: enforce });
		expect(res.status).toBe(403);
		expect(lastLog()).toMatchObject({ decision: "block", mode: "enforce" });
	});

	it("blocks as before when the api sends no mode", async () => {
		edgeReply = () => json(legacyEdge({ agent: blockingAgent() }));
		const res = await send("/", { ip: "203.0.113.44", vars: enforce });
		expect(res.status).toBe(403);
	});

	it("does not block in MODE=monitor when the api answers enforce", async () => {
		edgeReply = () =>
			json(legacyEdge({ agent: blockingAgent(), mode: "enforce" }));
		const res = await send("/", { ip: "203.0.113.45" });
		expect(res.status).toBe(200);
		expect(lastLog().decision).toBe("would_block");
	});

	it("keeps the mode a cached verdict was answered with", async () => {
		edgeReply = () =>
			json(legacyEdge({ agent: blockingAgent(), mode: "monitor" }));
		expect((await send("/", { ip: "203.0.113.46", vars: enforce })).status).toBe(
			200,
		);
		edgeReply = () =>
			json(legacyEdge({ agent: blockingAgent(), mode: "enforce" }));
		calls = [];
		expect((await send("/", { ip: "203.0.113.46", vars: enforce })).status).toBe(
			200,
		);
		expect(apiCalls()).toHaveLength(0);
	});
});

describe("fail open", () => {
	it("forwards with status timeout when the API is slow", async () => {
		vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
			const req = new Request(input, init);
			calls.push({
				url: req.url,
				method: req.method,
				headers: req.headers,
				body: "",
			});
			if (req.url.startsWith(API)) return hang(init?.signal);
			return new Response("origin ok");
		});
		const res = await send("/", {
			ip: "203.0.113.8",
			vars: { MODE: "enforce", TIMEOUT_MS: "20" },
		});
		expect(res.status).toBe(200);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-status")).toBe("timeout");
		expect(h.get("x-ipscanner-class")).toBeNull();
	});

	it("forwards with status error when the API fails", async () => {
		edgeReply = () => json({ error: "server_error", message: "boom" }, 500);
		const res = await send("/", {
			ip: "203.0.113.9",
			vars: { MODE: "enforce" },
		});
		expect(res.status).toBe(200);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-status")).toBe("error");
		expect(h.get("x-ipscanner-risk")).toBeNull();
	});

	it("treats an answer missing an enabled half as a failed check", async () => {
		edgeReply = () =>
			json(
				legacyEdge({
					agent: blockingAgent(),
					network: null,
					degraded: ["network"],
				}),
			);
		const res = await send("/", {
			ip: "203.0.113.32",
			vars: { MODE: "enforce" },
		});
		expect(res.status).toBe(200);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-status")).toBe("error");
		expect(h.get("x-ipscanner-class")).toBeNull();
		edgeReply = () => json(legacyEdge());
		calls = [];
		await send("/", { ip: "203.0.113.32" });
		expect(apiPaths()).toEqual(["/v1/edge/check"]);
		expect(originCall()!.headers.get("x-ipscanner-status")).toBe("ok");
	});

	it("uses an answer whose missing half is turned off", async () => {
		edgeReply = () =>
			json(
				legacyEdge({
					agent: blockingAgent(),
					network: null,
					degraded: ["network"],
				}),
			);
		const res = await send("/", {
			ip: "203.0.113.33",
			vars: { MODE: "enforce", CHECK_IP: "false" },
		});
		expect(res.status).toBe(403);
	});
});

describe("passthrough", () => {
	it("strips spoofed X-IPScanner headers", async () => {
		await send("/", {
			ip: "203.0.113.11",
			vars: { IPSCANNER_API_KEY: "" },
			init: {
				headers: { "X-IPScanner-Class": "human", "X-IPScanner-Risk": "0" },
			},
		});
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-class")).toBeNull();
		expect(h.get("x-ipscanner-risk")).toBeNull();
		expect(h.get("x-ipscanner-status")).toBe("skipped");
		expect(apiCalls()).toHaveLength(0);
	});

	it("replaces spoofed headers with real verdicts", async () => {
		await send("/", {
			ip: "203.0.113.12",
			init: { headers: { "X-IPScanner-Class": "known_bot" } },
		});
		expect(originCall()!.headers.get("x-ipscanner-class")).toBe("human");
	});

	it("skips static asset paths", async () => {
		const res = await send("/assets/app.css", { ip: "203.0.113.13" });
		expect(res.status).toBe(200);
		expect(apiCalls()).toHaveLength(0);
		expect(originCall()!.headers.get("x-ipscanner-status")).toBe("skipped");
	});

	it("skips OPTIONS requests", async () => {
		await send("/api", { ip: "203.0.113.14", init: { method: "OPTIONS" } });
		expect(apiCalls()).toHaveLength(0);
	});

	it("skips when both checks are off", async () => {
		await send("/", {
			ip: "203.0.113.34",
			vars: { CHECK_AGENT: "false", CHECK_IP: "false" },
		});
		expect(apiCalls()).toHaveLength(0);
		expect(originCall()!.headers.get("x-ipscanner-status")).toBe("skipped");
	});

	it("checks other methods", async () => {
		await send("/api", {
			ip: "203.0.113.15",
			init: { method: "POST", body: "x=1" },
		});
		expect(apiCalls()).toHaveLength(1);
		expect(originCall()!.method).toBe("POST");
		expect(originCall()!.body).toBe("x=1");
	});

	it("uses only the IP half with CHECK_AGENT off", async () => {
		edgeReply = () =>
			json(
				legacyEdge({
					agent: blockingAgent(),
					network: { ...cleanNetwork, networkClass: "hosting", riskScore: 40 },
				}),
			);
		const res = await send("/", {
			ip: "203.0.113.35",
			vars: { MODE: "enforce", CHECK_AGENT: "false" },
		});
		expect(res.status).toBe(200);
		expect(apiPaths()).toEqual(["/v1/edge/check"]);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-class")).toBeNull();
		expect(h.get("x-ipscanner-action")).toBeNull();
		expect(h.get("x-ipscanner-confidence")).toBeNull();
		expect(h.get("x-ipscanner-network-class")).toBe("hosting");
		expect(h.get("x-ipscanner-risk")).toBe("40");
		expect(h.get("x-ipscanner-country")).toBe("DE");
	});

	it("uses only the agent half with CHECK_IP off", async () => {
		edgeReply = () =>
			json(
				legacyEdge({
					network: { ...cleanNetwork, networkClass: "vpn", anonymized: true },
				}),
			);
		const res = await send("/", {
			ip: "203.0.113.16",
			vars: { MODE: "enforce", CHECK_IP: "false", BLOCK_ANONYMIZED: "true" },
		});
		expect(res.status).toBe(200);
		expect(apiPaths()).toEqual(["/v1/edge/check"]);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-class")).toBe("human");
		expect(h.get("x-ipscanner-network-class")).toBe("residential_clean");
		expect(h.get("x-ipscanner-anonymized")).toBe("false");
		expect(h.get("x-ipscanner-risk")).toBeNull();
		expect(h.get("x-ipscanner-country")).toBeNull();
	});
});

describe("caching", () => {
	it("serves repeat visitors from cache", async () => {
		await send("/", { ip: "203.0.113.17" });
		expect(apiCalls()).toHaveLength(1);
		calls = [];
		await send("/other", { ip: "203.0.113.17" });
		expect(apiCalls()).toHaveLength(0);
		expect(originCall()!.headers.get("x-ipscanner-class")).toBe("human");
		expect(lastLog().cache).toEqual({ agent: "hit", ip: "hit" });
	});

	it("does not cache failures", async () => {
		edgeReply = () => json({ error: "server_error" }, 500);
		await send("/", { ip: "203.0.113.18" });
		edgeReply = () => json(legacyEdge());
		calls = [];
		await send("/", { ip: "203.0.113.18" });
		expect(apiPaths()).toEqual(["/v1/edge/check"]);
	});

	it("caches per IP and User-Agent", async () => {
		await send("/", { ip: "203.0.113.36" });
		calls = [];
		await send("/", {
			ip: "203.0.113.36",
			init: { headers: { "User-Agent": "Other/1.0" } },
		});
		expect(apiPaths()).toEqual(["/v1/edge/check"]);
	});

	it("caches per IP with CHECK_AGENT off", async () => {
		const vars = { CHECK_AGENT: "false" };
		await send("/", { ip: "203.0.113.37", vars });
		calls = [];
		await send("/", {
			ip: "203.0.113.37",
			vars,
			init: { headers: { "User-Agent": "Other/1.0" } },
		});
		expect(apiCalls()).toHaveLength(0);
		expect(lastLog().cache).toEqual({ ip: "hit" });
	});
});

describe("routing", () => {
	it("forwards to ORIGIN_URL when set", async () => {
		await send("/path?q=1", {
			ip: "203.0.113.19",
			vars: { ORIGIN_URL: "https://backend.example.net" },
		});
		expect(originCall()!.url).toBe("https://backend.example.net/path?q=1");
	});

	it("keeps paths that look like another host on ORIGIN_URL", async () => {
		for (const path of ["//evil.example/x?q=1", "/\\evil.example/x?q=1"]) {
			calls = [];
			await send(path, {
				ip: "203.0.113.22",
				vars: { ORIGIN_URL: "https://backend.example.net" },
			});
			expect(originCall()!.url).toBe(
				"https://backend.example.net//evil.example/x?q=1",
			);
		}
	});

	it("shows the setup page on workers.dev without an origin", async () => {
		const ctx = createExecutionContext();
		const req = new Request(
			"https://ipscanner-cloudflare.example.workers.dev/",
			{ headers: { "CF-Connecting-IP": "203.0.113.20" } },
		);
		const res = await worker.fetch(
			req as Request<unknown, IncomingRequestCfProperties>,
			{ ...env, IPSCANNER_API_KEY: "" },
			ctx,
		);
		await waitOnExecutionContext(ctx);
		const body = await res.text();
		expect(res.status).toBe(200);
		expect(body).toContain("IPScanner edge guard");
		expect(body).toContain("API key missing");
		expect(originCall()).toBeUndefined();
	});
});

describe("legacy path", () => {
	it("makes exactly one edge check when SITE_ID is unset", async () => {
		await send("/", { ip: "203.0.113.21", vars: { SITE_ID: "" } });
		expect(apiPaths()).toEqual(["/v1/edge/check"]);
		expect("site" in JSON.parse(apiCalls()[0].body)).toBe(false);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-traffic-class")).toBeNull();
		expect(h.get("x-ipscanner-site")).toBeNull();
	});
});

describe("sites", () => {
	let n = 0;
	let site: string;
	let ipCounter = 0;
	const nextIp = () => `198.51.100.${++ipCounter}`;
	const vars = (extra: Partial<Env> = {}): Partial<Env> => ({
		SITE_ID: site,
		...extra,
	});
	const paths = () => apiCalls().map((c) => new URL(c.url).pathname);
	const policyCalls = () => paths().filter((p) => p.endsWith("/policy"));
	const edgeCalls = () => paths().filter((p) => p === "/v1/edge/check");
	let now: number;
	const advance = (ms: number) => {
		now += ms;
	};

	beforeEach(() => {
		site = `site_test${++n}`;
		edgeReply = () => json(edgeHuman);
		now = 1_800_000_000_000;
		vi.spyOn(Date, "now").mockImplementation(() => now);
	});

	it("makes one edge check and one policy fetch per visitor", async () => {
		const res = await send("/", {
			ip: "198.51.100.200",
			vars: vars(),
			init: { headers: { "CF-Ray": "ray123", "Accept-Language": "en" } },
		});
		expect(res.status).toBe(200);
		expect(paths().sort()).toEqual([
			"/v1/edge/check",
			`/v1/sites/${site}/policy`,
		]);
		const edge = apiCalls().find((c) => c.url.endsWith("/v1/edge/check"))!;
		expect(edge.method).toBe("POST");
		expect(edge.headers.get("authorization")).toBe("Bearer test-key");
		expect(edge.headers.get("x-ipscanner-source")).toBe("cloudflare_worker");
		expect(edge.headers.get("user-agent")).toBe(`ipscanner-cloudflare/${VERSION}`);
		expect(JSON.parse(edge.body)).toEqual({
			site,
			ip: "198.51.100.200",
			user_agent: "Mozilla/5.0 test",
			headers: { "accept-language": "en" },
			request_id: "ray123",
		});
		const policy = apiCalls().find((c) => c.url.endsWith("/policy"))!;
		expect(policy.method).toBe("GET");
		expect(policy.headers.get("authorization")).toBe("Bearer test-key");
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-status")).toBe("ok");
		expect(h.get("x-ipscanner-traffic-class")).toBe("human");
		expect(h.get("x-ipscanner-site")).toBe(site);
		expect(h.get("x-ipscanner-class")).toBe("human");
		expect(h.get("x-ipscanner-action")).toBe("allow");
		expect(h.get("x-ipscanner-confidence")).toBe("0.92");
		expect(h.get("x-ipscanner-network-class")).toBe("residential_clean");
		expect(h.get("x-ipscanner-anonymized")).toBe("false");
		expect(h.get("x-ipscanner-risk")).toBe("3");
		expect(h.get("x-ipscanner-country")).toBe("DE");
	});

	it("caches the verdict, not the decision", async () => {
		const ip = nextIp();
		edgeReply = () => json(edgeVerdict("ai_agent"));
		expect((await send("/", { ip, vars: vars() })).status).toBe(200);
		calls = [];
		expect((await send("/two", { ip, vars: vars() })).status).toBe(200);
		expect(paths()).toEqual([]);
		policyReply = (s) => json(sitePolicy(s, "enforce", { ai_agent: "block" }));
		advance(31_000);
		calls = [];
		expect((await send("/three", { ip, vars: vars() })).status).toBe(403);
		expect(edgeCalls()).toHaveLength(0);
		expect(policyCalls()).toHaveLength(1);
	});

	it("reuses the policy from the isolate memo", async () => {
		await send("/", { ip: nextIp(), vars: vars() });
		await caches.default.delete(
			new Request(`https://ipscanner-cache.invalid/policy/${site}`),
		);
		calls = [];
		await send("/", { ip: nextIp(), vars: vars() });
		expect(paths()).toEqual(["/v1/edge/check"]);
	});

	it("reuses the policy from the Cache API", async () => {
		policyReply = (s) => json(sitePolicy(s, "enforce", { ai_agent: "block" }));
		edgeReply = () => json(edgeVerdict("ai_agent"));
		await send("/", { ip: nextIp(), vars: vars() });
		clearPolicyMemo();
		calls = [];
		const res = await send("/", { ip: nextIp(), vars: vars() });
		expect(paths()).toEqual(["/v1/edge/check"]);
		expect(res.status).toBe(403);
	});

	it("fetches the policy again after POLICY_TTL", async () => {
		await send("/", { ip: nextIp(), vars: vars({ POLICY_TTL: "5" }) });
		advance(4_000);
		calls = [];
		await send("/", { ip: nextIp(), vars: vars({ POLICY_TTL: "5" }) });
		expect(policyCalls()).toHaveLength(0);
		advance(2_000);
		calls = [];
		await send("/", { ip: nextIp(), vars: vars({ POLICY_TTL: "5" }) });
		expect(policyCalls()).toHaveLength(1);
	});

	it("defaults POLICY_TTL to 30 seconds", async () => {
		await send("/", { ip: nextIp(), vars: vars() });
		advance(29_000);
		calls = [];
		await send("/", { ip: nextIp(), vars: vars() });
		expect(policyCalls()).toHaveLength(0);
		advance(2_000);
		calls = [];
		await send("/", { ip: nextIp(), vars: vars() });
		expect(policyCalls()).toHaveLength(1);
	});

	it("keeps the last good policy when a fetch fails", async () => {
		policyReply = (s) => json(sitePolicy(s, "enforce", { ai_agent: "block" }));
		edgeReply = () => json(edgeVerdict("ai_agent"));
		await send("/", { ip: nextIp(), vars: vars() });
		advance(60_000);
		policyReply = () => json({ error: "server_error" }, 500);
		calls = [];
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(403);
		expect(policyCalls()).toHaveLength(1);
		clearPolicyMemo();
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(403);
	});

	it("keeps the last good policy when a fetch times out", async () => {
		policyReply = (s) => json(sitePolicy(s, "enforce", { ai_agent: "block" }));
		edgeReply = () => json(edgeVerdict("ai_agent"));
		await send("/", { ip: nextIp(), vars: vars() });
		advance(60_000);
		vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
			const req = new Request(input, init);
			if (req.url.endsWith("/policy")) return hang(init?.signal);
			if (req.url.endsWith("/v1/edge/check")) return json(edgeVerdict("ai_agent"));
			return new Response("origin ok");
		});
		const res = await send("/", {
			ip: nextIp(),
			vars: vars({ TIMEOUT_MS: "20" }),
		});
		expect(res.status).toBe(403);
	});

	it("waits before retrying a failed policy fetch", async () => {
		policyReply = () => json({ error: "server_error" }, 500);
		await send("/", { ip: nextIp(), vars: vars() });
		advance(4_000);
		calls = [];
		await send("/", { ip: nextIp(), vars: vars() });
		expect(policyCalls()).toHaveLength(0);
		advance(2_000);
		policyReply = (s) => json(sitePolicy(s, "enforce", { human: "block" }));
		calls = [];
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(403);
		expect(policyCalls()).toHaveLength(1);
	});

	it("drops a stale policy older than 24 hours", async () => {
		policyReply = (s) => json(sitePolicy(s, "enforce", { ai_agent: "block" }));
		edgeReply = () => json(edgeVerdict("ai_agent"));
		await send("/", { ip: nextIp(), vars: vars() });
		advance(25 * 3600_000);
		policyReply = () => json({ error: "server_error" }, 500);
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(200);
	});

	it("passes traffic when no policy is available", async () => {
		policyReply = () => json({ error: "server_error" }, 500);
		edgeReply = () => json(edgeVerdict("malicious_automation"));
		const res = await send("/", { ip: nextIp(), vars: vars() });
		expect(res.status).toBe(200);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-status")).toBe("ok");
		expect(h.get("x-ipscanner-traffic-class")).toBe("malicious_automation");
	});

	it("passes traffic when the policy times out and none is cached", async () => {
		edgeReply = () => json(edgeVerdict("malicious_automation"));
		vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
			const req = new Request(input, init);
			calls.push({
				url: req.url,
				method: req.method,
				headers: req.headers,
				body: "",
			});
			if (req.url.endsWith("/policy")) return hang(init?.signal);
			if (req.url.endsWith("/v1/edge/check"))
				return json(edgeVerdict("malicious_automation"));
			return new Response("origin ok");
		});
		const res = await send("/", {
			ip: nextIp(),
			vars: vars({ TIMEOUT_MS: "20" }),
		});
		expect(res.status).toBe(200);
		expect(originCall()!.headers.get("x-ipscanner-status")).toBe("ok");
	});

	it("passes traffic for an unknown site", async () => {
		policyReply = () =>
			json({ error: "unknown_site", message: "Unknown site" }, 404);
		edgeReply = () =>
			json({ ...edgeVerdict("malicious_automation"), site: null });
		const res = await send("/", { ip: nextIp(), vars: vars() });
		expect(res.status).toBe(200);
		calls = [];
		await send("/", { ip: nextIp(), vars: vars() });
		expect(policyCalls()).toHaveLength(0);
	});

	it("never blocks in monitor mode", async () => {
		policyReply = (s) =>
			json(
				sitePolicy(s, "monitor", {
					malicious_automation: "block",
					ai_agent: "flag",
				}),
			);
		edgeReply = () =>
			json({
				...edgeVerdict("malicious_automation"),
				agent: { ...human, class: "malicious_automation", action: "block" },
			});
		const res = await send("/", { ip: nextIp(), vars: vars() });
		expect(res.status).toBe(200);
		expect(originCall()!.headers.get("x-ipscanner-action")).toBe("block");
		edgeReply = () => json(edgeVerdict("ai_agent"));
		calls = [];
		await send("/", { ip: nextIp(), vars: vars() });
		expect(originCall()!.headers.get("x-ipscanner-action")).toBe("flag");
		edgeReply = () =>
			json({ ...edgeVerdict("ai_agent"), agent: { ...human, class: "ai_agent" } });
		calls = [];
		await send("/", { ip: nextIp(), vars: vars() });
		expect(originCall()!.headers.get("x-ipscanner-action")).toBe("allow");
	});

	it("blocks in enforce mode with a 403 page", async () => {
		policyReply = (s) =>
			json(sitePolicy(s, "enforce", { malicious_automation: "block" }));
		edgeReply = () => json(edgeVerdict("malicious_automation"));
		const res = await send("/", {
			ip: nextIp(),
			vars: vars(),
			init: { headers: { "CF-Ray": "ray403" } },
		});
		expect(res.status).toBe(403);
		const body = await res.text();
		expect(body).toContain("Blocked by IPScanner edge guard");
		expect(body).toContain("ray403");
		expect(originCall()).toBeUndefined();
	});

	it("never blocks when the api answers monitor", async () => {
		policyReply = (s) =>
			json(
				sitePolicy(s, "enforce", { malicious_automation: "block", vpn: "flag" }),
			);
		edgeReply = () =>
			json({ ...edgeVerdict("malicious_automation"), mode: "monitor" });
		const res = await send("/", { ip: nextIp(), vars: vars() });
		expect(res.status).toBe(200);
		expect(originCall()).toBeDefined();
		expect(lastLog()).toMatchObject({ decision: "would_block", mode: "monitor" });
		edgeReply = () => json({ ...edgeVerdict("vpn", "human"), mode: "monitor" });
		calls = [];
		await send("/", { ip: nextIp(), vars: vars() });
		expect(lastLog().decision).toBe("would_flag");
	});

	it("blocks when the api answers enforce", async () => {
		policyReply = (s) =>
			json(sitePolicy(s, "enforce", { malicious_automation: "block" }));
		edgeReply = () =>
			json({ ...edgeVerdict("malicious_automation"), mode: "enforce" });
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(403);
		expect(lastLog()).toMatchObject({ decision: "block", mode: "enforce" });
	});

	it("does not block a monitor policy when the api answers enforce", async () => {
		policyReply = (s) =>
			json(sitePolicy(s, "monitor", { malicious_automation: "block" }));
		edgeReply = () =>
			json({ ...edgeVerdict("malicious_automation"), mode: "enforce" });
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(200);
	});

	it("keeps the mode a cached verdict was answered with", async () => {
		const ip = nextIp();
		policyReply = (s) =>
			json(sitePolicy(s, "enforce", { malicious_automation: "block" }));
		edgeReply = () =>
			json({ ...edgeVerdict("malicious_automation"), mode: "monitor" });
		expect((await send("/", { ip, vars: vars() })).status).toBe(200);
		edgeReply = () =>
			json({ ...edgeVerdict("malicious_automation"), mode: "enforce" });
		calls = [];
		expect((await send("/", { ip, vars: vars() })).status).toBe(200);
		expect(edgeCalls()).toHaveLength(0);
	});

	it("flags in enforce mode", async () => {
		policyReply = (s) => json(sitePolicy(s, "enforce", { vpn: "flag" }));
		edgeReply = () =>
			json({
				...edgeHuman,
				class: "vpn",
				network: { ...edgeHuman.network, networkClass: "vpn", anonymized: true },
			});
		const res = await send("/", { ip: nextIp(), vars: vars() });
		expect(res.status).toBe(200);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-action")).toBe("flag");
		expect(h.get("x-ipscanner-class")).toBe("human");
		expect(h.get("x-ipscanner-traffic-class")).toBe("vpn");
		expect(h.get("x-ipscanner-network-class")).toBe("vpn");
		expect(h.get("x-ipscanner-anonymized")).toBe("true");
	});

	it("allows classes missing from the policy", async () => {
		policyReply = (s) =>
			json(sitePolicy(s, "enforce", { malicious_automation: "block" }));
		edgeReply = () => json(edgeVerdict("hosting", "human"));
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(200);
	});

	it("always passes verified bots", async () => {
		policyReply = (s) =>
			json(
				sitePolicy(s, "enforce", {
					verified_bot: "block",
					known_bot: "block",
					hosting: "block",
				}),
			);
		edgeReply = () =>
			json({
				...edgeHuman,
				class: "verified_bot",
				agent: {
					class: "known_bot",
					confidence: 0.99,
					action: "block",
					signals: { allowlist_verified: true, allowlist_type: "search" },
				},
			});
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(200);
		edgeReply = () =>
			json({
				...edgeHuman,
				class: "hosting",
				agent: {
					class: "known_bot",
					confidence: 0.99,
					action: "allow",
					signals: { allowlist_verified: true },
				},
			});
		calls = [];
		expect((await send("/", { ip: nextIp(), vars: vars() })).status).toBe(200);
		expect(originCall()!.headers.get("x-ipscanner-action")).toBe("allow");
	});

	it("ignores the env var policy", async () => {
		policyReply = (s) => json(sitePolicy(s, "monitor", {}));
		edgeReply = () =>
			json({
				...edgeVerdict("malicious_automation"),
				agent: { ...human, class: "malicious_automation", action: "block" },
			});
		const res = await send("/", {
			ip: nextIp(),
			vars: vars({ MODE: "enforce", BLOCK_ANONYMIZED: "true" }),
		});
		expect(res.status).toBe(200);
		calls = [];
		await send("/", {
			ip: nextIp(),
			vars: vars({ CHECK_AGENT: "false", CHECK_IP: "false" }),
		});
		expect(paths()).toEqual(["/v1/edge/check"]);
	});

	it("fails open when the edge check fails", async () => {
		policyReply = (s) =>
			json(sitePolicy(s, "enforce", { malicious_automation: "block" }));
		edgeReply = () => json({ error: "server_error" }, 500);
		const res = await send("/", { ip: nextIp(), vars: vars() });
		expect(res.status).toBe(200);
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-status")).toBe("error");
		expect(h.get("x-ipscanner-traffic-class")).toBeNull();
		expect(h.get("x-ipscanner-site")).toBeNull();
	});

	it("fails open within TIMEOUT_MS when the API hangs", async () => {
		vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
			const req = new Request(input, init);
			if (req.url.startsWith(API)) return hang(init?.signal);
			return new Response("origin ok");
		});
		const res = await send("/", {
			ip: nextIp(),
			vars: vars({ TIMEOUT_MS: "20" }),
		});
		expect(res.status).toBe(200);
		expect(await res.text()).toBe("origin ok");
	});

	it("strips spoofed site headers", async () => {
		await send("/", {
			ip: nextIp(),
			vars: vars(),
			init: {
				headers: {
					"X-IPScanner-Site": "site_evil",
					"X-IPScanner-Traffic-Class": "verified_bot",
				},
			},
		});
		const h = originCall()!.headers;
		expect(h.get("x-ipscanner-site")).toBe(site);
		expect(h.get("x-ipscanner-traffic-class")).toBe("human");
	});

	it("skips static assets without calling the API", async () => {
		await send("/app.js", { ip: nextIp(), vars: vars() });
		expect(apiCalls()).toHaveLength(0);
		expect(originCall()!.headers.get("x-ipscanner-status")).toBe("skipped");
	});
});
