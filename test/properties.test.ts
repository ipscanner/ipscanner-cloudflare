import {
	createExecutionContext,
	waitOnExecutionContext,
} from "cloudflare:test";
import { env } from "cloudflare:workers";
import fc from "fast-check";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config";
import worker, { shouldBlock } from "../src/index";
import { clearPolicyMemo } from "../src/ipscanner";

const API = "https://ipscanner.io";
const EDGE = `${API}/v1/edge/check`;
const POLICY = /^https:\/\/ipscanner\.io\/v1\/sites\/[^/]+\/policy$/;
const VERDICT_HEADERS = new Set([
	"x-ipscanner-status",
	"x-ipscanner-class",
	"x-ipscanner-action",
	"x-ipscanner-confidence",
	"x-ipscanner-network-class",
	"x-ipscanner-anonymized",
	"x-ipscanner-risk",
	"x-ipscanner-country",
	"x-ipscanner-traffic-class",
	"x-ipscanner-site",
]);

interface Call {
	url: string;
	headers: Headers;
	body: string;
}

let calls: Call[];
let edgeReply: () => unknown;
let policyReply: () => unknown;
let run = 0;

function edge(tag: string) {
	return {
		class: "human",
		agent: {
			class: tag,
			confidence: 0.9,
			action: "allow",
			signals: { network_origin: "residential_clean", anonymized: false },
		},
		network: {
			networkClass: "residential_clean",
			anonymized: false,
			country: tag,
		},
	};
}

beforeEach(() => {
	calls = [];
	edgeReply = () => edge("human");
	policyReply = () => ({ mode: "monitor", policy: {}, version: 1 });
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const req = new Request(input, init);
		calls.push({ url: req.url, headers: req.headers, body: await req.text() });
		if (req.url === EDGE) return Response.json(edgeReply());
		if (POLICY.test(req.url)) return Response.json(policyReply());
		return new Response("origin ok");
	});
	vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
	vi.restoreAllMocks();
});

async function send(
	request: Request,
	vars: Partial<Env> = {},
): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(
		request as Request<unknown, IncomingRequestCfProperties>,
		{ ...env, ...vars },
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return res;
}

function visitor(
	ip: string | null,
	ua: string,
	extra: [string, string][] = [],
	url = "https://example.com/",
): Request {
	const headers = new Headers(extra);
	if (ip !== null) headers.set("CF-Connecting-IP", ip);
	headers.set("User-Agent", ua);
	return new Request(url, { headers });
}

function edgeCalls(): Call[] {
	return calls.filter((c) => c.url === EDGE);
}

function forwarded(): Call | undefined {
	return calls.filter((c) => c.url !== EDGE && !POLICY.test(c.url)).at(-1);
}

function verdictHeaders(headers: Headers): [string, string][] {
	return [...headers].filter(([k]) => k.startsWith("x-ipscanner-"));
}

function at(value: unknown, ...path: string[]): unknown {
	let v = value;
	for (const key of path)
		v = v == null ? undefined : (v as Record<string, unknown>)[key];
	return v;
}

// What the worker sees after the JSON round trip.
function wire(value: unknown): unknown {
	return JSON.parse(JSON.stringify(value));
}

const ip = fc.oneof(fc.ipV4(), fc.ipV6());
const headerValue = fc.string({ unit: "grapheme-ascii", maxLength: 40 });
const anyJson = fc.jsonValue({ maxDepth: 2 });
const text = fc.oneof(
	fc.constantFrom(
		"human",
		"known_bot",
		"verified_bot",
		"ai_agent",
		"malicious_automation",
		"allow",
		"flag",
		"block",
		"monitor",
		"enforce",
		"vpn",
		"tor",
		"residential_proxy",
		"hosting",
		"__proto__",
		"constructor",
	),
	fc.string({ unit: "binary-ascii", maxLength: 12 }),
	fc.string({ unit: "binary", maxLength: 12 }),
);
const field = fc.oneof(text, anyJson);
const agent = fc.record(
	{
		class: field,
		action: field,
		confidence: fc.oneof(fc.double(), field),
		signals: fc.oneof(
			fc.record(
				{
					allowlist_verified: fc.oneof(fc.boolean(), field),
					network_origin: field,
					anonymized: fc.oneof(fc.boolean(), field),
				},
				{ requiredKeys: [] },
			),
			anyJson,
		),
	},
	{ requiredKeys: [] },
);
const network = fc.record(
	{
		networkClass: field,
		anonymized: fc.oneof(fc.boolean(), field),
		riskScore: fc.oneof(fc.integer(), field),
		country: field,
	},
	{ requiredKeys: [] },
);
const verdict = fc.oneof(
	{
		weight: 4,
		arbitrary: fc.record(
			{
				class: field,
				mode: field,
				agent: fc.oneof(agent, anyJson),
				network: fc.oneof(network, anyJson),
			},
			{ requiredKeys: [] },
		),
	},
	{ weight: 1, arbitrary: anyJson },
);
const policy = fc.oneof(
	{
		weight: 4,
		arbitrary: fc.record(
			{
				mode: fc.oneof(fc.constantFrom("monitor", "enforce"), field),
				policy: fc.oneof(
					fc.dictionary(
						text,
						fc.oneof(fc.constantFrom("allow", "flag", "block"), field),
					),
					anyJson,
				),
				version: fc.oneof(fc.nat(), field),
			},
			{ requiredKeys: [] },
		),
	},
	{ weight: 1, arbitrary: anyJson },
);

describe("config parsing", () => {
	const setting = fc.oneof(
		fc.string({ unit: "binary" }),
		fc.integer().map(String),
		fc.double().map(String),
		fc.constantFrom("", " ", "true", " TRUE ", "enforce", "0", "-1", "1e3"),
	);

	it("never throws and always yields usable settings", () => {
		fc.assert(
			fc.property(
				fc.record(
					{
						IPSCANNER_API_KEY: setting,
						IPSCANNER_API_URL: setting,
						ORIGIN_URL: setting,
						MODE: setting,
						CHECK_AGENT: setting,
						CHECK_IP: setting,
						BLOCK_CLASSES: setting,
						BLOCK_ANONYMIZED: setting,
						TIMEOUT_MS: setting,
						AGENT_TTL: setting,
						IP_TTL: setting,
						SKIP_PATHS: setting,
						SITE_ID: setting,
						POLICY_TTL: setting,
					},
					{ requiredKeys: [] },
				),
				(vars) => {
					const cfg = loadConfig(vars);
					for (const n of [
						cfg.timeoutMs,
						cfg.agentTtl,
						cfg.ipTtl,
						cfg.policyTtl,
					]) {
						expect(Number.isInteger(n) && n > 0).toBe(true);
					}
					expect(cfg.apiUrl.endsWith("/")).toBe(false);
					expect(cfg.enforce).toBe(
						(vars.MODE ?? "").trim().toLowerCase() === "enforce",
					);
					const classes = (vars.BLOCK_CLASSES ?? "malicious_automation")
						.split(",")
						.map((s) => s.trim())
						.filter(Boolean);
					expect(cfg.blockClasses).toEqual(classes);
					let valid: RegExp | null = null;
					try {
						valid = vars.SKIP_PATHS ? new RegExp(vars.SKIP_PATHS, "i") : null;
					} catch {}
					expect(cfg.skipPaths?.source).toBe(valid?.source);
				},
			),
			{ numRuns: 300 },
		);
	});
});

describe("block decisions", () => {
	it("never blocks an allowlisted visitor or anonymity alone when BLOCK_ANONYMIZED is off", () => {
		fc.assert(
			fc.property(
				fc.array(text),
				fc.boolean(),
				agent,
				network,
				(blockClasses, blockAnonymized, a, n) => {
					const cfg = { ...loadConfig({}), blockClasses, blockAnonymized };
					const parsedAgent = wire(a) as Parameters<typeof shouldBlock>[1];
					const parsedNetwork = wire(n) as Parameters<typeof shouldBlock>[2];
					const block = shouldBlock(cfg, parsedAgent, parsedNetwork);
					if (at(parsedAgent, "signals", "allowlist_verified") === true)
						expect(block).toBe(false);
					const flagged =
						parsedAgent?.action === "block" ||
						blockClasses.includes(parsedAgent?.class as string);
					if (!blockAnonymized && !flagged) expect(block).toBe(false);
				},
			),
			{ numRuns: 500 },
		);
	});
});

describe("client IP", () => {
	const spoofable = fc.array(
		fc.tuple(
			fc.constantFrom(
				"X-Forwarded-For",
				"X-Real-IP",
				"True-Client-IP",
				"Forwarded",
				"X-Client-IP",
				"CF-Connecting-IPv6",
			),
			fc.oneof(ip, headerValue),
		),
		{ maxLength: 6 },
	);

	it("checks CF-Connecting-IP whatever other headers claim", async () => {
		await fc.assert(
			fc.asyncProperty(ip, spoofable, async (cfIp, spoofed) => {
				calls = [];
				await send(visitor(cfIp, `prop/${++run}`, spoofed));
				const checks = edgeCalls();
				expect(checks).toHaveLength(1);
				expect(JSON.parse(checks[0].body).ip).toBe(cfIp);
			}),
		);
	});

	it("never checks a visitor without CF-Connecting-IP", async () => {
		await fc.assert(
			fc.asyncProperty(spoofable, async (spoofed) => {
				calls = [];
				await send(visitor(null, `prop/${++run}`, spoofed));
				expect(edgeCalls()).toHaveLength(0);
				expect(forwarded()!.headers.get("x-ipscanner-status")).toBe(
					"skipped",
				);
			}),
		);
	});
});

describe("spoofed verdict headers", () => {
	const spoofed = fc.array(
		fc.tuple(
			fc.mixedCase(fc.stringMatching(/^x-ipscanner-[a-z0-9-]{0,16}$/)),
			headerValue,
		),
		{ minLength: 1, maxLength: 8 },
	);

	it("never reach the origin", async () => {
		calls = [];
		await send(visitor("198.51.100.1", "prop/baseline"));
		const baseline = verdictHeaders(forwarded()!.headers);
		await fc.assert(
			fc.asyncProperty(spoofed, fc.boolean(), async (extra, withKey) => {
				calls = [];
				await send(
					visitor("198.51.100.1", `prop/${++run}`, extra),
					withKey ? {} : { IPSCANNER_API_KEY: "" },
				);
				expect(verdictHeaders(forwarded()!.headers)).toEqual(
					withKey ? baseline : [["x-ipscanner-status", "skipped"]],
				);
			}),
		);
	});
});

describe("origin routing", () => {
	const piece = fc.oneof(
		fc.constantFrom(
			"/",
			"//",
			"\\",
			".",
			"..",
			"%2e",
			"%2F",
			"@",
			":",
			"?",
			"#",
			"evil.example",
		),
		fc.string({ maxLength: 6 }),
	);
	const path = fc.array(piece, { maxLength: 8 }).map((p) => `/${p.join("")}`);
	const origin = fc.constantFrom(
		"https://backend.example.net",
		"https://backend.example.net/",
		"https://backend.example.net/base/",
		"http://127.0.0.1:8080",
	);

	it("keeps the ORIGIN_URL host and the request path and query", async () => {
		await fc.assert(
			fc.asyncProperty(path, origin, async (p, originUrl) => {
				calls = [];
				const request = visitor(
					"203.0.113.70",
					"prop/routing",
					[],
					`https://example.com${p}`,
				);
				const incoming = new URL(request.url);
				await send(request, { ORIGIN_URL: originUrl });
				const target = new URL(forwarded()!.url);
				expect(target.origin).toBe(new URL(originUrl).origin);
				expect(target.pathname).toBe(incoming.pathname);
				expect(target.search).toBe(incoming.search);
			}),
		);
	});
});

describe("verdict decoding", () => {
	it("fails open on any edge answer and blocks only when allowed to", async () => {
		await fc.assert(
			fc.asyncProperty(
				verdict,
				fc.constantFrom("monitor", "enforce"),
				fc.boolean(),
				async (body, mode, blockAnonymized) => {
					calls = [];
					edgeReply = () => body;
					const res = await send(visitor("192.0.2.1", `prop/${++run}`), {
						MODE: mode,
						BLOCK_ANONYMIZED: String(blockAnonymized),
					});
					const v = wire(body);
					if (res.status === 403) {
						expect(mode).toBe("enforce");
						expect(at(v, "mode")).not.toBe("monitor");
						expect(at(v, "agent", "signals", "allowlist_verified")).not.toBe(
							true,
						);
						return;
					}
					expect(res.status).toBe(200);
					for (const [k] of verdictHeaders(forwarded()!.headers))
						expect(VERDICT_HEADERS.has(k)).toBe(true);
				},
			),
		);
	});

	it("blocks a site visitor only as its enforced policy says", async () => {
		await fc.assert(
			fc.asyncProperty(verdict, policy, async (body, sitePolicy) => {
				calls = [];
				clearPolicyMemo();
				edgeReply = () => body;
				policyReply = () => sitePolicy;
				const res = await send(visitor("192.0.2.2", `prop/${++run}`), {
					SITE_ID: `site_prop_${run}`,
				});
				const v = wire(body);
				const p = wire(sitePolicy);
				if (res.status === 403) {
					const rules = at(p, "policy") as Record<string, unknown>;
					const trafficClass = at(v, "class") as string;
					expect(at(p, "mode")).toBe("enforce");
					expect(at(v, "mode")).not.toBe("monitor");
					expect(trafficClass).not.toBe("verified_bot");
					expect(at(v, "agent", "signals", "allowlist_verified")).not.toBe(
						true,
					);
					expect(typeof rules === "object" && rules !== null).toBe(true);
					expect(Object.hasOwn(rules, trafficClass)).toBe(true);
					expect(rules[trafficClass]).toBe("block");
					return;
				}
				expect(res.status).toBe(200);
				for (const [k] of verdictHeaders(forwarded()!.headers))
					expect(VERDICT_HEADERS.has(k)).toBe(true);
			}),
		);
	});
});

describe("verdict cache", () => {
	// A fresh IPv6 prefix per run keeps runs apart; small host parts make repeat visitors likely.
	const host = fc.integer({ min: 1, max: 3 });
	const ua = fc.oneof(fc.constantFrom("a", "a|b", "b"), headerValue);

	it("shares a verdict only between requests with the same cache key", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.tuple(host, ua),
				fc.tuple(host, ua),
				fc.boolean(),
				async ([hostA, uaA], [hostB, uaB], checkAgent) => {
					calls = [];
					const prefix = `2001:db8:${(++run).toString(16)}::`;
					const vars = { CHECK_AGENT: String(checkAgent) };
					let answer = 0;
					edgeReply = () => edge(`v${++answer}`);
					await send(visitor(`${prefix}${hostA}`, uaA), vars);
					await send(visitor(`${prefix}${hostB}`, uaB), vars);
					const sameKey =
						hostA === hostB && (!checkAgent || uaA.trim() === uaB.trim());
					expect(edgeCalls()).toHaveLength(sameKey ? 1 : 2);
					expect(forwarded()!.headers.get("x-ipscanner-country")).toBe(
						sameKey ? "v1" : "v2",
					);
				},
			),
		);
	});
});
