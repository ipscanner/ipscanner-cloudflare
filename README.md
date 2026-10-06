# IPScanner Edge Guard

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ipscanner/ipscanner-cloudflare)

<!-- dash-content-start -->

A Cloudflare Worker that sits in front of your site and checks every visitor with [IPScanner](https://ipscanner.io) Agentscan and IP Detection before the request reaches your origin.

- **Monitor mode** (default) adds `X-IPScanner-*` verdict headers to the request your origin receives, so your app can log, rate limit or challenge as it sees fit.
- **Enforce mode** also returns a 403 to visitors that Agentscan marks as `block`, that fall into a blocked class, or (optionally) that come through a VPN, proxy or Tor.
- Verified search engines and AI crawlers on the Agentscan allowlist are never blocked.
- Both checks run in parallel, are cached with the Cache API, and fail open: if the API is slow or unreachable, the request goes through unchanged.
- Incoming `X-IPScanner-*` headers are stripped, so clients cannot spoof a verdict.
- One JSON log line per checked request, ready for Workers Logs.

The Worker uses plain `fetch` and the Cache API. It has no runtime dependencies.

<!-- dash-content-end -->

## Getting started

1. Create an API key at [ipscanner.io](https://ipscanner.io). Keys look like `pk_live_` followed by 56 hex characters (test keys start with `pk_test_`).
2. Deploy with the button above, or clone and deploy:

   ```sh
   npm install
   npx wrangler deploy
   ```

3. Store the key as a secret:

   ```sh
   npx wrangler secret put IPSCANNER_API_KEY
   ```

Without a key the Worker passes every request through unchecked and logs a warning once.

## Put it in front of your site

**Route (zone on Cloudflare).** Add a route to `wrangler.jsonc` and leave `ORIGIN_URL` empty. Requests that pass the guard continue to the origin in your DNS records.

```jsonc
"routes": [{ "pattern": "example.com/*", "zone_name": "example.com" }]
```

**Custom domain or workers.dev.** The Worker is the origin here, so set `ORIGIN_URL` to your backend (for example `https://backend.example.com`). Path and query string are kept.

If neither is configured, the `workers.dev` URL shows a setup page listing the headers your origin would receive. Use it to check the key and your own verdict.

## Configuration

All values are strings in the `vars` block of `wrangler.jsonc`.

| Variable            | Default                | Description                                                                                                           |
| ------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `IPSCANNER_API_KEY` |                        | Secret. Your API key.                                                                                                 |
| `MODE`              | `monitor`              | `monitor` annotates only. `enforce` also blocks.                                                                      |
| `CHECK_AGENT`       | `true`                 | Run Agentscan (`POST /v1/agentscan/check`).                                                                           |
| `CHECK_IP`          | `true`                 | Run IP Detection (`POST /v1/ip/lookup`).                                                                              |
| `BLOCK_CLASSES`     | `malicious_automation` | Comma separated Agentscan classes to block in enforce mode: `human`, `known_bot`, `ai_agent`, `malicious_automation`. |
| `BLOCK_ANONYMIZED`  | `false`                | In enforce mode, also block VPN, proxy and Tor traffic.                                                               |
| `TIMEOUT_MS`        | `1500`                 | Timeout per API call. On timeout the request is forwarded.                                                            |
| `AGENT_TTL`         | `600`                  | Seconds to cache an Agentscan verdict per IP and User-Agent.                                                          |
| `IP_TTL`            | `3600`                 | Seconds to cache an IP lookup per IP.                                                                                 |
| `SKIP_PATHS`        | static assets          | Case insensitive regex on the path. Matching requests are not checked. Empty checks everything.                       |
| `ORIGIN_URL`        | empty                  | Backend to forward to. Leave empty on a route.                                                                        |
| `IPSCANNER_API_URL` | `https://ipscanner.io` | API base URL.                                                                                                         |

`OPTIONS` requests are never checked. All other methods are.

## Headers

Added to the request forwarded to your origin:

| Header                      | Source       | Example                                                  |
| --------------------------- | ------------ | -------------------------------------------------------- |
| `X-IPScanner-Status`        | Guard        | `ok`, `error`, `timeout` or `skipped`                    |
| `X-IPScanner-Class`         | Agentscan    | `human`, `known_bot`, `ai_agent`, `malicious_automation` |
| `X-IPScanner-Action`        | Agentscan    | `allow`, `flag`, `block`                                 |
| `X-IPScanner-Confidence`    | Agentscan    | `0.92`                                                   |
| `X-IPScanner-Network-Class` | IP Detection | `residential_clean`, `hosting`, `vpn`, `tor`, ...        |
| `X-IPScanner-Anonymized`    | Both         | `true` or `false`                                        |
| `X-IPScanner-Risk`          | IP Detection | `0` to `100`                                             |
| `X-IPScanner-Country`       | IP Detection | `DE`                                                     |

When a check fails or is skipped, only `X-IPScanner-Status` is set.

## Enforce rules

In `enforce` mode a visitor gets a 403 page with the request ID when:

- Agentscan returns `action: block`, or
- the class is listed in `BLOCK_CLASSES`, or
- `BLOCK_ANONYMIZED` is `true` and either check reports the IP as anonymized.

A visitor whose Agentscan signals include `allowlist_verified: true` is always allowed.

## Logs

Each checked request writes one JSON line with `ip`, `path`, `class`, `action`, `networkClass`, `decision` (`allow`, `block`, or `would_block` in monitor mode) and cache hits. Observability is enabled in `wrangler.jsonc`, so these are searchable in Workers Logs.

## Cost

Each uncached visitor uses 1 request unit per enabled check, so 2 units with both checks on. Repeat visits within `AGENT_TTL` and `IP_TTL` are served from the cache. The Cache API is local to each Cloudflare data center, so a visitor seen in one location is checked again in another. Raise the TTLs, narrow the route, or turn off one check to reduce usage.

## Develop locally

```sh
cp .dev.vars.example .dev.vars
npm run dev
npm test
npm run test:e2e
```

API reference: [ipscanner.io/api-documentation](https://ipscanner.io/api-documentation).

## Licence

MIT
