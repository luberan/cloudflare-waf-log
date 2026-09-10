# Cloudflare WAF Dashboard

A Cloudflare Worker that visualises WAF / Security events **and HTTP traffic analytics** across **multiple Cloudflare accounts** (your own + customer accounts).
Fully functional on the **Free tier**. WAF and HTTP range options are derived from each zone's real GraphQL dataset limits.

The UI has two tabs that share the account / zone / time-range selectors:

- **🛡 WAF** — firewall / security event rows. Cloudflare may adaptively sample this raw event log, so the UI labels these counts as sampled rows rather than estimated totals.
- **📊 HTTP Traffic** — zone-wide HTTP analytics: requests, data transfer, visits, status codes, cache ratio, top countries / hostnames / paths, content types, HTTP versions, and edge/origin performance (TTFB & origin response time). Numbers are scoped to `requestSource: eyeball` so they line up with Cloudflare's own HTTP Traffic dashboard. Three datasets back it automatically by how wide the range is, the same way the Cloudflare dashboard switches resolution: short ranges (~24 h) use **`httpRequestsAdaptiveGroups`** (fine-grained, every breakdown; works on the Free plan, no Pro+); mid ranges (~3 d) switch to the hourly **`httpRequests1hGroups`** roll-up; long ranges (up to ~30 d) use the daily **`httpRequests1dGroups`** roll-up (retained longest). Daily queries use the requested number of calendar-day buckets. At roll-up ranges the visitor KPI changes to one globally aggregated **Unique IPs** value, while per-path / per-hostname / performance panels hide because that data only exists in the fine-grained dataset.

## Features

- **Switching between Cloudflare accounts** — each account has its own API token stored as a Worker secret
- **Switching between zones** within the selected account; every zone-scoped API request verifies zone ownership before querying analytics or reading cached data
- Filtering by:
  - **action** (chips: `block`, `managed_challenge`, `jschallenge`, `challenge`, `allow`, `log`, `skip`)
  - **hostname** (e.g. `www.example.com`)
   - **path** (exact values, one per line, so paths containing commas remain representable)
  - **Rule ID** (firewall rule UUID, comma-separated)
  - **country** (ISO2 codes: `US,DE,RU,...`)
  - **ASN** (AS numbers, comma-separated: `13335,15169`)
   - **User-Agent** (exact values, one per line, including values that contain commas)
- Country filters are case-insensitive; ASN filters accept the `AS` prefix and `0` for unknown ASNs. Table and chart selections use the same normalized values as API requests.
- Time range (WAF tab): options up to the zone's `firewallEventsAdaptive` limit (24 h Free/Pro, 3 d Business, up to 30 d Enterprise)
- **KPI cards**: sampled rows / blocked / challenge / allow+log
- **Charts**:
   - Stacked time series (sampled rows per hour, colour-coded by action, including empty hours)
  - Doughnut by action
  - Top 15 countries (horizontal bar)
  - Top 15 hostnames
  - Doughnut by source (`waf`, `firewallrules`, `botManagement`, …)
- **Tables**:
  - Top 30 Rule IDs *(click = filter on Rule ID)*
  - Top 50 paths *(click = filter on Path)*
  - Top 50 ASNs *(click = filter on ASN)*
  - Top 50 user agents *(click = filter on UA)*
  - Latest ~500 events (time, action, IP, ASN, country, host, path, method, rule, ray ID)
- **Clear filters** — single button that clears all chips and inputs
- **CSV export** — downloads the returned sampled event rows for the current filters (up to 10 000 rows, UTF-8 + BOM, opens directly in Excel)

## Architecture

| Part | File | Purpose |
|---|---|---|
| Worker (TypeScript) | [src/index.ts](src/index.ts) | API endpoints — proxy to the Cloudflare GraphQL Analytics API |
| Dashboard markup | [public/index.html](public/index.html) | Vanilla HTML + CSS, no build step |
| Dashboard logic | [public/app.js](public/app.js) | All client-side JS (fetch, charts, faceted filters) |
| Chart.js (vendored) | `public/vendor/chart.umd.min.js` | Self-hosted Chart.js — no CDN, so the CSP can use `script-src 'self'` |
| Configuration | [wrangler.jsonc](wrangler.jsonc) | Worker entrypoint + assets binding + disabling the default domains |

### API endpoints

| Endpoint | Description |
|---|---|
| `GET /api/accounts` | List of configured accounts (only `id` + `label`, never a token) |
| `GET /api/zones?account=<id>` | List of zones for the given account |
| `GET /api/stats?account=<id>&zone=<id>&...filters` | WAF aggregations + latest 500 events (everything in a single request) |
| `GET /api/http-stats?account=<id>&zone=<id>&since=&until=` | HTTP traffic + edge performance aggregations (server-side grouped; `httpRequestsAdaptiveGroups` for short ranges, hourly/daily roll-up for longer ones) |
| `GET /api/http-settings?account=<id>&zone=<id>` | HTTP dataset limits for the zone (retention + max query window) |
| `GET /api/waf-settings?account=<id>&zone=<id>` | WAF event dataset limit used to populate and enforce the WAF time-range dropdown |
| `GET /api/log?account=<id>&zone=<id>&...filters` | Events only (limit controllable via `&limit=`) |
| `GET /api/export.csv?account=<id>&zone=<id>&...filters` | CSV export of raw events (up to 10 000 rows, `Content-Disposition: attachment`) |

### WAF sampling and Worker-side aggregation

The Cloudflare `firewallEventsAdaptiveGroups` dataset (server-side aggregation) **requires the Pro+ plan**. On Free only `firewallEventsAdaptive` is available. It is a raw adaptive dataset, so Cloudflare can sample it before returning at most 10 000 rows. The Worker computes `byAction`, `byCountry`, `byHost`, `byPath`, `byRule`, `bySource`, `byAsn`, `byUserAgent`, and `series` from those returned rows.

The API therefore reports `sampledRows`, `matchedSampledRows`, and `sampling.rowLimitReached`; it never presents row counts as estimated event totals. Sampling can occur even below 10 000 rows. Narrower ranges reduce sampling, but only Logpush/raw Enterprise logs can guarantee every event. If the per-zone Settings lookup is temporarily unavailable, the requested WAF interval is sent unchanged and marked with `range.limitSource: "fallback"`; it is never silently shortened to a guessed limit.

WAF and HTTP responses include `range.effectiveSince` and `range.effectiveUntil`, which anchor the charts to the actual queried interval. Traffic charts include empty time buckets; missing performance measurements remain gaps, not zero-millisecond timings. HTTP selection tolerates up to 60 seconds of retention-boundary drift before choosing a coarser dataset, while still clamping the actual query to the dataset's retention and duration limits.

### Drill-down facets + caching

The filters `country / host / path / rule / asn / ua` are **facet-style multi-select**:
- Clicking an item in a table / bar adds it to the filter, clicking again removes it.
- The active item is highlighted, the others stay visible (greyed out) — classic faceted-search UX.
- The Worker applies these filters in JS, not in the GraphQL query. CF is only asked about `action + source + zone + datetime`.

The outer WAF fetch and HTTP statistics use the Worker Cache API on a best-effort basis (TTL 5 min). Keys include the actual account ID, a SHA-256 fingerprint of the account ID and API token, and the exact normalized time bounds; WAF keys also include action, source and row limit. Raw tokens are never stored in cache keys. Account reassignment or token rotation therefore cannot reuse the previous configuration's data or dataset settings.

Facet toggles and CSV export reuse the current time snapshot. **Load** starts a fresh snapshot. Every zone-scoped request, including a cache hit, still verifies zone ownership through the Cloudflare REST API. Cache read, parsing or write failures fall back to uncached data (`BYPASS`) instead of failing the request. Changing accounts or zones clears old results immediately, including when the new account has no zones or its lookup fails.

**Cloudflare Access limitation:** [Cloudflare currently documents Cache API as unavailable for Workers fronted by Access](https://developers.cloudflare.com/workers/runtime-apis/cache/). This concerns the Worker's five-minute reuse of GraphQL results, not browser caching of HTML/JS or the HTTP dashboard's **Cached** metric (which describes the monitored zone's traffic). The dashboard works without this optimization: a cache miss fetches fresh upstream data, at the cost of latency and more API requests. Keep Access enabled.

A successful `cache.put()` does not guarantee that anything was stored. An API response's `x-cache: HIT` confirms reuse; `MISS` alone does not prove a problem because the request may use a new interval or reach another data center. Confirm production behavior with repeated identical requests within the TTL, rather than assuming a local test proves caching behind Access. The corrected time and credential cache keys still matter wherever Cache API is functional. If token permissions are edited in place, rotate the token or purge cached data when immediate cache invalidation is required.

## Secret configuration

**All sensitive data lives only in Worker secrets.** Nothing sensitive is committed to the repo or to `wrangler.jsonc`.

For **each CF account** create THREE secrets:

| Secret name | Description | Example |
|---|---|---|
| `CFACC_<ID>_LABEL` | Label shown in the UI dropdown | `My account` |
| `CFACC_<ID>_ACCOUNT` | Cloudflare Account ID (32 hex chars) | `00000000000000000000000000000000` |
| `CFACC_<ID>_TOKEN` | Cloudflare API token (read-only, see below) | `cf_xxx...` |

`<ID>` is any short identifier (`PERSONAL`, `ACME`, `NOVA`, …). It appears in the URL as `?account=<id>`. The Worker normalises it to lowercase internally.

**Adding a new account** = create three new secrets. Nothing existing changes, you do not need to know the older tokens.
**Token rotation** = overwrite just `CFACC_<ID>_TOKEN`.
**Removing an account** = delete its three secrets.

### Cloudflare API token — how to create one

> Scope each token to the zones of its intended account. Selecting an account in the dashboard alone does not constrain a user token's permissions. The Worker independently verifies that the requested zone belongs to its configured account.

1. **My Profile → API Tokens → Create Token → Custom token**
2. **Token name**: e.g. `waf-log-personal`
3. **Permission policy** — in the top-left Resources selector pick **All Domains**
   *(NOT "Entire Account" — that scope does not contain zone-level permissions such as Zone:Read and Zone Analytics:Read)*
4. Tick in the categories:
   - **DNS & Zones → Zone : Read**
   - **Analytics & Logs → Analytics : Read**
5. Restrict the token's resource scope to the intended account's zones. Client IP filtering and TTL are optional.
6. **Continue → Create Token** → copy it (shown only once)

## Setup

### Local development

```powershell
npm install

# Create .dev.vars (DO NOT commit — it's in .gitignore).
@'
CFACC_PERSONAL_LABEL=My account
CFACC_PERSONAL_ACCOUNT=00000000000000000000000000000000
CFACC_PERSONAL_TOKEN=cf_xxx
ALLOW_UNAUTHENTICATED_LOCAL_DEV=true
'@ | Out-File -Encoding utf8 .dev.vars

npm run dev
```

Open <http://localhost:8787>.

Run all automated checks without Cloudflare credentials:

```powershell
npm run check
npm run deploy:dry-run
```

### Production — Worker secrets

In the dashboard: **Workers & Pages → your Worker → Settings → Variables and Secrets → Add → Type: Secret**

For each account add three secrets (`CFACC_<ID>_LABEL`, `CFACC_<ID>_ACCOUNT`, `CFACC_<ID>_TOKEN`).
After adding all of them click **Deploy** (once — applies all changes together).

Or via the CLI:
```powershell
"My account" | npx wrangler secret put CFACC_PERSONAL_LABEL
"abc123..."  | npx wrangler secret put CFACC_PERSONAL_ACCOUNT
"cf_xxx..."  | npx wrangler secret put CFACC_PERSONAL_TOKEN
```

### Deploy via GitHub → Cloudflare Workers Builds

1. Push the repo to GitHub
2. **Workers & Pages → Create → Workers → Connect to Git**, choose the repo
3. Build settings:
   - **Build command**: *(leave empty — no build is required)*
   - **Deploy command**: `npx wrangler deploy`
   - **Non-production deploy command**: `npx wrangler versions upload`
   - **Builds for non-production branches**: leave disabled (preview URLs are disabled in the config anyway)
4. After the first deploy add the secrets (see above)
5. Every push to `main` then triggers an auto-deploy

### Custom domain

The `*.workers.dev` URL is disabled ([wrangler.jsonc](wrangler.jsonc) — `workers_dev: false`), so the Worker is only reachable via a custom domain. Setup:

1. **Worker → Settings → Domains & Routes → Add → Custom Domain**
2. Enter the domain, e.g. `waf.example.com` (must be a zone on the same CF account as the worker)
3. CF automatically creates the `CNAME` and issues a TLS cert

### Access protection — Cloudflare Access (Zero Trust)

Without protection the Worker is public and would expose data from all customer accounts. **It MUST sit behind Access:**

1. **Zero Trust dashboard → Access → Applications → Add application → Self-hosted**
2. Application domain: `waf.example.com` (the custom domain from the previous step)
3. Path: leave empty (protects the whole hostname including `/api/*`)
4. **Policy** → Add policy:
   - Action: `Allow`
   - Include: `Emails: you@example.com` (or an IdP group, …)
5. Save & deploy the application

Without a valid Access session, Cloudflare Access redirects the browser to its login page before the request reaches the Worker.

#### Required API JWT verification

The Worker also verifies the Access JWT itself, so a removed or partially configured Access application cannot silently expose the API. Set both variables in production (plain vars, not secrets):

| Variable | Description | Example |
|---|---|---|
| `CF_ACCESS_TEAM_DOMAIN` | Your Zero Trust team domain | `https://yourteam.cloudflareaccess.com` |
| `CF_ACCESS_AUD` | Application Audience (AUD) tag of the Access application | `0a1b2c…` |

These values may be configured as dashboard runtime variables. The committed Wrangler config sets `keep_vars: true`, so Workers Builds preserves dashboard-defined variables instead of deleting them on the next deploy.

Every `/api/*` request must carry a valid Access token (`Cf-Access-Jwt-Assertion` header or `CF_Authorization` cookie); the Worker checks the RS256 signature against your team's public keys plus the audience, issuer, expiry and optional not-before (`nbf`) time. Tokens are rejected at their expiration second and before their not-before time. Missing or partial production configuration returns `503` instead of failing open. Only local `.dev.vars` should set `ALLOW_UNAUTHENTICATED_LOCAL_DEV=true`; the bypass is accepted exclusively for `localhost`/loopback request URLs and cannot disable authentication on a deployed hostname.

The verifier authorizes the Access application audience, not individual Cloudflare accounts. Every identity allowed by the Access policy can read every account configured in this Worker, so use a policy whose members are trusted for all of them.

## Important — disabling the default domains

[wrangler.jsonc](wrangler.jsonc) hard-codes:
- `workers_dev: false` — disables `<worker>.<subdomain>.workers.dev`
- `preview_urls: false` — disables preview URLs from `wrangler versions upload`

Keep both disabled to avoid an alternative entry point without the custom hostname's Access policy. Every reachable hostname needs effective Access protection; API JWT verification remains mandatory regardless of the hostname.

## Dataset and platform limits

- **WAF event retention**: Free/Pro 24 h, Business 3 d, Enterprise up to 30 d. The dropdown queries the exact per-zone limit.
- **Adaptive WAF sampling**: `firewallEventsAdaptive` can be sampled at any row count and returns at most 10 000 rows. The dashboard always labels its derived counts as sampled rows.
- **Worker quotas**: 100 000 req/day, 10 ms CPU
- **GraphQL rate limit**: default 300 GraphQL queries per 5 minutes per Cloudflare user. A cold adaptive HTTP view uses six GraphQL requests plus one REST zone-ownership check. Where Cache API is available, repeated identical intervals can reuse analytics for 5 minutes; ownership is still checked on every request.
- **Zone listing**: follows pagination until the last page instead of silently stopping at 1 000 zones. Cloudflare's platform subrequest limits still apply to very large accounts.
- **`firewallEventsAdaptiveGroups` (server-side aggregation) is Pro+ only** — that is why the Worker aggregates raw events in JS

## Security notes

- Tokens have read-only permissions — even a leaked secret cannot change anything in the CF accounts
- The frontend never receives a token — `GET /api/accounts` returns only `id` + `label`
- The Worker must sit behind Cloudflare Access, and its API also [requires a valid Access JWT](#required-api-jwt-verification)
- All assets are served with a strict per-response `Content-Security-Policy` (`script-src 'self' 'nonce-…'`, `frame-ancestors 'none'`, …) plus `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy`. Application scripts are self-hosted. Cloudflare Bot JavaScript Detections parses the nonce and adds it to its dynamically injected snippet, without enabling general `'unsafe-inline'`
- CSV export escapes formula-trigger characters (`= + - @`) to prevent CSV/Excel formula injection, and the download filename is sanitised
- Upstream REST, GraphQL and Access signing-key requests have a hard timeout covering both response headers and JSON body consumption; a timed-out required request returns `504`
- `.dev.vars` is listed in [.gitignore](.gitignore)

## Possible extensions

- Cron Trigger → store aggregations in D1/R2 for history longer than the plan's WAF retention
- Alerting webhook (Slack/Discord) when the blocked-request threshold is exceeded

## License

[MIT](LICENSE)
