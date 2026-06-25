# Cloudflare WAF Dashboard

A Cloudflare Worker that visualises WAF / Security events **and HTTP traffic analytics** across **multiple Cloudflare accounts** (your own + customer accounts).
Fully functional on the **Free tier** (24 h WAF event retention).

The UI has two tabs that share the account / zone / time-range selectors:

- **🛡 WAF** — firewall / security events (the original dashboard, see below).
- **📊 HTTP Traffic** — zone-wide HTTP analytics: requests, data transfer, visits, status codes, cache ratio, top countries / hostnames / paths, content types, HTTP versions, and edge/origin performance (TTFB & origin response time). Backed by `httpRequestsAdaptiveGroups`, whose **server-side aggregation works on the Free plan** (no Pro+ needed) and is retained well beyond 24 h. The time-range dropdown is built per-zone from the dataset's real limits (retention / max query window) reported by the GraphQL Settings node, so each plan can look as far back as it is allowed to — not an artificial 24 h cap.

## Features

- **Switching between Cloudflare accounts** — each account has its own API token stored as a Worker secret
- **Switching between zones** within the selected account
- Filtering by:
  - **action** (chips: `block`, `managed_challenge`, `jschallenge`, `challenge`, `allow`, `log`, `skip`)
  - **hostname** (e.g. `www.example.com`)
  - **path** (e.g. `/wp-login.php`)
  - **Rule ID** (firewall rule UUID, comma-separated)
  - **country** (ISO2 codes: `US,DE,RU,...`)
  - **ASN** (AS numbers, comma-separated: `13335,15169`)
  - **User-Agent** (exact match)
- Time range (WAF tab): last **1 / 6 / 24 h** (Free tier — Cloudflare does not retain WAF events longer than that)
- **KPI cards**: total / blocked / challenge / allow+log
- **Charts**:
  - Stacked time series (events per hour, colour-coded by action)
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
- **CSV export** — downloads the raw events for the current filters (up to 10 000 rows, UTF-8 + BOM, opens directly in Excel)

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
| `GET /api/http-stats?account=<id>&zone=<id>&since=&until=` | HTTP traffic + edge performance aggregations (`httpRequestsAdaptiveGroups`, server-side grouped) |
| `GET /api/http-settings?account=<id>&zone=<id>` | HTTP dataset limits for the zone (retention + max query window) used to populate the time-range dropdown |
| `GET /api/log?account=<id>&zone=<id>&...filters` | Events only (limit controllable via `&limit=`) |
| `GET /api/export.csv?account=<id>&zone=<id>&...filters` | CSV export of raw events (up to 10 000 rows, `Content-Disposition: attachment`) |

### Note about the Free tier — aggregation runs in the Worker

The Cloudflare `firewallEventsAdaptiveGroups` dataset (server-side aggregation) **requires the Pro+ plan**. On Free only `firewallEventsAdaptive` is available (raw events, 24 h, max 10 000 rows per request). The Worker therefore fetches raw events and computes all statistics (`byAction`, `byCountry`, `byHost`, `byPath`, `byRule`, `bySource`, `byAsn`, `byUserAgent`, `series`) in JS. The response includes `totalSampled` and `truncated` — if a zone exceeds 10 000 events in 24 h, the dashboard will warn you that the statistics are based on a sample.

### Drill-down facets + caching

The filters `country / host / path / rule / asn / ua` are **facet-style multi-select**:
- Clicking an item in a table / bar adds it to the filter, clicking again removes it.
- The active item is highlighted, the others stay visible (greyed out) — classic faceted-search UX.
- The Worker applies these filters in JS, not in the GraphQL query. CF is only asked about `action + source + zone + datetime`.

The result of the outer GraphQL fetch is cached in the Worker Cache API (TTL 5 min, keyed by `acc + zone + 5-min bucket(time) + action + source`). Toggling facets between each other is therefore **instant** (cache HIT) — instead of 500–2000 ms of CF latency you get <50 ms. A `⚡ cache HIT / ☁ cache MISS` indicator with the request latency is shown in the dashboard header.

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

> **First switch into the account** whose data you want to read (top-left switcher in the dashboard). The token is tied to the account it was created in — a token created in a different account will not see foreign zones.

1. **My Profile → API Tokens → Create Token → Custom token**
2. **Token name**: e.g. `waf-log-personal`
3. **Permission policy** — in the top-left Resources selector pick **All Domains**
   *(NOT "Entire Account" — that scope does not contain zone-level permissions such as Zone:Read and Zone Analytics:Read)*
4. Tick in the categories:
   - **DNS & Zones → Zone : Read**
   - **Analytics & Logs → Analytics : Read**
5. *(optional)* Client IP filtering, TTL — leave at default
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
'@ | Out-File -Encoding utf8 .dev.vars

npm run dev
```

Open <http://localhost:8787>.

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

Without a valid Access session the Worker returns 302 to the CF Access login page.

#### Optional — verify the Access JWT in code (defense-in-depth)

By default the Worker trusts that Access sits in front of it (network-level enforcement). You can additionally have the Worker **verify the Access JWT itself**, so that a misconfigured/removed Access application cannot silently expose the data. Set two more variables (plain vars, not secrets):

| Variable | Description | Example |
|---|---|---|
| `CF_ACCESS_TEAM_DOMAIN` | Your Zero Trust team domain | `https://yourteam.cloudflareaccess.com` |
| `CF_ACCESS_AUD` | Application Audience (AUD) tag of the Access application | `0a1b2c…` |

When **both** are set, every `/api/*` request must carry a valid Access token (`Cf-Access-Jwt-Assertion` header or `CF_Authorization` cookie); the Worker checks the RS256 signature against your team's public keys plus the audience, issuer and expiry, and returns `403` otherwise. When either is unset, in-code verification is skipped (so `wrangler dev` keeps working).

## Important — disabling the default domains

[wrangler.jsonc](wrangler.jsonc) hard-codes:
- `workers_dev: false` — disables `<worker>.<subdomain>.workers.dev`
- `preview_urls: false` — disables preview URLs from `wrangler versions upload`

Without this Wrangler would re-enable the default domains on every deploy, which would bypass Access (preview URLs have no Access policy attached). If you ever need to enable the default domain again, delete these lines from the config.

## Free tier limitations

- **WAF event retention**: 24 h (Pro 72 h, Biz 30 d, Ent 6 m) — Cloudflare limit, not this code
- **Max 10 000 events per request** — if the zone exceeds this, statistics are based on a sample (you'll see `truncated: true` in the response)
- **Worker quotas**: 100 000 req/day, 10 ms CPU
- **GraphQL rate limit**: ~1 200 req/5 min per token (each account has its own → scales with the number of accounts)
- **`firewallEventsAdaptiveGroups` (server-side aggregation) is Pro+ only** — that is why the Worker aggregates raw events in JS

## Security notes

- Tokens have read-only permissions — even a leaked secret cannot change anything in the CF accounts
- The frontend never receives a token — `GET /api/accounts` returns only `id` + `label`
- The Worker must sit behind Cloudflare Access — otherwise the dashboard is public. Optionally it can also [verify the Access JWT in code](#optional--verify-the-access-jwt-in-code-defense-in-depth) as defense-in-depth
- All assets are served with a strict `Content-Security-Policy` (`script-src 'self'`, `frame-ancestors 'none'`, …) plus `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy`. All scripts are self-hosted (Chart.js in `public/vendor/`, app logic in `public/app.js`) — no third-party origins are loaded
- CSV export escapes formula-trigger characters (`= + - @`) to prevent CSV/Excel formula injection, and the download filename is sanitised
- Upstream calls to the Cloudflare API/GraphQL have a hard timeout, so a stalled upstream returns `504` instead of hanging the Worker
- `.dev.vars` is listed in [.gitignore](.gitignore)

## Possible extensions

- Cron Trigger → store aggregations in D1/R2 for history longer than 24 h
- Alerting webhook (Slack/Discord) when the blocked-request threshold is exceeded

## License

[MIT](LICENSE)
