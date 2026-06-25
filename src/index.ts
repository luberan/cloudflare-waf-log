/**
 * Cloudflare Worker — WAF events dashboard (multi-account)
 *
 * Endpoints:
 *   GET /api/accounts                              → list of configured accounts (id + label)
 *   GET /api/zones?account=<id>                    → list of zones for the given account
 *   GET /api/log?account=<id>&zone=<id>&...        → individual events (firewallEventsAdaptive)
 *   GET /api/stats?account=<id>&zone=<id>&...      → WAF aggregations (firewallEventsAdaptive, client-side grouped)
 *   GET /api/http-stats?account=<id>&zone=<id>&... → HTTP traffic + edge performance (httpRequestsAdaptiveGroups, server-side grouped)
 *   GET /api/export.csv?account=<id>&zone=<id>&... → CSV export of raw events (up to 10 000 rows)
 *
 * Configuration (everything as Worker secrets — nothing in the repo):
 *   For each CF account create THREE secrets:
 *     CFACC_<ID>_LABEL     – what appears in the UI dropdown (e.g. "ACME Inc.")
 *     CFACC_<ID>_ACCOUNT   – Cloudflare Account ID (32 hex chars)
 *     CFACC_<ID>_TOKEN     – Cloudflare API token (read-only)
 *   <ID> is any short identifier [A-Z0-9_], it appears in the URL as ?account=<id>.
 *
 *   Example — two accounts:
 *     CFACC_PERSONAL_LABEL   = "My account"
 *     CFACC_PERSONAL_ACCOUNT = "abc123..."
 *     CFACC_PERSONAL_TOKEN   = "cf_xxx"
 *     CFACC_ACME_LABEL       = "ACME Inc."
 *     CFACC_ACME_ACCOUNT     = "def456..."
 *     CFACC_ACME_TOKEN       = "cf_yyy"
 *
 *   Adding a new account = three new secrets, nothing existing changes.
 *   Token rotation = overwrite just CFACC_<ID>_TOKEN.
 *
 * Access protection: the Worker is meant to sit behind Cloudflare Access. Optionally, setting the
 * env vars CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD turns on in-code Access JWT verification as
 * defense-in-depth (every /api request must then carry a valid Access token).
 */

export interface Env {
  ASSETS: Fetcher;
  // CFACC_*_LABEL / _ACCOUNT / _TOKEN per account; optionally CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD
  // to enable in-code Cloudflare Access JWT verification.
  [key: string]: unknown;
}

type Account = {
  id: string;
  label: string;
  accountId: string;
  token: string;
};

const CF_API = "https://api.cloudflare.com/client/v4";
const CF_GRAPHQL = "https://api.cloudflare.com/client/v4/graphql";

// Hard timeout for upstream Cloudflare requests so a stalled call cannot pin the Worker until the
// platform limit. AbortSignal.timeout rejects with a TimeoutError DOMException, surfaced as 504.
const CF_FETCH_TIMEOUT_MS = 20000;

async function timedFetch(input: string, init: RequestInit = {}): Promise<Response> {
  try {
    return await fetch(input, { ...init, signal: AbortSignal.timeout(CF_FETCH_TIMEOUT_MS) });
  } catch (e) {
    if (e instanceof DOMException && e.name === "TimeoutError") {
      throw new HttpError(504, "upstream request to Cloudflare timed out");
    }
    throw e;
  }
}

type Filters = {
  zoneTag: string;
  datetimeGeq: string;
  datetimeLeq: string;
  action?: string[];
  clientCountryName?: string[];
  clientRequestHTTPHost?: string[];
  clientRequestPath?: string[];
  ruleId?: string[];
  source?: string[];
  clientAsn?: number[];
  userAgent?: string[];
  limit?: number;
};

function json(data: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...(init.headers || {}),
    },
  });
}

function err(status: number, message: string): Response {
  return json({ error: message }, { status });
}

/** An error carrying an HTTP status, so request-validation failures surface as 4xx instead of 500. */
class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

// Security headers applied to every static asset response. The dashboard self-hosts all of its
// scripts (Chart.js lives in /vendor, the app logic in /app.js), so the CSP can lock scripts to
// same-origin. Inline styles / style attributes are still used, hence 'unsafe-inline' for style only.
const SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy":
    "default-src 'self'; " +
    "script-src 'self'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'none'; " +
    "object-src 'none'; " +
    "form-action 'self'",
};

// Accounts are derived from Worker secrets which cannot change without a redeploy (and a redeploy
// spins up a fresh isolate), so the parsed list is memoized per Env for the isolate's lifetime.
const accountsCache = new WeakMap<Env, Account[]>();

function loadAccounts(env: Env): Account[] {
  const cached = accountsCache.get(env);
  if (cached) return cached;

  // Group the CFACC_<ID>_<KIND> secrets by normalized id, reading each value from its ACTUAL key
  // so that secrets defined with lowercase ids are not silently dropped.
  const parts = new Map<string, { label?: string; accountId?: string; token?: string }>();
  for (const key of Object.keys(env)) {
    const m = key.match(/^CFACC_([A-Z0-9_]+)_(LABEL|ACCOUNT|TOKEN)$/i);
    if (!m) continue;
    const val = env[key];
    if (typeof val !== "string") continue;
    const id = m[1].toUpperCase();
    const kind = m[2].toUpperCase();
    const entry = parts.get(id) ?? {};
    if (kind === "LABEL") entry.label = val;
    else if (kind === "ACCOUNT") entry.accountId = val;
    else entry.token = val;
    parts.set(id, entry);
  }

  const out: Account[] = [];
  const incomplete: string[] = [];
  for (const [id, p] of parts) {
    if (p.label !== undefined && p.accountId !== undefined && p.token !== undefined) {
      out.push({ id: id.toLowerCase(), label: p.label, accountId: p.accountId, token: p.token });
    } else {
      incomplete.push(id);
    }
  }
  if (out.length === 0) {
    throw new HttpError(
      500,
      incomplete.length
        ? `Account(s) ${incomplete.join(", ")} are missing one of LABEL/ACCOUNT/TOKEN secrets`
        : "No accounts configured — set CFACC_<ID>_LABEL, _ACCOUNT, _TOKEN as Worker secrets",
    );
  }
  out.sort((a, b) => a.label.localeCompare(b.label));
  accountsCache.set(env, out);
  return out;
}

function pickAccount(env: Env, url: URL): Account {
  const id = url.searchParams.get("account");
  if (!id) throw new HttpError(400, "missing 'account' query parameter");
  const acc = loadAccounts(env).find((a) => a.id === id);
  if (!acc) throw new HttpError(404, `unknown account '${id}'`);
  return acc;
}

function parseFilters(url: URL): Filters {
  const zone = url.searchParams.get("zone");
  if (!zone) throw new HttpError(400, "missing 'zone' query parameter");

  const now = new Date();
  const defaultFrom = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const since = url.searchParams.get("since") ?? defaultFrom.toISOString();
  const until = url.searchParams.get("until") ?? now.toISOString();

  const multi = (name: string) => {
    const v = url.searchParams
      .getAll(name)
      .flatMap((s) => s.split(","))
      .map((s) => s.trim())
      .filter(Boolean);
    return v.length ? v : undefined;
  };

  const multiInt = (name: string) => {
    const v = multi(name)
      ?.map((s) => Number(s.replace(/^AS/i, "")))
      .filter((n) => Number.isFinite(n) && n > 0);
    return v && v.length ? v : undefined;
  };

  const limit = Number(url.searchParams.get("limit") ?? "200");

  return {
    zoneTag: zone,
    datetimeGeq: since,
    datetimeLeq: until,
    action: multi("action"),
    clientCountryName: multi("country"),
    clientRequestHTTPHost: multi("host"),
    clientRequestPath: multi("path"),
    ruleId: multi("rule"),
    source: multi("source"),
    clientAsn: multiInt("asn"),
    userAgent: multi("ua"),
    limit: Number.isFinite(limit) ? Math.min(Math.max(limit, 1), 1000) : 200,
  };
}

async function cfFetch<T>(acc: Account, path: string): Promise<T> {
  const res = await timedFetch(`${CF_API}${path}`, {
    headers: {
      authorization: `Bearer ${acc.token}`,
      "content-type": "application/json",
    },
  });
  const body = (await res.json()) as { success: boolean; result: T; errors?: unknown };
  if (!res.ok || !body.success) {
    throw new Error(`Cloudflare API ${res.status}: ${JSON.stringify(body.errors ?? body)}`);
  }
  return body.result;
}

async function gql<T>(acc: Account, query: string, variables: Record<string, unknown>): Promise<T> {
  const res = await timedFetch(CF_GRAPHQL, {
    method: "POST",
    headers: {
      authorization: `Bearer ${acc.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ query, variables }),
  });
  const body = (await res.json()) as { data?: T; errors?: { message: string }[] };
  if (!res.ok || body.errors?.length) {
    throw new Error(`GraphQL error: ${JSON.stringify(body.errors ?? res.statusText)}`);
  }
  return body.data as T;
}

// ── Routes ────────────────────────────────────────────────────────────────────

function listAccounts(env: Env): Response {
  // Never 500 here — an empty list lets the dashboard show its first-run setup hint.
  let accounts: { id: string; label: string }[] = [];
  try {
    accounts = loadAccounts(env).map((a) => ({ id: a.id, label: a.label }));
  } catch (e) {
    if (!(e instanceof HttpError)) throw e;
  }
  return json({ accounts });
}

async function listZones(acc: Account): Promise<Response> {
  type Zone = { id: string; name: string; status: string; plan: { name: string } };
  const all: Zone[] = [];
  let page = 1;
  while (true) {
    const result = await cfFetch<Zone[]>(
      acc,
      `/zones?account.id=${encodeURIComponent(acc.accountId)}&per_page=50&page=${page}`,
    );
    all.push(...result);
    if (result.length < 50) break;
    page++;
    if (page > 20) break;
  }
  return json({
    zones: all
      .map((z) => ({ id: z.id, name: z.name, status: z.status, plan: z.plan?.name }))
      .sort((a, b) => a.name.localeCompare(b.name)),
  });
}

async function fetchEvents(acc: Account, f: Filters, limit: number): Promise<any[]> {
  const query = /* GraphQL */ `
    query Events(
      $zoneTag: String!
      $limit: Int!
      $filter: ZoneFirewallEventsAdaptiveFilter_InputObject
    ) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          firewallEventsAdaptive(
            filter: $filter
            limit: $limit
            orderBy: [datetime_DESC]
          ) {
            datetime
            action
            source
            clientIP
            clientAsn
            clientCountryName
            clientASNDescription
            clientRequestHTTPHost
            clientRequestPath
            clientRequestHTTPMethodName
            userAgent
            ruleId
            rayName
          }
        }
      }
    }
  `;

  const filter: Record<string, unknown> = {
    datetime_geq: f.datetimeGeq,
    datetime_leq: f.datetimeLeq,
  };
  if (f.action?.length) filter.action_in = f.action;
  if (f.clientCountryName?.length) filter.clientCountryName_in = f.clientCountryName;
  if (f.clientRequestHTTPHost?.length) filter.clientRequestHTTPHost_in = f.clientRequestHTTPHost;
  if (f.clientRequestPath?.length) filter.clientRequestPath_in = f.clientRequestPath;
  if (f.ruleId?.length) filter.ruleId_in = f.ruleId;
  if (f.source?.length) filter.source_in = f.source;
  if (f.clientAsn?.length) filter.clientAsn_in = f.clientAsn;
  if (f.userAgent?.length) filter.userAgent_in = f.userAgent;

  type Resp = { viewer: { zones: { firewallEventsAdaptive: any[] }[] } };
  const data = await gql<Resp>(acc, query, { zoneTag: f.zoneTag, limit, filter });
  return data.viewer.zones[0]?.firewallEventsAdaptive ?? [];
}

// Cache TTL for fetched events in the Worker Cache API. Short TTL keeps the data
// reasonably fresh while making rapid facet-toggle UX instant.
const EVENTS_CACHE_TTL_SECONDS = 300;

async function cachedFetchEvents(
  acc: Account,
  f: Filters,
  limit: number,
): Promise<{ events: any[]; cacheState: "HIT" | "MISS" | "BYPASS" }> {
  const cache = (caches as unknown as { default?: Cache }).default;
  if (!cache) {
    // Cache API not available (e.g. in tests) — fall back to a direct fetch.
    const events = await fetchEvents(acc, f, limit);
    return { events, cacheState: "BYPASS" };
  }

  // Cache key — unifies all attributes that distinguish the outer fetch.
  // Account is part of the key (different token + different accountId); so are zone/time/action/source.
  // Time bounds are rounded down to 5-minute buckets — the frontend sends `new Date().toISOString()`
  // with millisecond precision, so without bucketing every request would have a unique key and
  // the cache would never hit. 5 min = same as the TTL → within a cache lifetime all toggle
  // requests hit the same key.
  const bucket = (iso: string) => {
    const ms = Date.parse(iso);
    if (!Number.isFinite(ms)) return iso;
    return new Date(Math.floor(ms / 300000) * 300000).toISOString();
  };
  const keyUrl = new URL("https://waf-cache.internal/events");
  keyUrl.searchParams.set("acc", acc.id);
  keyUrl.searchParams.set("zone", f.zoneTag);
  keyUrl.searchParams.set("from", bucket(f.datetimeGeq));
  keyUrl.searchParams.set("to", bucket(f.datetimeLeq));
  keyUrl.searchParams.set("action", (f.action ?? []).slice().sort().join(","));
  keyUrl.searchParams.set("source", (f.source ?? []).slice().sort().join(","));
  keyUrl.searchParams.set("limit", String(limit));
  const cacheKey = new Request(keyUrl.toString(), { method: "GET" });

  const cached = await cache.match(cacheKey);
  if (cached) {
    const events = (await cached.json()) as any[];
    return { events, cacheState: "HIT" };
  }

  const events = await fetchEvents(acc, f, limit);
  // ctx.waitUntil would be slightly better (let the request finish first) but Cache.put
  // is a fast write into edge cache — a few ms — so awaiting it is fine.
  await cache.put(
    cacheKey,
    new Response(JSON.stringify(events), {
      headers: {
        "content-type": "application/json",
        "cache-control": `public, max-age=${EVENTS_CACHE_TTL_SECONDS}`,
      },
    }),
  );
  return { events, cacheState: "MISS" };
}

async function getEvents(acc: Account, f: Filters): Promise<Response> {
  const events = await fetchEvents(acc, f, f.limit ?? 200);
  return json({ events });
}

const CSV_COLUMNS: { header: string; key: string }[] = [
  { header: "datetime", key: "datetime" },
  { header: "action", key: "action" },
  { header: "source", key: "source" },
  { header: "clientIP", key: "clientIP" },
  { header: "clientAsn", key: "clientAsn" },
  { header: "clientCountryName", key: "clientCountryName" },
  { header: "clientASNDescription", key: "clientASNDescription" },
  { header: "clientRequestHTTPHost", key: "clientRequestHTTPHost" },
  { header: "clientRequestPath", key: "clientRequestPath" },
  { header: "clientRequestHTTPMethodName", key: "clientRequestHTTPMethodName" },
  { header: "userAgent", key: "userAgent" },
  { header: "ruleId", key: "ruleId" },
  { header: "rayName", key: "rayName" },
];

function csvEscape(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = String(v);
  // Prefix formula-trigger chars to prevent CSV injection in Excel/Sheets.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

async function exportCsv(acc: Account, f: Filters): Promise<Response> {
  const events = await fetchEvents(acc, f, 10000);
  const lines = [CSV_COLUMNS.map((c) => c.header).join(",")];
  for (const e of events) {
    lines.push(CSV_COLUMNS.map((c) => csvEscape((e as Record<string, unknown>)[c.key])).join(","));
  }
  // UTF-8 BOM so Excel opens it with correct encoding.
  const body = "\uFEFF" + lines.join("\r\n") + "\r\n";
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const safeZone = f.zoneTag.replace(/[^a-zA-Z0-9]/g, "").slice(0, 8) || "zone";
  const filename = `waf-${acc.id}-${safeZone}-${stamp}.csv`;
  return new Response(body, {
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="${filename}"`,
      "cache-control": "no-store",
      "x-event-count": String(events.length),
      "x-truncated": events.length >= 10000 ? "1" : "0",
    },
  });
}

async function getSummary(acc: Account, f: Filters): Promise<Response> {
  // Note: on the Free tier `firewallEventsAdaptiveGroups` is NOT available (requires Pro+).
  // So we fetch raw events (limit 10000 = hard limit) and aggregate them here in the Worker.
  //
  // Drill-down facets (country, host, path, rule, asn, ua) are applied in JS, so that each
  // facet table can show all options even when one of them is an active filter
  // (typical facet-search UX: selecting a value in one facet must not erase the other options
  // in the same facet). Server-side we filter only by action, source, zone, datetime — those
  // do not have drill-down UI.
  //
  // Cache: the outer fetch (zone+time+action+source) is cached in the Worker Cache API.
  // A facet toggle = identical outer fetch → cache HIT → the CF GraphQL roundtrip
  // (typically 500–2000 ms) is skipped.
  const outerFilters: Filters = {
    ...f,
    clientCountryName: undefined,
    clientRequestHTTPHost: undefined,
    clientRequestPath: undefined,
    ruleId: undefined,
    clientAsn: undefined,
    userAgent: undefined,
  };
  const { events, cacheState } = await cachedFetchEvents(acc, outerFilters, 10000);

  type Facet = "country" | "host" | "path" | "rule" | "asn" | "ua";
  // Precompute filter values as Sets once (instead of Array.includes per event × per facet).
  const fCountry = f.clientCountryName?.length ? new Set(f.clientCountryName) : null;
  const fHost = f.clientRequestHTTPHost?.length ? new Set(f.clientRequestHTTPHost) : null;
  const fPath = f.clientRequestPath?.length ? new Set(f.clientRequestPath) : null;
  const fRule = f.ruleId?.length ? new Set(f.ruleId) : null;
  const fAsn = f.clientAsn?.length ? new Set(f.clientAsn) : null;
  const fUa = f.userAgent?.length ? new Set(f.userAgent) : null;
  const matches = (e: any, exclude?: Facet): boolean => {
    if (exclude !== "country" && fCountry && !fCountry.has(e.clientCountryName)) return false;
    if (exclude !== "host" && fHost && !fHost.has(e.clientRequestHTTPHost)) return false;
    if (exclude !== "path" && fPath && !fPath.has(e.clientRequestPath)) return false;
    if (exclude !== "rule" && fRule && !fRule.has(e.ruleId)) return false;
    if (exclude !== "asn" && fAsn && !fAsn.has(e.clientAsn)) return false;
    if (exclude !== "ua" && fUa && !fUa.has(e.userAgent)) return false;
    return true;
  };

  const filtered = events.filter((e) => matches(e));

  const counter = (src: any[], key: (e: any) => string | undefined) => {
    const m = new Map<string, number>();
    for (const e of src) {
      const k = key(e) ?? "(unknown)";
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()]
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => b.count - a.count);
  };

  const facetSrc = (exclude: Facet) => events.filter((e) => matches(e, exclude));

  const byAction = counter(filtered, (e) => e.action);
  const bySource = counter(filtered, (e) => e.source);
  const byCountry = counter(facetSrc("country"), (e) => e.clientCountryName).slice(0, 50);
  const byHost = counter(facetSrc("host"), (e) => e.clientRequestHTTPHost).slice(0, 50);
  const byPath = counter(facetSrc("path"), (e) => e.clientRequestPath).slice(0, 50);
  const byRule = counter(facetSrc("rule"), (e) => e.ruleId).slice(0, 50);
  const byUserAgent = counter(facetSrc("ua"), (e) => e.userAgent).slice(0, 50);

  // ASN aggregation — group by numeric ASN, keep description as label.
  const asnSrc = facetSrc("asn");
  const asnMap = new Map<string, { count: number; label: string }>();
  for (const e of asnSrc) {
    const asn = e.clientAsn ?? 0;
    const k = String(asn);
    const cur = asnMap.get(k);
    if (cur) cur.count++;
    else asnMap.set(k, { count: 1, label: e.clientASNDescription || "(unknown)" });
  }
  const byAsn = [...asnMap.entries()]
    .map(([asn, { count, label }]) => ({ key: asn, label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 50);

  // Hourly time series, per action — from the filtered set.
  const seriesMap = new Map<string, number>(); // key: "hour|action"
  for (const e of filtered) {
    const hour = (e.datetime as string).slice(0, 13) + ":00:00Z";
    const k = `${hour}|${e.action}`;
    seriesMap.set(k, (seriesMap.get(k) ?? 0) + 1);
  }
  const series = [...seriesMap.entries()].map(([k, count]) => {
    const [hour, action] = k.split("|");
    return { hour, action, count };
  });
  series.sort((a, b) => a.hour.localeCompare(b.hour));

  return json(
    {
      byAction,
      byCountry,
      byHost,
      byPath,
      bySource,
      byRule,
      byAsn,
      byUserAgent,
      series,
      events: filtered.slice(0, 500),
      totalSampled: events.length,
      totalMatched: filtered.length,
      truncated: events.length >= 10000,
      cache: cacheState,
    },
    { headers: { "x-cache": cacheState } },
  );
}

// ── HTTP traffic analytics (httpRequestsAdaptiveGroups) ─────────────────────────
// Unlike firewallEventsAdaptiveGroups (Pro+), httpRequestsAdaptiveGroups supports server-side
// aggregation on the Free plan — so here we let Cloudflare do the grouping and only assemble the
// chart-ready shape, instead of pulling raw events and counting in JS.
//
// Adaptive sampling: a group's count/sum cover only the SAMPLED events; multiplying by that group's
// avg sampleInterval estimates the true value (sampleInterval is 1 for low-traffic zones, so the
// scaling is a no-op for small sites and correctly extrapolates for busy ones).

type HttpRange = { zoneTag: string; sinceIso: string; untilIso: string };

function parseHttpRange(url: URL): HttpRange {
  const zone = url.searchParams.get("zone");
  if (!zone) throw new HttpError(400, "missing 'zone' query parameter");
  const now = Date.now();
  // Normalize to a guaranteed-ISO string (Date.toISOString) so the value is safe to inline into the
  // GraphQL query literal below — no untrusted characters can reach the query string.
  const toIso = (v: string | null, fallbackMs: number): string => {
    const ms = v ? Date.parse(v) : NaN;
    return new Date(Number.isFinite(ms) ? ms : fallbackMs).toISOString();
  };
  return {
    zoneTag: zone,
    untilIso: toIso(url.searchParams.get("until"), now),
    sinceIso: toIso(url.searchParams.get("since"), now - 24 * 60 * 60 * 1000),
  };
}

// Time + zone filter as a GraphQL object literal. Values are normalized ISO strings (see above).
const httpFilter = (r: HttpRange) =>
  `{ datetime_geq: "${r.sinceIso}", datetime_leq: "${r.untilIso}" }`;

const sampleScale = (g: any): number => g?.avg?.sampleInterval ?? 1;

type HttpGroup = { key: string; requests: number; bytes: number };

/**
 * One breakdown (group-by single dimension). When `optional` is true a schema mismatch on the
 * dimension (e.g. a field unavailable on the plan) degrades to an empty array instead of failing
 * the whole request, so the core breakdowns keep working.
 */
async function httpGroupBy(
  acc: Account,
  r: HttpRange,
  dimension: string,
  opts: { limit?: number; bytes?: boolean; optional?: boolean } = {},
): Promise<HttpGroup[]> {
  const { limit = 30, bytes = true, optional = false } = opts;
  const query = /* GraphQL */ `
    query HttpGroup($zoneTag: String!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          g: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: ${limit}, orderBy: [count_DESC]) {
            count
            avg { sampleInterval }${bytes ? "\n            sum { edgeResponseBytes }" : ""}
            dimensions { ${dimension} }
          }
        }
      }
    }
  `;
  const run = async (): Promise<HttpGroup[]> => {
    type Resp = { viewer: { zones: { g: any[] }[] } };
    const data = await gql<Resp>(acc, query, { zoneTag: r.zoneTag });
    const groups = data.viewer.zones[0]?.g ?? [];
    return groups
      .map((g) => {
        const s = sampleScale(g);
        return {
          key: String(g.dimensions?.[dimension] ?? ""),
          requests: Math.round((g.count ?? 0) * s),
          bytes: Math.round((g.sum?.edgeResponseBytes ?? 0) * s),
        };
      })
      .filter((x) => x.key !== "");
  };
  if (!optional) return run();
  try {
    return await run();
  } catch {
    return [];
  }
}

type HttpSeriesPoint = { t: string; requests: number; bytes: number; visits: number };

async function httpSeries(acc: Account, r: HttpRange, timeDim: string): Promise<HttpSeriesPoint[]> {
  const query = /* GraphQL */ `
    query HttpSeries($zoneTag: String!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          g: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 5000, orderBy: [${timeDim}_ASC]) {
            count
            avg { sampleInterval }
            sum { edgeResponseBytes visits }
            dimensions { ${timeDim} }
          }
        }
      }
    }
  `;
  type Resp = { viewer: { zones: { g: any[] }[] } };
  const data = await gql<Resp>(acc, query, { zoneTag: r.zoneTag });
  const groups = data.viewer.zones[0]?.g ?? [];
  return groups.map((g) => {
    const s = sampleScale(g);
    return {
      t: g.dimensions?.[timeDim] as string,
      requests: Math.round((g.count ?? 0) * s),
      bytes: Math.round((g.sum?.edgeResponseBytes ?? 0) * s),
      visits: Math.round((g.sum?.visits ?? 0) * s),
    };
  });
}

type HttpPerf = {
  ttfbMs: number | null;
  originMs: number | null;
  series: { t: string; ttfbMs: number | null; originMs: number | null }[];
} | null;

/**
 * Edge/origin timing over time. These avg fields are not available on every plan/dataset version,
 * so the whole thing is best-effort: any failure returns null and the UI simply hides the panel.
 */
async function httpPerf(acc: Account, r: HttpRange, timeDim: string): Promise<HttpPerf> {
  const query = /* GraphQL */ `
    query HttpPerf($zoneTag: String!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          g: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 5000, orderBy: [${timeDim}_ASC]) {
            count
            avg { edgeTimeToFirstByteMs originResponseDurationMs }
            dimensions { ${timeDim} }
          }
        }
      }
    }
  `;
  try {
    type Resp = { viewer: { zones: { g: any[] }[] } };
    const data = await gql<Resp>(acc, query, { zoneTag: r.zoneTag });
    const groups = data.viewer.zones[0]?.g ?? [];
    const series = groups.map((g) => ({
      t: g.dimensions?.[timeDim] as string,
      ttfbMs: (g.avg?.edgeTimeToFirstByteMs ?? null) as number | null,
      originMs: (g.avg?.originResponseDurationMs ?? null) as number | null,
      count: (g.count ?? 0) as number,
    }));
    // Overall averages weighted by request count (avg of per-bucket averages would bias quiet hours).
    let wc = 0;
    let ttfb = 0;
    let origin = 0;
    for (const s of series) {
      wc += s.count;
      if (s.ttfbMs != null) ttfb += s.ttfbMs * s.count;
      if (s.originMs != null) origin += s.originMs * s.count;
    }
    return {
      ttfbMs: wc ? ttfb / wc : null,
      originMs: wc ? origin / wc : null,
      series: series.map(({ t, ttfbMs, originMs }) => ({ t, ttfbMs, originMs })),
    };
  } catch {
    return null;
  }
}

// cacheStatus dimension values that count as "served from cache" for the cached-% KPI.
const CACHED_STATUSES = new Set(["hit", "stale", "revalidated", "updating"]);

async function buildHttpStats(acc: Account, r: HttpRange) {
  // Minute resolution for short windows, hourly otherwise — both are always-available time dimensions.
  const hours = (Date.parse(r.untilIso) - Date.parse(r.sinceIso)) / 3_600_000;
  const timeDim = hours <= 2 ? "datetimeMinute" : "datetimeHour";

  // Core breakdowns must succeed (they back the primary charts); the rest are best-effort.
  const [
    series,
    byCountry,
    byStatus,
    byHost,
    byPath,
    byContentType,
    byHttpVersion,
    byCacheStatus,
    perf,
  ] = await Promise.all([
    httpSeries(acc, r, timeDim),
    httpGroupBy(acc, r, "clientCountryName", { limit: 50 }),
    httpGroupBy(acc, r, "edgeResponseStatus", { limit: 50, bytes: false }),
    httpGroupBy(acc, r, "clientRequestHTTPHost", { limit: 30 }),
    httpGroupBy(acc, r, "clientRequestPath", { limit: 50 }),
    httpGroupBy(acc, r, "edgeResponseContentTypeName", { limit: 30, optional: true }),
    httpGroupBy(acc, r, "clientRequestHTTPProtocol", { limit: 20, bytes: false, optional: true }),
    httpGroupBy(acc, r, "cacheStatus", { limit: 20, optional: true }),
    httpPerf(acc, r, timeDim),
  ]);

  const totals = series.reduce(
    (a, s) => {
      a.requests += s.requests;
      a.bytes += s.bytes;
      a.visits += s.visits;
      return a;
    },
    { requests: 0, bytes: 0, visits: 0 },
  );

  let cachedPct: number | null = null;
  if (byCacheStatus.length) {
    const all = byCacheStatus.reduce((s, x) => s + x.requests, 0);
    const cached = byCacheStatus
      .filter((x) => CACHED_STATUSES.has(x.key.toLowerCase()))
      .reduce((s, x) => s + x.requests, 0);
    cachedPct = all ? (cached / all) * 100 : null;
  }

  return {
    timeDim,
    series,
    byCountry,
    byStatus,
    byHost,
    byPath,
    byContentType,
    byHttpVersion,
    byCacheStatus,
    perf,
    totals: { ...totals, cachedPct },
  };
}

async function getHttpStats(acc: Account, url: URL): Promise<Response> {
  const r = parseHttpRange(url);
  const cache = (caches as unknown as { default?: Cache }).default;
  const bucket = (iso: string) => {
    const ms = Date.parse(iso);
    return Number.isFinite(ms) ? new Date(Math.floor(ms / 300000) * 300000).toISOString() : iso;
  };

  if (!cache) {
    const payload = await buildHttpStats(acc, r);
    return json({ ...payload, cache: "BYPASS" }, { headers: { "x-cache": "BYPASS" } });
  }

  const keyUrl = new URL("https://waf-cache.internal/http-stats");
  keyUrl.searchParams.set("acc", acc.id);
  keyUrl.searchParams.set("zone", r.zoneTag);
  keyUrl.searchParams.set("from", bucket(r.sinceIso));
  keyUrl.searchParams.set("to", bucket(r.untilIso));
  const cacheKey = new Request(keyUrl.toString(), { method: "GET" });

  const hit = await cache.match(cacheKey);
  if (hit) {
    const payload = (await hit.json()) as Record<string, unknown>;
    return json({ ...payload, cache: "HIT" }, { headers: { "x-cache": "HIT" } });
  }

  const payload = await buildHttpStats(acc, r);
  await cache.put(
    cacheKey,
    new Response(JSON.stringify(payload), {
      headers: {
        "content-type": "application/json",
        "cache-control": `public, max-age=${EVENTS_CACHE_TTL_SECONDS}`,
      },
    }),
  );
  return json({ ...payload, cache: "MISS" }, { headers: { "x-cache": "MISS" } });
}

// ── Optional Cloudflare Access verification (defense-in-depth) ──────────────────
// Enabled only when BOTH CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD are set. When enabled, every
// /api request must carry a valid Access JWT (the Cf-Access-Jwt-Assertion header that Access
// injects, or the CF_Authorization cookie) — verified against the team's public keys, audience
// and expiry. When unset, verification is skipped so local `wrangler dev` and network-only Access
// setups keep working.

type AccessJwk = { kid?: string; n?: string; e?: string };
let jwksCache: { keys: AccessJwk[]; exp: number } | null = null;
const JWKS_TTL_MS = 3_600_000;

function b64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson<T>(s: string): T {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s))) as T;
}

async function getAccessJwks(teamDomain: string): Promise<AccessJwk[]> {
  if (jwksCache && jwksCache.exp > Date.now()) return jwksCache.keys;
  const res = await timedFetch(`${teamDomain}/cdn-cgi/access/certs`, { method: "GET" });
  if (!res.ok) throw new HttpError(403, "unable to fetch Access signing keys");
  const body = (await res.json()) as { keys?: AccessJwk[] };
  const keys = body.keys ?? [];
  jwksCache = { keys, exp: Date.now() + JWKS_TTL_MS };
  return keys;
}

async function verifyAccess(env: Env, request: Request): Promise<void> {
  const rawTeam = typeof env.CF_ACCESS_TEAM_DOMAIN === "string" ? env.CF_ACCESS_TEAM_DOMAIN.trim() : "";
  const aud = typeof env.CF_ACCESS_AUD === "string" ? env.CF_ACCESS_AUD.trim() : "";
  if (!rawTeam || !aud) return; // verification not configured → skip

  // Normalize: ensure a scheme and strip trailing slashes. A plain loop (not a `/\/+$/` regex)
  // avoids polynomial backtracking on inputs with many trailing slashes.
  const withScheme = rawTeam.startsWith("http") ? rawTeam : `https://${rawTeam}`;
  let end = withScheme.length;
  while (end > 0 && withScheme[end - 1] === "/") end--;
  const teamDomain = withScheme.slice(0, end);

  const fromCookie = (request.headers.get("cookie") ?? "")
    .split(/;\s*/)
    .find((c) => c.startsWith("CF_Authorization="))
    ?.slice("CF_Authorization=".length);
  const token = request.headers.get("cf-access-jwt-assertion") || fromCookie;
  if (!token) throw new HttpError(403, "missing Cloudflare Access token");

  const segments = token.split(".");
  if (segments.length !== 3) throw new HttpError(403, "malformed Access token");
  const [rawHeader, rawPayload, rawSig] = segments;

  let header: { alg?: string; kid?: string };
  let payload: { aud?: string | string[]; exp?: number; iss?: string };
  try {
    header = b64urlToJson(rawHeader);
    payload = b64urlToJson(rawPayload);
  } catch {
    throw new HttpError(403, "invalid Access token");
  }
  if (header.alg !== "RS256" || !header.kid) throw new HttpError(403, "unsupported Access token");

  const jwk = (await getAccessJwks(teamDomain)).find((k) => k.kid === header.kid);
  if (!jwk?.n || !jwk.e) throw new HttpError(403, "unknown Access signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(rawSig),
    new TextEncoder().encode(`${rawHeader}.${rawPayload}`),
  );
  if (!ok) throw new HttpError(403, "invalid Access token signature");

  if (typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) {
    throw new HttpError(403, "expired Access token");
  }
  if (payload.iss !== teamDomain) throw new HttpError(403, "Access token issuer mismatch");
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(aud)) throw new HttpError(403, "Access token audience mismatch");
}

// ── Entrypoint ────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) {
      const res = await env.ASSETS.fetch(request);
      const headers = new Headers(res.headers);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
    }

    try {
      await verifyAccess(env, request);

      if (url.pathname === "/api/accounts") return listAccounts(env);

      const account = pickAccount(env, url);

      if (url.pathname === "/api/zones") return await listZones(account);
      if (url.pathname === "/api/log") return await getEvents(account, parseFilters(url));
      if (url.pathname === "/api/stats") return await getSummary(account, parseFilters(url));
      if (url.pathname === "/api/http-stats") return await getHttpStats(account, url);
      if (url.pathname === "/api/export.csv") return await exportCsv(account, parseFilters(url));

      return err(404, "not found");
    } catch (e) {
      if (e instanceof HttpError) return err(e.status, e.message);
      console.error("Unhandled API error:", e);
      return err(500, "internal server error");
    }
  },
} satisfies ExportedHandler<Env>;
