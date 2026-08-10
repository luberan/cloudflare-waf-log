/**
 * Cloudflare Worker — WAF events dashboard (multi-account)
 *
 * Endpoints:
 *   GET /api/accounts                              → list of configured accounts (id + label)
 *   GET /api/zones?account=<id>                    → list of zones for the given account
 *   GET /api/log?account=<id>&zone=<id>&...        → individual events (firewallEventsAdaptive)
 *   GET /api/stats?account=<id>&zone=<id>&...      → WAF aggregations (firewallEventsAdaptive, client-side grouped)
 *   GET /api/http-stats?account=<id>&zone=<id>&... → HTTP traffic + edge performance (httpRequestsAdaptiveGroups, server-side grouped)
 *   GET /api/http-settings?account=<id>&zone=<id>   → HTTP dataset limits for the zone (retention / max query window)
 *   GET /api/waf-settings?account=<id>&zone=<id>    → WAF dataset limit for the zone
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
 * Access protection: the Worker must sit behind Cloudflare Access. Every production /api request
 * also requires in-code JWT verification via CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD. Local
 * development must explicitly set ALLOW_UNAUTHENTICATED_LOCAL_DEV=true.
 */

export interface Env {
  ASSETS: Fetcher;
  // CFACC_*_LABEL / _ACCOUNT / _TOKEN per account; CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD in
  // production; ALLOW_UNAUTHENTICATED_LOCAL_DEV=true only in local .dev.vars.
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

export type Filters = {
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

const MAX_FILTER_VALUES = 100;
const MAX_FILTER_VALUE_LENGTH = 4096;
const MAX_ANALYTICS_RANGE_SECONDS = 31 * 24 * 60 * 60;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

function isoQueryValue(url: URL, name: string, fallbackMs: number): { iso: string; ms: number } {
  const raw = url.searchParams.get(name);
  const ms = raw === null ? fallbackMs : Date.parse(raw);
  if (!Number.isFinite(ms)) throw new HttpError(400, `invalid '${name}' timestamp`);
  return { iso: new Date(ms).toISOString(), ms };
}

function validateTimeRange(sinceMs: number, untilMs: number): void {
  if (sinceMs >= untilMs) throw new HttpError(400, "'since' must be earlier than 'until'");
  if (untilMs > Date.now() + MAX_FUTURE_SKEW_MS) {
    throw new HttpError(400, "'until' cannot be in the future");
  }
  if ((untilMs - sinceMs) / 1000 > MAX_ANALYTICS_RANGE_SECONDS) {
    throw new HttpError(400, "requested range exceeds 31 days");
  }
}

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

export function parseFilters(url: URL): Filters {
  const zone = url.searchParams.get("zone");
  if (!zone) throw new HttpError(400, "missing 'zone' query parameter");
  if (zone.length > 128) throw new HttpError(400, "invalid 'zone' query parameter");

  const now = Date.now();
  const since = isoQueryValue(url, "since", now - 24 * 60 * 60 * 1000);
  const until = isoQueryValue(url, "until", now);
  validateTimeRange(since.ms, until.ms);

  const multi = (name: string, splitCommas = true) => {
    const v = url.searchParams
      .getAll(name)
      .flatMap((s) => (splitCommas ? s.split(",") : [s]))
      .map((s) => s.trim())
      .filter(Boolean);
    if (v.length > MAX_FILTER_VALUES) {
      throw new HttpError(400, `too many '${name}' filter values`);
    }
    if (v.some((s) => s.length > MAX_FILTER_VALUE_LENGTH)) {
      throw new HttpError(400, `'${name}' filter value is too long`);
    }
    return v.length ? v : undefined;
  };

  const multiInt = (name: string) => {
    const raw = multi(name);
    if (!raw) return undefined;
    const normalized = raw.map((s) => s.replace(/^AS/i, ""));
    if (normalized.some((value) => !/^\d+$/.test(value))) {
      throw new HttpError(400, `invalid '${name}' filter value`);
    }
    const values = normalized.map(Number);
    if (values.some((n) => !Number.isSafeInteger(n) || n <= 0 || n > 0xffffffff)) {
      throw new HttpError(400, `invalid '${name}' filter value`);
    }
    return values;
  };

  const rawLimit = url.searchParams.get("limit");
  const limit = rawLimit === null ? 200 : Number(rawLimit);
  if (!Number.isInteger(limit) || limit < 1) throw new HttpError(400, "invalid 'limit' query parameter");

  return {
    zoneTag: zone,
    datetimeGeq: since.iso,
    datetimeLeq: until.iso,
    action: multi("action"),
    clientCountryName: multi("country"),
    clientRequestHTTPHost: multi("host"),
    clientRequestPath: multi("path", false),
    ruleId: multi("rule"),
    source: multi("source"),
    clientAsn: multiInt("asn"),
    userAgent: multi("ua", false),
    limit: Math.min(limit, 1000),
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
  const prepared = await clampWafFilters(acc, f);
  const events = await fetchEvents(acc, prepared.filters, prepared.filters.limit ?? 200);
  return json({ events, range: prepared.range });
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
  const prepared = await clampWafFilters(acc, f);
  f = prepared.filters;
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
      "x-range-clamped": prepared.range.clamped ? "1" : "0",
      "x-effective-range-seconds": String(prepared.range.effectiveSeconds),
    },
  });
}

async function getSummary(acc: Account, f: Filters): Promise<Response> {
  const prepared = await clampWafFilters(acc, f);
  f = prepared.filters;
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
  // Cloudflare serializes clientAsn as a string in raw event rows, while the filter input is UInt32.
  const fAsn = f.clientAsn?.length ? new Set(f.clientAsn.map(String)) : null;
  const fUa = f.userAgent?.length ? new Set(f.userAgent) : null;
  const matches = (e: any, exclude?: Facet): boolean => {
    if (exclude !== "country" && fCountry && !fCountry.has(e.clientCountryName)) return false;
    if (exclude !== "host" && fHost && !fHost.has(e.clientRequestHTTPHost)) return false;
    if (exclude !== "path" && fPath && !fPath.has(e.clientRequestPath)) return false;
    if (exclude !== "rule" && fRule && !fRule.has(e.ruleId)) return false;
    if (exclude !== "asn" && fAsn && !fAsn.has(String(e.clientAsn))) return false;
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
      sampledRows: events.length,
      matchedSampledRows: filtered.length,
      sampling: {
        dataset: "firewallEventsAdaptive",
        adaptive: true,
        rowLimitReached: events.length >= 10000,
      },
      // Backward-compatible aliases; these are row counts, never estimated event totals.
      totalSampled: events.length,
      totalMatched: filtered.length,
      truncated: events.length >= 10000,
      range: prepared.range,
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
// Numbers are scoped to eyeball requests (requestSource: eyeball) to match Cloudflare's HTTP Traffic
// dashboard. For the *Groups* datasets Cloudflare already returns count/sum extrapolated to the true
// estimate, so we use them as-is — multiplying by sampleInterval would double-count and inflate
// wide-window queries (where sampling kicks in) by the sample factor, which is exactly what made a
// 24 h view show ~10x the real numbers (and vary every time the sampling rate changed).

type HttpRange = { zoneTag: string; sinceIso: string; untilIso: string };

export function parseHttpRange(url: URL): HttpRange {
  const zone = url.searchParams.get("zone");
  if (!zone) throw new HttpError(400, "missing 'zone' query parameter");
  if (zone.length > 128) throw new HttpError(400, "invalid 'zone' query parameter");
  const now = Date.now();
  const until = isoQueryValue(url, "until", now);
  const since = isoQueryValue(url, "since", now - 24 * 60 * 60 * 1000);
  validateTimeRange(since.ms, until.ms);
  return {
    zoneTag: zone,
    untilIso: until.iso,
    sinceIso: since.iso,
  };
}

// Time + zone filter as a GraphQL object literal. Values are normalized ISO strings (see above).
// requestSource: eyeball limits to real end-user requests (excludes Worker sub-requests etc.) — the
// same scoping Cloudflare's HTTP Traffic dashboard uses, so the totals line up with it.
const httpFilter = (r: HttpRange) =>
  `{ datetime_geq: "${r.sinceIso}", datetime_leq: "${r.untilIso}", requestSource: eyeball }`;

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
            count${bytes ? "\n            sum { edgeResponseBytes }" : ""}
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
      .map((g) => ({
        key: String(g.dimensions?.[dimension] ?? ""),
        requests: Math.round(g.count ?? 0),
        bytes: Math.round(g.sum?.edgeResponseBytes ?? 0),
      }))
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

type HttpCore = {
  series: HttpSeriesPoint[];
  byCountry: HttpGroup[];
  byStatus: HttpGroup[];
  byHost: HttpGroup[];
  byPath: HttpGroup[];
};

async function httpCore(acc: Account, r: HttpRange, timeDim: string): Promise<HttpCore> {
  const query = /* GraphQL */ `
    query HttpCore($zoneTag: String!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          series: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 5000, orderBy: [${timeDim}_ASC]) {
            count
            sum { edgeResponseBytes visits }
            dimensions { ${timeDim} }
          }
          country: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 50, orderBy: [count_DESC]) {
            count
            sum { edgeResponseBytes }
            dimensions { clientCountryName }
          }
          status: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 50, orderBy: [count_DESC]) {
            count
            dimensions { edgeResponseStatus }
          }
          host: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 30, orderBy: [count_DESC]) {
            count
            sum { edgeResponseBytes }
            dimensions { clientRequestHTTPHost }
          }
          path: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 50, orderBy: [count_DESC]) {
            count
            sum { edgeResponseBytes }
            dimensions { clientRequestPath }
          }
        }
      }
    }
  `;
  type Resp = {
    viewer: {
      zones: {
        series: any[];
        country: any[];
        status: any[];
        host: any[];
        path: any[];
      }[];
    };
  };
  const data = await gql<Resp>(acc, query, { zoneTag: r.zoneTag });
  const zone = data.viewer.zones[0];
  const mapGroups = (groups: any[] | undefined, dimension: string): HttpGroup[] =>
    (groups ?? [])
      .map((g) => ({
        key: String(g.dimensions?.[dimension] ?? ""),
        requests: Math.round(g.count ?? 0),
        bytes: Math.round(g.sum?.edgeResponseBytes ?? 0),
      }))
      .filter((g) => g.key !== "");
  return {
    series: (zone?.series ?? []).map((g) => ({
      t: g.dimensions?.[timeDim] as string,
      requests: Math.round(g.count ?? 0),
      bytes: Math.round(g.sum?.edgeResponseBytes ?? 0),
      visits: Math.round(g.sum?.visits ?? 0),
    })),
    byCountry: mapGroups(zone?.country, "clientCountryName"),
    byStatus: mapGroups(zone?.status, "edgeResponseStatus"),
    byHost: mapGroups(zone?.host, "clientRequestHTTPHost"),
    byPath: mapGroups(zone?.path, "clientRequestPath"),
  };
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
          series: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 5000, orderBy: [${timeDim}_ASC]) {
            avg { edgeTimeToFirstByteMs originResponseDurationMs }
            dimensions { ${timeDim} }
          }
          overall: httpRequestsAdaptiveGroups(filter: ${httpFilter(r)}, limit: 1) {
            avg { edgeTimeToFirstByteMs originResponseDurationMs }
          }
        }
      }
    }
  `;
  try {
    type Resp = { viewer: { zones: { series: any[]; overall: any[] }[] } };
    const data = await gql<Resp>(acc, query, { zoneTag: r.zoneTag });
    const zone = data.viewer.zones[0];
    const groups = zone?.series ?? [];
    const series = groups.map((g) => ({
      t: g.dimensions?.[timeDim] as string,
      ttfbMs: (g.avg?.edgeTimeToFirstByteMs ?? null) as number | null,
      originMs: (g.avg?.originResponseDurationMs ?? null) as number | null,
    }));
    const overall = zone?.overall?.[0]?.avg;
    if (!series.length && !overall) return null;
    return {
      ttfbMs: (overall?.edgeTimeToFirstByteMs ?? null) as number | null,
      originMs: (overall?.originResponseDurationMs ?? null) as number | null,
      series,
    };
  } catch {
    return null;
  }
}

// cacheStatus dimension values that count as "served from cache" for the cached-% KPI.
const CACHED_STATUSES = new Set(["hit", "stale", "revalidated", "updating"]);

type HttpLimits = {
  adaptive: DatasetWindow;
  hourly: DatasetWindow;
  daily: DatasetWindow;
  adaptiveMaxSeconds: number;
  hourlyMaxSeconds: number;
  dailyMaxSeconds: number;
  maxRangeSeconds: number;
};

type DatasetLimit = { notOlderThan?: number; maxDuration?: number } | null;
type DatasetWindow = {
  notOlderThanSeconds: number;
  maxDurationSeconds: number;
  maxRangeSeconds: number;
};
type LimitsCacheEntry<T> = { value: T; expiresAt: number };
const SETTINGS_CACHE_TTL_MS = 5 * 60 * 1000;
const SETTINGS_FAILURE_TTL_MS = 30 * 1000;
const httpLimitsCache = new Map<string, LimitsCacheEntry<HttpLimits>>();

function datasetWindow(setting: DatasetLimit): DatasetWindow {
  const notOlderThanSeconds = Number(setting?.notOlderThan) || 0;
  const maxDurationSeconds = Number(setting?.maxDuration) || 0;
  const candidates = [notOlderThanSeconds, maxDurationSeconds].filter((value) => value > 0);
  const maxRangeSeconds = candidates.length ? Math.min(...candidates) : 0;
  return {
    notOlderThanSeconds: notOlderThanSeconds || maxRangeSeconds,
    maxDurationSeconds: maxDurationSeconds || maxRangeSeconds,
    maxRangeSeconds,
  };
}

function fallbackDatasetWindow(seconds: number): DatasetWindow {
  return { notOlderThanSeconds: seconds, maxDurationSeconds: seconds, maxRangeSeconds: seconds };
}

// Per-zone/plan limits from the GraphQL Settings node, for the THREE datasets we read HTTP traffic
// from, in increasing range / decreasing resolution: fine-grained `httpRequestsAdaptiveGroups` (short
// window, full breakdowns), the hourly roll-up `httpRequests1hGroups`, and the daily roll-up
// `httpRequests1dGroups` (retained longest — what powers Cloudflare's 30-day views). The per-dataset
// limits decide where we switch datasets; maxRangeSeconds (the largest) is how far back the range
// dropdown may offer. Best-effort: zeros on failure.
async function httpLimitsSeconds(acc: Account, zone: string): Promise<HttpLimits> {
  const cacheKey = `${acc.accountId}:${zone}`;
  const cached = httpLimitsCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.value;

  const query = /* GraphQL */ `
    query HttpSettings($zoneTag: String!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          settings {
            httpRequestsAdaptiveGroups { notOlderThan maxDuration }
            httpRequests1hGroups { notOlderThan maxDuration }
            httpRequests1dGroups { notOlderThan maxDuration }
          }
        }
      }
    }
  `;
  type Resp = {
    viewer: {
      zones: {
        settings: {
          httpRequestsAdaptiveGroups: DatasetLimit;
          httpRequests1hGroups: DatasetLimit;
          httpRequests1dGroups: DatasetLimit;
        };
      }[];
    };
  };
  let result: HttpLimits;
  try {
    const data = await gql<Resp>(acc, query, { zoneTag: zone });
    const settings = data.viewer.zones[0]?.settings;
    const adaptive = datasetWindow(settings?.httpRequestsAdaptiveGroups ?? null);
    const hourly = datasetWindow(settings?.httpRequests1hGroups ?? null);
    const daily = datasetWindow(settings?.httpRequests1dGroups ?? null);
    result = {
      adaptive,
      hourly,
      daily,
      adaptiveMaxSeconds: adaptive.maxRangeSeconds,
      hourlyMaxSeconds: hourly.maxRangeSeconds,
      dailyMaxSeconds: daily.maxRangeSeconds,
      maxRangeSeconds: Math.max(adaptive.maxRangeSeconds, hourly.maxRangeSeconds, daily.maxRangeSeconds),
    };
  } catch {
    const empty = fallbackDatasetWindow(0);
    result = {
      adaptive: empty,
      hourly: empty,
      daily: empty,
      adaptiveMaxSeconds: 0,
      hourlyMaxSeconds: 0,
      dailyMaxSeconds: 0,
      maxRangeSeconds: 0,
    };
  }
  const ttl = result.maxRangeSeconds > 0 ? SETTINGS_CACHE_TTL_MS : SETTINGS_FAILURE_TTL_MS;
  httpLimitsCache.set(cacheKey, { value: result, expiresAt: Date.now() + ttl });
  return result;
}

type WafLimit = DatasetWindow & { source: "cloudflare" | "fallback" };
type WafRangeInfo = {
  requestedSeconds: number;
  effectiveSeconds: number;
  clamped: boolean;
  maxRangeSeconds: number;
  limitSource: WafLimit["source"];
};
const WAF_FALLBACK_SECONDS = 31 * 24 * 60 * 60;
const wafLimitsCache = new Map<string, LimitsCacheEntry<WafLimit>>();

async function wafLimitSeconds(acc: Account, zone: string): Promise<WafLimit> {
  const cacheKey = `${acc.accountId}:${zone}`;
  const cached = wafLimitsCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const query = /* GraphQL */ `
    query WafSettings($zoneTag: String!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          settings { firewallEventsAdaptive { notOlderThan maxDuration } }
        }
      }
    }
  `;
  type Resp = {
    viewer: { zones: { settings: { firewallEventsAdaptive: DatasetLimit } }[] };
  };
  let value: WafLimit = { ...fallbackDatasetWindow(WAF_FALLBACK_SECONDS), source: "fallback" };
  try {
    const data = await gql<Resp>(acc, query, { zoneTag: zone });
    const window = datasetWindow(data.viewer.zones[0]?.settings?.firewallEventsAdaptive ?? null);
    if (window.maxRangeSeconds > 0) value = { ...window, source: "cloudflare" };
  } catch {
    // Keep the request unchanged when Settings is unavailable; upstream remains the authority.
  }
  const ttl = value.source === "cloudflare" ? SETTINGS_CACHE_TTL_MS : SETTINGS_FAILURE_TTL_MS;
  wafLimitsCache.set(cacheKey, { value, expiresAt: Date.now() + ttl });
  return value;
}

async function clampWafFilters(
  acc: Account,
  filters: Filters,
): Promise<{ filters: Filters; range: WafRangeInfo }> {
  const limit = await wafLimitSeconds(acc, filters.zoneTag);
  const untilMs = Date.parse(filters.datetimeLeq);
  const sinceMs = Date.parse(filters.datetimeGeq);
  const requestedSeconds = Math.round((untilMs - sinceMs) / 1000);
  if (limit.source === "fallback") {
    return {
      filters,
      range: {
        requestedSeconds,
        effectiveSeconds: requestedSeconds,
        clamped: false,
        maxRangeSeconds: limit.maxRangeSeconds,
        limitSource: limit.source,
      },
    };
  }
  const retentionCutoffMs = Date.now() - limit.notOlderThanSeconds * 1000;
  if (untilMs < retentionCutoffMs) throw new HttpError(400, "requested WAF range is outside retained data");
  const effectiveSinceMs = Math.max(
    sinceMs,
    retentionCutoffMs,
    untilMs - limit.maxDurationSeconds * 1000,
  );
  const effectiveSeconds = Math.round((untilMs - effectiveSinceMs) / 1000);
  const clamped = effectiveSinceMs > sinceMs;
  return {
    filters: clamped
      ? { ...filters, datetimeGeq: new Date(effectiveSinceMs).toISOString() }
      : filters,
    range: {
      requestedSeconds,
      effectiveSeconds,
      clamped,
      maxRangeSeconds: limit.maxRangeSeconds,
      limitSource: limit.source,
    },
  };
}

// Defaults when Settings is unavailable: adaptive ~24 h, hourly roll-up ~3 d, daily roll-up ~30 d.
const HTTP_ADAPTIVE_FALLBACK_SECONDS = 24 * 60 * 60;
const HTTP_HOURLY_FALLBACK_SECONDS = 3 * 24 * 60 * 60;
const HTTP_DAILY_FALLBACK_SECONDS = 30 * 24 * 60 * 60;
const DAY_SECONDS = 24 * 60 * 60;

export function alignDailyRange(r: HttpRange, effectiveSeconds: number): { range: HttpRange; calendarDays: number } {
  const calendarDays = Math.max(1, Math.ceil(effectiveSeconds / DAY_SECONDS));
  const endDayMs = Date.parse(`${r.untilIso.slice(0, 10)}T00:00:00.000Z`);
  const startDayMs = endDayMs - (calendarDays - 1) * DAY_SECONDS * 1000;
  return {
    range: { ...r, sinceIso: new Date(startDayMs).toISOString() },
    calendarDays,
  };
}

// Dispatcher: pick the dataset by how wide the requested window is, mirroring how Cloudflare's own
// dashboard switches resolution. Up to the adaptive limit → httpRequestsAdaptiveGroups (fine-grained,
// eyeball-scoped, every breakdown incl. paths & performance); up to the hourly roll-up's limit →
// httpRequests1hGroups (hourly); beyond that → httpRequests1dGroups (daily, retained longest, ~30 d).
// The window is clamped to whatever the chosen dataset allows, so a too-wide request returns the
// longest available slice + a note.
async function buildHttpStats(acc: Account, r: HttpRange) {
  const limits = await httpLimitsSeconds(acc, r.zoneTag);
  const adaptive = limits.adaptive.maxRangeSeconds > 0
    ? limits.adaptive
    : fallbackDatasetWindow(HTTP_ADAPTIVE_FALLBACK_SECONDS);
  const hourly = limits.hourly.maxRangeSeconds > 0
    ? limits.hourly
    : fallbackDatasetWindow(HTTP_HOURLY_FALLBACK_SECONDS);
  const daily = limits.daily.maxRangeSeconds > 0
    ? limits.daily
    : fallbackDatasetWindow(HTTP_DAILY_FALLBACK_SECONDS);
  const maxRangeSeconds =
    limits.maxRangeSeconds > 0
      ? limits.maxRangeSeconds
      : Math.max(adaptive.maxRangeSeconds, hourly.maxRangeSeconds, daily.maxRangeSeconds);

  const untilMs = Date.parse(r.untilIso);
  const sinceMs = Date.parse(r.sinceIso);
  const requestedSeconds =
    Number.isFinite(untilMs) && Number.isFinite(sinceMs) ? Math.max(0, Math.round((untilMs - sinceMs) / 1000)) : 0;
  const nowMs = Date.now();
  const candidates: { tier: "adaptive" | "hourly" | "daily"; window: DatasetWindow }[] = [
    { tier: "adaptive", window: adaptive },
    { tier: "hourly", window: hourly },
    { tier: "daily", window: daily },
  ];
  const supports = ({ window }: (typeof candidates)[number]) =>
    requestedSeconds <= window.maxDurationSeconds &&
    sinceMs >= nowMs - window.notOlderThanSeconds * 1000;
  let selected = candidates.find(supports);
  let clamped = false;
  if (!selected) {
    const eligible = candidates
      .filter(({ window }) => untilMs >= nowMs - window.notOlderThanSeconds * 1000)
      .sort((a, b) => b.window.notOlderThanSeconds - a.window.notOlderThanSeconds);
    selected = eligible[0];
    if (!selected) throw new HttpError(400, "requested HTTP range is outside retained data");
    const earliestMs = Math.max(
      nowMs - selected.window.notOlderThanSeconds * 1000,
      untilMs - selected.window.maxDurationSeconds * 1000,
    );
    if (earliestMs > sinceMs) {
      r = { ...r, sinceIso: new Date(earliestMs).toISOString() };
      clamped = true;
    }
  }
  const tier = selected.tier;
  let effectiveSeconds = Math.max(0, Math.round((untilMs - Date.parse(r.sinceIso)) / 1000));
  let calendarDays: number | null = null;
  if (tier === "daily") {
    const aligned = alignDailyRange(r, effectiveSeconds);
    r = aligned.range;
    calendarDays = aligned.calendarDays;
    effectiveSeconds = calendarDays * DAY_SECONDS;
  }

  const body =
    tier === "adaptive"
      ? await buildHttpStatsAdaptive(acc, r)
      : tier === "hourly"
        ? await buildHttpStatsRollup(acc, r, "httpRequests1hGroups", HOURLY_CONVENTIONS)
        : await buildHttpStatsRollup(acc, r, "httpRequests1dGroups", DAILY_CONVENTIONS);
  return {
    ...body,
    dataset: tier,
    range: {
      requestedSeconds,
      effectiveSeconds,
      clamped,
      maxRangeSeconds,
      calendarDays,
      effectiveSince: r.sinceIso,
      effectiveUntil: r.untilIso,
    },
  };
}

// Short windows: fine-grained adaptive dataset, scoped to eyeball, with every breakdown.
async function buildHttpStatsAdaptive(acc: Account, r: HttpRange) {
  // Minute resolution for short windows, hourly otherwise — both are always-available time dimensions.
  const hours = (Date.parse(r.untilIso) - Date.parse(r.sinceIso)) / 3_600_000;
  const timeDim = hours <= 2 ? "datetimeMinute" : "datetimeHour";

  // Core breakdowns must succeed (they back the primary charts); the rest are best-effort.
  const [core, byContentType, byHttpVersion, byCacheStatus, perf] = await Promise.all([
    httpCore(acc, r, timeDim),
    // Content type is NOT a dimension on httpRequestsAdaptiveGroups — Cloudflare only exposes it via
    // the roll-up `contentTypeMap` (same as their own dashboard). Pull it from httpRequests1hGroups.
    rollupMap(acc, r, "httpRequests1hGroups", ROLLUP_DATETIME_CONV, "contentTypeMap", "edgeResponseContentTypeName", 30),
    httpGroupBy(acc, r, "clientRequestHTTPProtocol", { limit: 20, bytes: false, optional: true }),
    httpGroupBy(acc, r, "cacheStatus", { limit: 20, optional: true }),
    httpPerf(acc, r, timeDim),
  ]);
  const { series, byCountry, byStatus, byHost, byPath } = core;

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
    totals: { ...totals, uniqueIps: null, cachedPct },
  };
}

// Roll-up datasets (httpRequests1hGroups hourly, httpRequests1dGroups daily). `count` is N/A on
// roll-up tables, so requests come from sum.requests and breakdowns from the pre-aggregated *Map
// fields. Per-path / per-host / performance aren't in the roll-up, so those return empty (the UI
// hides those panels). The time dimension + filter key differ by dataset/schema version, so each
// builder is given the conventions to try; `dateOnly` trims the filter value to YYYY-MM-DD (the daily
// dataset filters on a Date, not a DateTime).
type RollupConv = { dim: string; filterKey: string; dateOnly: boolean };
// Classic roll-up tables (httpRequests1hGroups / 1mGroups) filter on `datetime_geq/leq` with the
// `datetime` dimension — confirmed by Cloudflare's own prometheus-exporter. Used as the primary
// convention and for the adaptive view's content-type lookup (which has no adaptive dimension).
const ROLLUP_DATETIME_CONV: RollupConv = { dim: "datetime", filterKey: "datetime", dateOnly: false };
const HOURLY_CONVENTIONS: RollupConv[] = [
  ROLLUP_DATETIME_CONV,
  { dim: "datetimeHour", filterKey: "datetimeHour", dateOnly: false },
];
const DAILY_CONVENTIONS: RollupConv[] = [{ dim: "date", filterKey: "date", dateOnly: true }];

const rollupFilter = (r: HttpRange, conv: RollupConv) => {
  const v = (iso: string) => (conv.dateOnly ? iso.slice(0, 10) : iso);
  return `{ ${conv.filterKey}_geq: "${v(r.sinceIso)}", ${conv.filterKey}_leq: "${v(r.untilIso)}" }`;
};

// One pre-aggregated breakdown map (e.g. countryMap) summed across all timeslots. Best-effort — a
// schema mismatch on the map/field name returns [] so the rest of the roll-up view keeps working.
async function rollupMap(
  acc: Account,
  r: HttpRange,
  dataset: string,
  conv: RollupConv,
  mapNode: string,
  keyField: string,
  limit: number,
): Promise<HttpGroup[]> {
  const query = /* GraphQL */ `
    query RollupMap($zoneTag: String!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          g: ${dataset}(filter: ${rollupFilter(r, conv)}, limit: 1000) {
            sum { ${mapNode} { ${keyField} requests } }
          }
        }
      }
    }
  `;
  try {
    type Resp = { viewer: { zones: { g: any[] }[] } };
    const data = await gql<Resp>(acc, query, { zoneTag: r.zoneTag });
    const groups = data.viewer.zones[0]?.g ?? [];
    const m = new Map<string, number>();
    for (const g of groups) {
      for (const e of (g.sum?.[mapNode] ?? []) as any[]) {
        const k = String(e?.[keyField] ?? "");
        if (k === "") continue;
        m.set(k, (m.get(k) ?? 0) + (Number(e?.requests) || 0));
      }
    }
    return [...m.entries()]
      .map(([key, requests]) => ({ key, requests, bytes: 0 }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, limit);
  } catch {
    return [];
  }
}

async function buildHttpStatsRollup(acc: Account, r: HttpRange, dataset: string, conventions: RollupConv[]) {
  // The time dimension + filter key differ by dataset/schema version — try the candidates and reuse
  // whichever worked for the breakdown queries.
  let series: { t: string; requests: number; bytes: number; cached: number }[] = [];
  let uniqueIps: number | null = null;
  let conv: RollupConv | null = null;
  let lastErr: unknown = null;
  for (const c of conventions) {
    const query = /* GraphQL */ `
      query RollupSeries($zoneTag: String!) {
        viewer {
          zones(filter: { zoneTag: $zoneTag }) {
            series: ${dataset}(filter: ${rollupFilter(r, c)}, limit: 1000, orderBy: [${c.dim}_ASC]) {
              dimensions { ${c.dim} }
              sum { requests bytes cachedRequests }
            }
            total: ${dataset}(filter: ${rollupFilter(r, c)}, limit: 1) {
              uniq { uniques }
            }
          }
        }
      }
    `;
    try {
      type Resp = { viewer: { zones: { series: any[]; total: any[] }[] } };
      const data = await gql<Resp>(acc, query, { zoneTag: r.zoneTag });
      const zone = data.viewer.zones[0];
      const groups = zone?.series ?? [];
      series = groups.map((g) => ({
        t: g.dimensions?.[c.dim] as string,
        requests: Number(g.sum?.requests) || 0,
        bytes: Number(g.sum?.bytes) || 0,
        cached: Number(g.sum?.cachedRequests) || 0,
      }));
      const rawUniques = zone?.total?.[0]?.uniq?.uniques;
      uniqueIps = rawUniques == null ? null : Number(rawUniques) || 0;
      conv = c;
      break;
    } catch (e) {
      lastErr = e;
    }
  }
  if (!conv) throw lastErr ?? new HttpError(502, "roll-up query failed");

  const totals = series.reduce(
    (a, s) => {
      a.requests += s.requests;
      a.bytes += s.bytes;
      a.cached += s.cached;
      return a;
    },
    { requests: 0, bytes: 0, cached: 0 },
  );
  const cachedPct = totals.requests ? (totals.cached / totals.requests) * 100 : null;
  const byCacheStatus: HttpGroup[] = totals.requests
    ? [
        { key: "cached", requests: totals.cached, bytes: 0 },
        { key: "uncached", requests: Math.max(0, totals.requests - totals.cached), bytes: 0 },
      ]
    : [];

  const [byCountry, byStatus, byContentType, byHttpVersion] = await Promise.all([
    rollupMap(acc, r, dataset, conv, "countryMap", "clientCountryName", 50),
    rollupMap(acc, r, dataset, conv, "responseStatusMap", "edgeResponseStatus", 50),
    rollupMap(acc, r, dataset, conv, "contentTypeMap", "edgeResponseContentTypeName", 30),
    rollupMap(acc, r, dataset, conv, "clientHTTPVersionMap", "clientHTTPProtocol", 20),
  ]);

  return {
    timeDim: conv.dim,
    series: series.map(({ t, requests, bytes }) => ({ t, requests, bytes })),
    byCountry,
    byStatus,
    byHost: [] as HttpGroup[],
    byPath: [] as HttpGroup[],
    byContentType,
    byHttpVersion,
    byCacheStatus,
    perf: null,
    totals: { requests: totals.requests, bytes: totals.bytes, visits: null, uniqueIps, cachedPct },
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

// Per-zone/plan limits for the HTTP dataset, queried from the GraphQL Settings node. Unlike WAF
// events (24 h on Free), httpRequestsAdaptiveGroups is retained much longer — and exactly how long
// depends on the zone's plan, so we ask Cloudflare instead of hard-coding a guess. The dashboard
// uses this to populate the time-range dropdown with everything the zone is actually allowed to read.
async function getHttpSettings(acc: Account, url: URL): Promise<Response> {
  const zone = url.searchParams.get("zone");
  if (!zone) throw new HttpError(400, "missing 'zone' query parameter");
  const limits = await httpLimitsSeconds(acc, zone);
  return json(limits, {
    headers: { "cache-control": limits.maxRangeSeconds > 0 ? "private, max-age=300" : "no-store" },
  });
}

async function getWafSettings(acc: Account, url: URL): Promise<Response> {
  const zone = url.searchParams.get("zone");
  if (!zone) throw new HttpError(400, "missing 'zone' query parameter");
  const limit = await wafLimitSeconds(acc, zone);
  return json(limit, {
    headers: { "cache-control": limit.source === "cloudflare" ? "private, max-age=300" : "no-store" },
  });
}

// ── Cloudflare Access verification ──────────────────────────────────────────────
// Production API requests require a valid Access JWT. The only bypass is an explicit development
// flag on a loopback URL; setting that flag on a deployed Worker cannot disable authentication.

type AccessJwk = { kid?: string; n?: string; e?: string };
type JwksCacheEntry = { keys: AccessJwk[]; exp: number; lastForcedRefreshAt: number };
const jwksCache = new Map<string, JwksCacheEntry>();
const JWKS_TTL_MS = 3_600_000;
const JWKS_UNKNOWN_KID_REFRESH_MS = 60_000;

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

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "localhost" || normalized === "::1") return true;
  const octets = normalized.split(".");
  return (
    octets.length === 4 &&
    octets[0] === "127" &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
  );
}

async function getAccessJwks(teamDomain: string, refresh = false): Promise<AccessJwk[]> {
  const now = Date.now();
  const cached = jwksCache.get(teamDomain);
  if (cached && cached.exp > now) {
    if (!refresh || now - cached.lastForcedRefreshAt < JWKS_UNKNOWN_KID_REFRESH_MS) return cached.keys;
  }
  const res = await timedFetch(`${teamDomain}/cdn-cgi/access/certs`, { method: "GET" });
  if (!res.ok) throw new HttpError(403, "unable to fetch Access signing keys");
  const body = (await res.json()) as { keys?: AccessJwk[] };
  const keys = body.keys ?? [];
  jwksCache.set(teamDomain, {
    keys,
    exp: now + JWKS_TTL_MS,
    lastForcedRefreshAt: refresh ? now : cached?.lastForcedRefreshAt ?? 0,
  });
  return keys;
}

async function verifyAccess(env: Env, request: Request): Promise<void> {
  const rawTeam = typeof env.CF_ACCESS_TEAM_DOMAIN === "string" ? env.CF_ACCESS_TEAM_DOMAIN.trim() : "";
  const aud = typeof env.CF_ACCESS_AUD === "string" ? env.CF_ACCESS_AUD.trim() : "";
  const allowLocal =
    env.ALLOW_UNAUTHENTICATED_LOCAL_DEV === "true" && isLoopbackHostname(new URL(request.url).hostname);
  if (!rawTeam || !aud) {
    if (!rawTeam && !aud && allowLocal) return;
    throw new HttpError(503, "Cloudflare Access verification is not configured");
  }

  let teamUrl: URL;
  try {
    teamUrl = new URL(rawTeam.includes("://") ? rawTeam : `https://${rawTeam}`);
  } catch {
    throw new HttpError(503, "invalid Cloudflare Access team domain");
  }
  if (
    teamUrl.protocol !== "https:" ||
    teamUrl.username ||
    teamUrl.password ||
    (teamUrl.pathname !== "/" && teamUrl.pathname !== "") ||
    teamUrl.search ||
    teamUrl.hash
  ) {
    throw new HttpError(503, "invalid Cloudflare Access team domain");
  }
  const teamDomain = teamUrl.origin;

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

  let jwk = (await getAccessJwks(teamDomain)).find((k) => k.kid === header.kid);
  if (!jwk) {
    jwk = (await getAccessJwks(teamDomain, true)).find((k) => k.kid === header.kid);
  }
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
      // Always revalidate assets so a redeploy takes effect immediately instead of serving a stale
      // app.js/index.html from the browser or edge cache (the dashboard is small — 304s are cheap).
      headers.set("cache-control", "no-cache");
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
      if (url.pathname === "/api/http-settings") return await getHttpSettings(account, url);
      if (url.pathname === "/api/waf-settings") return await getWafSettings(account, url);
      if (url.pathname === "/api/export.csv") return await exportCsv(account, parseFilters(url));

      return err(404, "not found");
    } catch (e) {
      if (e instanceof HttpError) return err(e.status, e.message);
      console.error("Unhandled API error:", e);
      return err(500, "internal server error");
    }
  },
} satisfies ExportedHandler<Env>;
