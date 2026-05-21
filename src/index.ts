/**
 * Cloudflare Worker — WAF events dashboard (multi-account)
 *
 * Endpoints:
 *   GET /api/accounts                              → list of configured accounts (id + label)
 *   GET /api/zones?account=<id>                    → list of zones for the given account
 *   GET /api/log?account=<id>&zone=<id>&...        → individual events (firewallEventsAdaptive)
 *   GET /api/stats?account=<id>&zone=<id>&...      → aggregations (firewallEventsAdaptive, client-side grouped)
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
 * Access protection of the dashboard itself is not handled in code — the Worker sits behind Cloudflare Access.
 */

export interface Env {
  ASSETS: Fetcher;
  [key: string]: unknown; // CFACC_*_LABEL / _ACCOUNT / _TOKEN
}

type Account = {
  id: string;
  label: string;
  accountId: string;
  token: string;
};

const CF_API = "https://api.cloudflare.com/client/v4";
const CF_GRAPHQL = "https://api.cloudflare.com/client/v4/graphql";

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
      ...(init.headers || {}),
    },
  });
}

function err(status: number, message: string): Response {
  return json({ error: message }, { status });
}

function loadAccounts(env: Env): Account[] {
  const ids = new Set<string>();
  for (const key of Object.keys(env)) {
    const m = key.match(/^CFACC_([A-Z0-9_]+)_(LABEL|ACCOUNT|TOKEN)$/i);
    if (m) ids.add(m[1].toUpperCase());
  }
  const out: Account[] = [];
  const incomplete: string[] = [];
  for (const id of ids) {
    const label = env[`CFACC_${id}_LABEL`];
    const accountId = env[`CFACC_${id}_ACCOUNT`];
    const token = env[`CFACC_${id}_TOKEN`];
    if (typeof label === "string" && typeof accountId === "string" && typeof token === "string") {
      out.push({ id: id.toLowerCase(), label, accountId, token });
    } else {
      incomplete.push(id);
    }
  }
  if (out.length === 0) {
    throw new Error(
      incomplete.length
        ? `Account(s) ${incomplete.join(", ")} are missing one of LABEL/ACCOUNT/TOKEN secrets`
        : "No accounts configured — set CFACC_<ID>_LABEL, _ACCOUNT, _TOKEN as Worker secrets",
    );
  }
  return out.sort((a, b) => a.label.localeCompare(b.label));
}

function pickAccount(env: Env, url: URL): Account {
  const id = url.searchParams.get("account");
  if (!id) throw new Error("missing 'account' query parameter");
  const acc = loadAccounts(env).find((a) => a.id === id);
  if (!acc) throw new Error(`unknown account '${id}'`);
  return acc;
}

function parseFilters(url: URL): Filters {
  const zone = url.searchParams.get("zone");
  if (!zone) throw new Error("missing 'zone' query parameter");

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
  const res = await fetch(`${CF_API}${path}`, {
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
  const res = await fetch(CF_GRAPHQL, {
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
  const accounts = loadAccounts(env).map((a) => ({ id: a.id, label: a.label }));
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
  const filename = `waf-${acc.id}-${f.zoneTag.slice(0, 8)}-${stamp}.csv`;
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
  const matches = (e: any, exclude?: Facet): boolean => {
    if (exclude !== "country" && f.clientCountryName?.length && !f.clientCountryName.includes(e.clientCountryName)) return false;
    if (exclude !== "host" && f.clientRequestHTTPHost?.length && !f.clientRequestHTTPHost.includes(e.clientRequestHTTPHost)) return false;
    if (exclude !== "path" && f.clientRequestPath?.length && !f.clientRequestPath.includes(e.clientRequestPath)) return false;
    if (exclude !== "rule" && f.ruleId?.length && !f.ruleId.includes(e.ruleId)) return false;
    if (exclude !== "asn" && f.clientAsn?.length && !f.clientAsn.includes(e.clientAsn)) return false;
    if (exclude !== "ua" && f.userAgent?.length && !f.userAgent.includes(e.userAgent)) return false;
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

// ── Entrypoint ────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      if (url.pathname === "/api/accounts") return listAccounts(env);

      const account = pickAccount(env, url);

      if (url.pathname === "/api/zones") return await listZones(account);
      if (url.pathname === "/api/log") return await getEvents(account, parseFilters(url));
      if (url.pathname === "/api/stats") return await getSummary(account, parseFilters(url));
      if (url.pathname === "/api/export.csv") return await exportCsv(account, parseFilters(url));

      return err(404, "not found");
    } catch (e) {
      console.error("Unhandled API error:", e);
      return err(500, "internal server error");
    }
  },
} satisfies ExportedHandler<Env>;
