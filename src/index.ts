/**
 * Cloudflare Worker — WAF events dashboard (multi-account)
 *
 * Endpoints:
 *   GET /api/accounts                              → seznam nakonfigurovaných účtů (id + label)
 *   GET /api/zones?account=<id>                    → seznam zón daného účtu
 *   GET /api/log?account=<id>&zone=<id>&...        → individuální eventy (firewallEventsAdaptive)
 *   GET /api/stats?account=<id>&zone=<id>&...      → agregace (firewallEventsAdaptiveGroups)
 *   GET /api/export.csv?account=<id>&zone=<id>&... → CSV export raw eventů (až 10 000 řádků)
 *
 * Konfigurace (vše jako Worker secrets — nic v repu):
 *   Pro každý CF účet vytvoř TŘI secrety:
 *     CFACC_<ID>_LABEL     – co se ukáže v UI dropdownu (např. "ACME s.r.o.")
 *     CFACC_<ID>_ACCOUNT   – Cloudflare Account ID (32 hex znaků)
 *     CFACC_<ID>_TOKEN     – Cloudflare API token (read-only)
 *   <ID> je libovolný krátký identifikátor [A-Z0-9_], objeví se v URL ?account=<id>.
 *
 *   Příklad — dva účty:
 *     CFACC_PERSONAL_LABEL   = "Můj účet"
 *     CFACC_PERSONAL_ACCOUNT = "abc123..."
 *     CFACC_PERSONAL_TOKEN   = "cf_xxx"
 *     CFACC_ACME_LABEL       = "ACME s.r.o."
 *     CFACC_ACME_ACCOUNT     = "def456..."
 *     CFACC_ACME_TOKEN       = "cf_yyy"
 *
 *   Přidání nového účtu = jen 3 nové secrety, nic existujícího se nemění.
 *   Rotace tokenu = přepsat jen CFACC_<ID>_TOKEN.
 *
 * Ochrana přístupu k samotnému dashboardu se neřeší v kódu — Worker je za Cloudflare Access.
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
  return out.sort((a, b) => a.label.localeCompare(b.label, "cs"));
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

// Cache TTL pro stažené eventy v Worker Cache API. Krátká TTL = data zůstávají
// "čerstvá" (max 60s zpoždění), ale rapid facet-toggle UX je instantní.
const EVENTS_CACHE_TTL_SECONDS = 300;

async function cachedFetchEvents(
  acc: Account,
  f: Filters,
  limit: number,
): Promise<{ events: any[]; cacheState: "HIT" | "MISS" | "BYPASS" }> {
  const cache = (caches as unknown as { default?: Cache }).default;
  if (!cache) {
    // Cache API není k dispozici (např. v testech) → fallback bez cache.
    const events = await fetchEvents(acc, f, limit);
    return { events, cacheState: "BYPASS" };
  }

  // Cache key — sjednotí všechny rozlišující atributy outer fetche.
  // Účet je část keye (token rozdíl + accountId rozdíl); zone/time/action/source taky.
  // Časové hranice zaokrouhlujeme na 5min buckety — frontend posílá `new Date().toISOString()`
  // s ms přesností, takže bez bucketu by každý request měl unikátní key a cache by nikdy nehitla.
  // 5min = stejně dlouhé jako TTL → během cache lifetime všechny toggle requesty hitnou stejný klíč.
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
  // ctx.waitUntil by bylo ideálnější (necháváme pokračovat request), ale Cache.put
  // je v Workeru rychlý write do edge cache — pár ms — takže await je v pořádku.
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
  // Pozn.: na Free tieru NENÍ dostupný firewallEventsAdaptiveGroups (vyžaduje Pro+).
  // Stáhneme tedy raw eventy (limit 10000 = HW limit) a agregujeme tady v Workeru.
  //
  // Drill-down facety (country, host, path, rule, asn, ua) aplikujeme AŽ v JS, aby každá
  // facetová tabulka mohla ukázat všechny možnosti i když je některá z nich aktivním filtrem
  // (typický facet-search UX: výběr v jedné facetě nesmí vymazat ostatní možnosti tamtéž).
  // Server-side filtrujeme jen action, source, zone, datetime — ty nemají drill-down UI.
  //
  // Cache: outer fetch (zone+time+action+source) cachujeme v Worker Cache API. Facet toggle
  // = identický outer fetch → cache HIT → skípne se CF GraphQL roundtrip (typicky 500–2000ms).
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

  // Time series po hodinách, per akce — z filtrované sady.
  const seriesMap = new Map<string, number>(); // klic: "hour|action"
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
      const msg = e instanceof Error ? e.message : String(e);
      return err(400, msg);
    }
  },
} satisfies ExportedHandler<Env>;
