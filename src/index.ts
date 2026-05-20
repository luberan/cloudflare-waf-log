/**
 * Cloudflare Worker — WAF events dashboard (multi-account)
 *
 * Endpoints:
 *   GET /api/accounts                              → seznam nakonfigurovaných účtů (id + label)
 *   GET /api/zones?account=<id>                    → seznam zón daného účtu
 *   GET /api/log?account=<id>&zone=<id>&...        → individuální eventy (firewallEventsAdaptive)
 *   GET /api/stats?account=<id>&zone=<id>&...      → agregace (firewallEventsAdaptiveGroups)
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

  type Resp = { viewer: { zones: { firewallEventsAdaptive: any[] }[] } };
  const data = await gql<Resp>(acc, query, { zoneTag: f.zoneTag, limit, filter });
  return data.viewer.zones[0]?.firewallEventsAdaptive ?? [];
}

async function getEvents(acc: Account, f: Filters): Promise<Response> {
  const events = await fetchEvents(acc, f, f.limit ?? 200);
  return json({ events });
}

async function getSummary(acc: Account, f: Filters): Promise<Response> {
  // Pozn.: na Free tieru NENÍ dostupný firewallEventsAdaptiveGroups (vyžaduje Pro+).
  // Stažneme tedy raw eventy (limit 10000 = HW limit) a agregujeme tady v Workeru.
  const events = await fetchEvents(acc, f, 10000);

  const counter = (key: (e: any) => string | undefined) => {
    const m = new Map<string, number>();
    for (const e of events) {
      const k = key(e) ?? "(unknown)";
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()]
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => b.count - a.count);
  };

  const byAction = counter((e) => e.action);
  const byCountry = counter((e) => e.clientCountryName).slice(0, 50);
  const byHost = counter((e) => e.clientRequestHTTPHost).slice(0, 50);
  const byPath = counter((e) => e.clientRequestPath).slice(0, 50);
  const bySource = counter((e) => e.source);
  const byRule = counter((e) => e.ruleId).slice(0, 50);

  // Time series po hodinách, per akce
  const seriesMap = new Map<string, number>(); // klic: "hour|action"
  for (const e of events) {
    const hour = (e.datetime as string).slice(0, 13) + ":00:00Z";
    const k = `${hour}|${e.action}`;
    seriesMap.set(k, (seriesMap.get(k) ?? 0) + 1);
  }
  const series = [...seriesMap.entries()].map(([k, count]) => {
    const [hour, action] = k.split("|");
    return { hour, action, count };
  });
  series.sort((a, b) => a.hour.localeCompare(b.hour));

  return json({
    byAction,
    byCountry,
    byHost,
    byPath,
    bySource,
    byRule,
    series,
    events: events.slice(0, 500),
    totalSampled: events.length,
    truncated: events.length >= 10000,
  });
}

async function debug(acc: Account): Promise<Response> {
  const out: Record<string, unknown> = {
    configured: { id: acc.id, label: acc.label, accountIdInSecret: acc.accountId },
  };

  // 1) verify token
  try {
    const r = await fetch(`${CF_API}/user/tokens/verify`, {
      headers: { authorization: `Bearer ${acc.token}` },
    });
    out.tokenVerify = await r.json();
  } catch (e) {
    out.tokenVerify = { error: String(e) };
  }

  // 2) accounts visible to token
  try {
    const r = await fetch(`${CF_API}/accounts?per_page=20`, {
      headers: { authorization: `Bearer ${acc.token}` },
    });
    const j = (await r.json()) as { result?: { id: string; name: string }[] };
    out.accountsVisibleToToken = j.result?.map((a) => ({ id: a.id, name: a.name }));
  } catch (e) {
    out.accountsVisibleToToken = { error: String(e) };
  }

  // 3) zones in configured account
  let firstZone: string | undefined;
  try {
    const r = await fetch(
      `${CF_API}/zones?account.id=${encodeURIComponent(acc.accountId)}&per_page=10`,
      { headers: { authorization: `Bearer ${acc.token}` } },
    );
    const j = (await r.json()) as {
      result?: { id: string; name: string; account: { id: string; name: string } }[];
    };
    out.zonesInConfiguredAccount = j.result?.map((z) => ({
      id: z.id,
      name: z.name,
      accountId: z.account.id,
      accountName: z.account.name,
    }));
    firstZone = j.result?.[0]?.id;
  } catch (e) {
    out.zonesInConfiguredAccount = { error: String(e) };
  }

  // 4) GraphQL test on first zone
  if (firstZone) {
    try {
      const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
      const until = new Date().toISOString();
      const body = JSON.stringify({
        query: `{ viewer { zones(filter:{zoneTag:"${firstZone}"}) { firewallEventsAdaptiveGroups(filter:{datetime_geq:"${since}",datetime_leq:"${until}"},limit:1) { count } } } }`,
      });
      const r = await fetch(CF_GRAPHQL, {
        method: "POST",
        headers: { authorization: `Bearer ${acc.token}`, "content-type": "application/json" },
        body,
      });
      out.graphqlTest = { zone: firstZone, response: await r.json() };
    } catch (e) {
      out.graphqlTest = { error: String(e) };
    }
  }

  return json(out);
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
      if (url.pathname === "/api/debug") return await debug(account);

      return err(404, "not found");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return err(400, msg);
    }
  },
} satisfies ExportedHandler<Env>;
