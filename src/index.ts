/**
 * Cloudflare Worker — WAF events dashboard (multi-account)
 *
 * Endpoints:
 *   GET /api/accounts                              → seznam nakonfigurovaných účtů (id + label)
 *   GET /api/zones?account=<id>                    → seznam zón daného účtu
 *   GET /api/log?account=<id>&zone=<id>&...        → individuální eventy (firewallEventsAdaptive)
 *   GET /api/stats?account=<id>&zone=<id>&...      → agregace (firewallEventsAdaptiveGroups)
 *
 * Pozn.: cesty se záměrně nejmenují /api/events ani /api/summary — ty by blokovaly
 * běžné adblockery (EasyPrivacy).
 *
 * Konfigurace (vše jako Worker secret — nic v plaintextu v repu):
 *   ACCOUNTS = JSON pole, např.
 *     [
 *       { "id": "personal", "label": "Můj účet",  "accountId": "abc123…", "token": "cf_xxx" },
 *       { "id": "acme",     "label": "ACME s.r.o.","accountId": "def456…", "token": "cf_yyy" }
 *     ]
 *   - `id`        — interní klíč použitý v query stringu (krátký, bez mezer)
 *   - `label`     — co se ukáže v UI
 *   - `accountId` — Cloudflare Account ID
 *   - `token`     — API token s právy: Account Analytics: Read, Zone: Read, Analytics: Read
 *
 * Ochrana přístupu k samotnému dashboardu se neřeší v kódu — Worker je za Cloudflare Access.
 */

export interface Env {
  ASSETS: Fetcher;
  ACCOUNTS: string; // JSON string (Worker secret)
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
  if (!env.ACCOUNTS) throw new Error("ACCOUNTS secret is not set");
  let parsed: unknown;
  try {
    parsed = JSON.parse(env.ACCOUNTS);
  } catch {
    throw new Error("ACCOUNTS secret is not valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error("ACCOUNTS must be a non-empty JSON array");
  }
  const accounts = parsed as Partial<Account>[];
  for (const a of accounts) {
    if (!a.id || !a.label || !a.accountId || !a.token) {
      throw new Error("Each account needs 'id', 'label', 'accountId', 'token'");
    }
  }
  return accounts as Account[];
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

async function getEvents(acc: Account, f: Filters): Promise<Response> {
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
  if (f.source?.length) filter.source_in = f.source;

  type Resp = { viewer: { zones: { firewallEventsAdaptive: unknown[] }[] } };
  const data = await gql<Resp>(acc, query, {
    zoneTag: f.zoneTag,
    limit: f.limit ?? 200,
    filter,
  });
  return json({ events: data.viewer.zones[0]?.firewallEventsAdaptive ?? [] });
}

async function getSummary(acc: Account, f: Filters): Promise<Response> {
  const baseFilter: Record<string, unknown> = {
    datetime_geq: f.datetimeGeq,
    datetime_leq: f.datetimeLeq,
  };
  if (f.action?.length) baseFilter.action_in = f.action;
  if (f.clientCountryName?.length) baseFilter.clientCountryName_in = f.clientCountryName;
  if (f.clientRequestHTTPHost?.length) baseFilter.clientRequestHTTPHost_in = f.clientRequestHTTPHost;
  if (f.source?.length) baseFilter.source_in = f.source;

  const groupQuery = (dim: string) => /* GraphQL */ `
    query G($zoneTag: String!, $filter: ZoneFirewallEventsAdaptiveGroupsFilter_InputObject) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          firewallEventsAdaptiveGroups(
            filter: $filter
            limit: 50
            orderBy: [count_DESC]
          ) {
            count
            dimensions { ${dim} }
          }
        }
      }
    }
  `;

  type GroupResp = {
    viewer: {
      zones: { firewallEventsAdaptiveGroups: { count: number; dimensions: Record<string, string> }[] }[];
    };
  };

  async function group(dim: string) {
    const data = await gql<GroupResp>(acc, groupQuery(dim), { zoneTag: f.zoneTag, filter: baseFilter });
    return (data.viewer.zones[0]?.firewallEventsAdaptiveGroups ?? []).map((g) => ({
      key: g.dimensions[dim] ?? "(unknown)",
      count: g.count,
    }));
  }

  const seriesQuery = /* GraphQL */ `
    query S($zoneTag: String!, $filter: ZoneFirewallEventsAdaptiveGroupsFilter_InputObject) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          firewallEventsAdaptiveGroups(
            filter: $filter
            limit: 500
            orderBy: [datetimeHour_ASC]
          ) {
            count
            dimensions { datetimeHour action }
          }
        }
      }
    }
  `;
  const seriesP = gql<GroupResp>(acc, seriesQuery, { zoneTag: f.zoneTag, filter: baseFilter }).then((d) =>
    (d.viewer.zones[0]?.firewallEventsAdaptiveGroups ?? []).map((g) => ({
      hour: g.dimensions.datetimeHour,
      action: g.dimensions.action,
      count: g.count,
    })),
  );

  const [byAction, byCountry, byHost, bySource, byRule, series] = await Promise.all([
    group("action"),
    group("clientCountryName"),
    group("clientRequestHTTPHost"),
    group("source"),
    group("ruleId"),
    seriesP,
  ]);

  return json({ byAction, byCountry, byHost, bySource, byRule, series });
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

      return err(404, "not found");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return err(400, msg);
    }
  },
} satisfies ExportedHandler<Env>;
