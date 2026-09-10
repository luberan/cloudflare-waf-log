import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { alignDailyRange, parseFilters, parseHttpRange } from "../src/index";

const hour = 60 * 60 * 1000;

describe("deployment configuration", () => {
  it("preserves dashboard-defined runtime variables during deploy", () => {
    const config = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");

    expect(config).toMatch(/"keep_vars"\s*:\s*true/);
  });

  it("keeps default and preview hostnames disabled without an authentication bypass mode", () => {
    const config = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");

    expect(config).not.toMatch(/"AUTH_MODE"\s*:/);
    expect(config).toMatch(/"workers_dev"\s*:\s*false/);
    expect(config).toMatch(/"preview_urls"\s*:\s*false/);
  });
});

function timeParams(hours = 1): URLSearchParams {
  const until = new Date(Date.now() - hour);
  const since = new Date(until.getTime() - hours * hour);
  return new URLSearchParams({ since: since.toISOString(), until: until.toISOString() });
}

function configuredEnv(extra: Record<string, unknown> = {}) {
  return {
    ASSETS: { fetch: vi.fn(async () => new Response("asset")) },
    ALLOW_UNAUTHENTICATED_LOCAL_DEV: "true",
    CFACC_TEST_LABEL: "Test account",
    CFACC_TEST_ACCOUNT: "00000000000000000000000000000000",
    CFACC_TEST_TOKEN: "test-token",
    ...extra,
  } as any;
}

function zoneDetailsResponse(input: unknown, accountId = "00000000000000000000000000000000") {
  const url = new URL(String(input));
  const prefix = "/client/v4/zones/";
  if (!url.pathname.startsWith(prefix)) return undefined;
  return Response.json({
    success: true,
    result: { id: decodeURIComponent(url.pathname.slice(prefix.length)), account: { id: accountId } },
  });
}

describe("API validation", () => {
  it("preserves commas in repeated path and user-agent filters", () => {
    const params = timeParams();
    params.set("zone", "zone-filter-values");
    params.append("path", "/a,b");
    params.append("path", "/second");
    params.set("ua", "Bot/1.0 (alpha, beta)");
    params.set("asn", "AS13335");

    const filters = parseFilters(new URL(`https://dashboard.test/api/stats?${params}`));

    expect(filters.clientRequestPath).toEqual(["/a,b", "/second"]);
    expect(filters.userAgent).toEqual(["Bot/1.0 (alpha, beta)"]);
    expect(filters.clientAsn).toEqual([13335]);
  });

  it("rejects invalid and reversed timestamps", () => {
    expect(() => parseHttpRange(new URL("https://dashboard.test/api/http-stats?zone=z&since=bad"))).toThrow(
      "invalid 'since' timestamp",
    );
    expect(() =>
      parseHttpRange(
        new URL(
          "https://dashboard.test/api/http-stats?zone=z&since=2026-08-10T11:00:00Z&until=2026-08-10T10:00:00Z",
        ),
      ),
    ).toThrow("'since' must be earlier than 'until'");
  });

  it("rejects non-decimal ASN syntax", () => {
    const params = timeParams();
    params.set("zone", "zone-asn-format");
    params.set("asn", "1e3");

    expect(() => parseFilters(new URL(`https://dashboard.test/api/stats?${params}`))).toThrow(
      "invalid 'asn' filter value",
    );
  });

  it.each(["0", "AS0", "AS000"])("accepts unknown ASN %s and normalizes country filters", (asn) => {
    const params = timeParams();
    params.set("zone", "zone-unknown-asn");
    params.set("asn", asn);
    params.set("country", "us,cz");
    const filters = parseFilters(new URL(`https://dashboard.test/api/stats?${params}`));

    expect(filters.clientAsn).toEqual([0]);
    expect(filters.clientCountryName).toEqual(["US", "CZ"]);
  });

  it("aligns a seven-day daily query to exactly seven calendar buckets", () => {
    const aligned = alignDailyRange(
      {
        zoneTag: "zone-daily-range",
        sinceIso: "2026-08-03T11:30:00.000Z",
        untilIso: "2026-08-10T11:30:00.000Z",
      },
      7 * 24 * 60 * 60,
    );

    expect(aligned.calendarDays).toBe(7);
    expect(aligned.range.sinceIso).toBe("2026-08-04T00:00:00.000Z");
    expect(aligned.range.untilIso).toBe("2026-08-10T11:30:00.000Z");
  });
});

describe("Worker security boundary", () => {
  beforeEach(() => {
    vi.stubGlobal("caches", {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("fails closed when Access verification is not configured", async () => {
    const response = await worker.fetch(new Request("https://dashboard.test/api/accounts"), configuredEnv({
      ALLOW_UNAUTHENTICATED_LOCAL_DEV: undefined,
    }));

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({ error: "Cloudflare Access verification is not configured" });
  });

  it("does not let a leftover external-IP setting disable Access verification", async () => {
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);
    const env = configuredEnv({
      AUTH_MODE: "external-ip",
      ALLOW_UNAUTHENTICATED_LOCAL_DEV: undefined,
    });
    const request = new Request("https://dashboard.test/api/accounts");
    const unconfigured = await worker.fetch(request, env);
    expect(unconfigured.status).toBe(503);

    const response = await worker.fetch(request, {
      ...env,
      CF_ACCESS_TEAM_DOMAIN: "https://required-access.cloudflareaccess.com",
      CF_ACCESS_AUD: "app",
    });

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "missing Cloudflare Access token" });
    expect(upstream).not.toHaveBeenCalled();
  });

  it("allows only the explicit local-development bypass", async () => {
    const response = await worker.fetch(new Request("http://127.0.0.1/api/accounts"), configuredEnv());

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ accounts: [{ id: "test", label: "Test account" }] });
  });

  it("does not honor the local-development bypass on a deployed hostname", async () => {
    const response = await worker.fetch(new Request("https://dashboard.test/api/accounts"), configuredEnv());

    expect(response.status).toBe(503);
  });

  it("rejects partial Access configuration even with the local bypass", async () => {
    const response = await worker.fetch(
      new Request("https://dashboard.test/api/accounts"),
      configuredEnv({ CF_ACCESS_AUD: "audience" }),
    );

    expect(response.status).toBe(503);
  });

  it.each(["log", "stats", "http-stats", "http-settings", "waf-settings", "export.csv"])(
    "rejects another account's zone before accessing %s data or cache",
    async (endpoint) => {
      const cacheMatch = vi.fn();
      vi.stubGlobal("caches", { default: { match: cacheMatch } });
      const upstream = vi.fn(async (input: unknown) =>
        zoneDetailsResponse(input, "11111111111111111111111111111111"),
      );
      vi.stubGlobal("fetch", upstream);

      const response = await worker.fetch(
        new Request(`http://127.0.0.1/api/${endpoint}?account=test&zone=foreign-zone`),
        configuredEnv(),
      );

      expect(response.status).toBe(403);
      await expect(response.json()).resolves.toEqual({ error: "zone does not belong to the selected account" });
      expect(upstream).toHaveBeenCalledTimes(1);
      expect(cacheMatch).not.toHaveBeenCalled();
    },
  );

  it("refreshes JWKS once when Access rotates to an unknown key ID", async () => {
    const teamDomain = "https://rotation-test.cloudflareaccess.com";
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const token = [
      encode({ alg: "RS256", kid: "new-key" }),
      encode({ aud: "test-audience", exp: Math.floor(Date.now() / 1000) + 300, iss: teamDomain }),
      Buffer.from("signature").toString("base64url"),
    ].join(".");
    const certFetch = vi.fn()
      .mockResolvedValueOnce(Response.json({ keys: [{ kid: "old-key", n: "AQAB", e: "AQAB" }] }))
      .mockResolvedValueOnce(Response.json({ keys: [{ kid: "new-key", n: "AQAB", e: "AQAB" }] }));
    vi.stubGlobal("fetch", certFetch);
    vi.stubGlobal("crypto", {
      subtle: {
        importKey: vi.fn(async () => ({})),
        verify: vi.fn(async () => true),
      },
    });

    const response = await worker.fetch(
      new Request("https://dashboard.test/api/accounts", {
        headers: { "cf-access-jwt-assertion": token },
      }),
      configuredEnv({
        CF_ACCESS_TEAM_DOMAIN: teamDomain,
        CF_ACCESS_AUD: "test-audience",
      }),
    );

    expect(response.status).toBe(200);
    expect(certFetch).toHaveBeenCalledTimes(2);
  });

  it("adds security headers to static asset responses", async () => {
    const env = configuredEnv({
      ASSETS: { fetch: vi.fn(async () => new Response("<html></html>", { headers: { "content-type": "text/html" } })) },
    });

    const response = await worker.fetch(new Request("https://dashboard.test/"), env);
    const secondResponse = await worker.fetch(new Request("https://dashboard.test/"), env);

    const csp = response.headers.get("content-security-policy") ?? "";
    const secondCsp = secondResponse.headers.get("content-security-policy") ?? "";
    const scriptSrc = csp.split(";").find((directive) => directive.trim().startsWith("script-src")) ?? "";
    const nonce = scriptSrc.match(/'nonce-([^']+)'/)?.[1];
    const secondNonce = secondCsp.match(/'nonce-([^']+)'/)?.[1];
    expect(csp).toContain("frame-ancestors 'none'");
    expect(nonce).toMatch(/^[A-Za-z0-9+/]{24}$/);
    expect(secondNonce).toMatch(/^[A-Za-z0-9+/]{24}$/);
    expect(secondNonce).not.toBe(nonce);
    expect(scriptSrc).not.toContain("sha256-");
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("cache-control")).toBe("no-cache");
  });

  it.each(["13335", "0"])("matches string ASN %s and labels raw WAF rows as adaptively sampled", async (asn) => {
    const params = timeParams();
    params.set("account", "test");
    params.set("zone", `zone-asn-sampling-${asn}`);
    params.set("asn", asn);
    params.append("path", "/a,b");
    params.set("ua", "Bot/1.0 (alpha, beta)");

    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: unknown, init?: RequestInit) => {
        const zoneDetails = zoneDetailsResponse(_input);
        if (zoneDetails) return zoneDetails;
        const body = JSON.parse(String(init?.body ?? "{}"));
        const query = String(body.query ?? "");
        if (query.includes("query WafSettings")) {
          return Response.json({
            data: {
              viewer: {
                zones: [
                  {
                    settings: {
                      firewallEventsAdaptive: { notOlderThan: 86400, maxDuration: 86400 },
                    },
                  },
                ],
              },
            },
          });
        }
        if (query.includes("query Events")) {
          return Response.json({
            data: {
              viewer: {
                zones: [
                  {
                    firewallEventsAdaptive: [
                      {
                        datetime: new Date(Date.now() - hour).toISOString(),
                        action: "block",
                        source: "waf",
                        clientIP: "203.0.113.1",
                        clientAsn: asn,
                        clientCountryName: "US",
                        clientASNDescription: "Cloudflare",
                        clientRequestHTTPHost: "example.test",
                        clientRequestPath: "/a,b",
                        clientRequestHTTPMethodName: "GET",
                        userAgent: "Bot/1.0 (alpha, beta)",
                        ruleId: "rule-id",
                        rayName: "ray-id",
                      },
                    ],
                  },
                ],
              },
            },
          });
        }
        throw new Error(`Unexpected GraphQL query: ${query}`);
      }),
    );

    const response = await worker.fetch(
      new Request(`http://127.0.0.1/api/stats?${params}`),
      configuredEnv(),
    );
    const body = (await response.json()) as any;

    expect(response.status).toBe(200);
    expect(body.sampledRows).toBe(1);
    expect(body.matchedSampledRows).toBe(1);
    expect(body.byAsn).toEqual([{ key: asn, label: "Cloudflare", count: 1 }]);
    expect(body.sampling).toEqual({
      dataset: "firewallEventsAdaptive",
      adaptive: true,
      rowLimitReached: false,
    });
  });

  it("does not truncate a WAF request when the Settings lookup fails", async () => {
    const params = timeParams(72);
    params.set("account", "test");
    params.set("zone", "zone-waf-settings-fallback");
    const originalSince = params.get("since");
    let queriedSince: string | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: unknown, init?: RequestInit) => {
        const zoneDetails = zoneDetailsResponse(_input);
        if (zoneDetails) return zoneDetails;
        const body = JSON.parse(String(init?.body ?? "{}"));
        const query = String(body.query ?? "");
        if (query.includes("query WafSettings")) {
          return Response.json({ errors: [{ message: "temporary Settings failure" }] });
        }
        if (query.includes("query Events")) {
          queriedSince = body.variables?.filter?.datetime_geq;
          return Response.json({ data: { viewer: { zones: [{ firewallEventsAdaptive: [] }] } } });
        }
        throw new Error(`Unexpected GraphQL query: ${query}`);
      }),
    );

    const response = await worker.fetch(
      new Request(`http://127.0.0.1/api/stats?${params}`),
      configuredEnv(),
    );
    const body = (await response.json()) as any;

    expect(response.status).toBe(200);
    expect(queriedSince).toBe(originalSince);
    expect(body.range).toMatchObject({
      requestedSeconds: 72 * 60 * 60,
      effectiveSeconds: 72 * 60 * 60,
      clamped: false,
      limitSource: "fallback",
    });
  });
});

describe("Analytics cache isolation and failures", () => {
  let accountId: string;
  let entries: Map<string, Response>;
  let cache: { match: ReturnType<typeof vi.fn>; put: ReturnType<typeof vi.fn> };
  let upstream: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    accountId = "00000000000000000000000000000000";
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-10T12:00:00Z"));
    entries = new Map();
    cache = {
      match: vi.fn(async (key: Request) => entries.get(key.url)?.clone()),
      put: vi.fn(async (key: Request, value: Response) => { entries.set(key.url, value.clone()); }),
    };
    vi.stubGlobal("caches", { default: cache });
    upstream = vi.fn(async (input: unknown, init?: RequestInit) => {
      const details = zoneDetailsResponse(input, accountId);
      if (details) return details;
      const { query, variables } = JSON.parse(String(init?.body));
      const window = { notOlderThan: 86400, maxDuration: 86400 };
      let result: Record<string, unknown>;
      if (query.includes("query WafSettings")) result = { settings: { firewallEventsAdaptive: window } };
      else if (query.includes("query HttpSettings")) result = { settings: {
        httpRequestsAdaptiveGroups: window,
        httpRequests1hGroups: { notOlderThan: 259200, maxDuration: 259200 },
        httpRequests1dGroups: { notOlderThan: 2592000, maxDuration: 2592000 },
      } };
      else if (query.includes("query Events")) result = { firewallEventsAdaptive: [{
        datetime: variables.filter.datetime_geq, action: "block", source: "waf", clientAsn: "13335",
      }] };
      else if (query.includes("query HttpCore")) result = {
        series: [{ count: 1, sum: { edgeResponseBytes: 10, visits: 1 }, dimensions: {
          datetimeMinute: query.match(/datetime_geq: "([^"]+)"/)[1],
        } }], country: [], status: [], host: [], path: [],
      };
      else if (query.includes("query HttpPerf")) result = { series: [], overall: [] };
      else result = { g: [] };
      return Response.json({ data: { viewer: { zones: [result] } } });
    });
    vi.stubGlobal("fetch", upstream);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  async function request(endpoint: string, suffix: string, minute = "00", env = configuredEnv()) {
    const params = new URLSearchParams({
      account: "test", zone: `cache-${endpoint}-${suffix}`,
      since: `2026-09-10T10:${minute}:00.000Z`, until: `2026-09-10T10:${minute}:30.000Z`,
    });
    const response = await worker.fetch(new Request(`http://127.0.0.1/api/${endpoint}?${params}`), env);
    expect(response.status).toBe(200);
    return response.json() as Promise<any>;
  }

  it.each(["stats", "http-stats"])("does not merge distinct short intervals in %s", async (endpoint) => {
    const first = await request(endpoint, "time");
    const second = await request(endpoint, "time", "04");
    const repeated = await request(endpoint, "time", "04");

    expect(first.cache).toBe("MISS");
    expect(second.cache).toBe("MISS");
    expect(repeated.cache).toBe("HIT");
    const actualTime = endpoint === "stats" ? repeated.events[0].datetime : repeated.range.effectiveSince;
    expect(actualTime).toBe("2026-09-10T10:04:00.000Z");
    expect(entries.size).toBe(2);
  });

  it.each(["stats", "http-stats"])("isolates account and token changes for %s", async (endpoint) => {
    await request(endpoint, "credentials");
    const rotated = await request(endpoint, "credentials", "00", configuredEnv({ CFACC_TEST_TOKEN: "rotated-token" }));
    accountId = "11111111111111111111111111111111";
    const reassigned = await request(endpoint, "credentials", "00", configuredEnv({ CFACC_TEST_ACCOUNT: accountId }));

    expect(rotated.cache).toBe("MISS");
    expect(reassigned.cache).toBe("MISS");
    expect(entries.size).toBe(3);
    for (const key of entries.keys()) {
      expect(key).not.toContain("test-token");
      expect(key).not.toContain("rotated-token");
    }
    const settingsCalls = upstream.mock.calls.filter(([, init]) => String(init?.body).includes("Settings"));
    expect(settingsCalls).toHaveLength(3);
  });

  it.each([
    ["stats", "read"], ["stats", "write"], ["stats", "json"], ["stats", "missing"],
    ["http-stats", "read"], ["http-stats", "write"], ["http-stats", "json"], ["http-stats", "missing"],
  ])("bypasses a %s cache %s failure without losing data", async (endpoint, phase) => {
    if (phase === "read") cache.match.mockRejectedValue(new Error("cache read failed"));
    if (phase === "write") cache.put.mockRejectedValue(new Error("cache write failed"));
    if (phase === "json") cache.match.mockResolvedValue(new Response("not json"));
    if (phase === "missing") vi.stubGlobal("caches", undefined);

    const body = await request(endpoint, phase);

    expect(body.cache).toBe("BYPASS");
    expect(endpoint === "stats" ? body.events.length : body.totals.requests).toBe(1);
  });
});

describe("Upstream response handling", () => {
  beforeEach(() => {
    vi.stubGlobal("caches", {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("lists every zone beyond the former twenty-page limit", async () => {
    const total = 1051;
    const upstream = vi.fn(async (input: unknown) => {
      const url = new URL(String(input));
      expect(url.searchParams.get("account.id")).toBe("00000000000000000000000000000000");
      const offset = (Number(url.searchParams.get("page")) - 1) * 50;
      const result = Array.from({ length: Math.min(50, total - offset) }, (_, index) => ({
        id: `zone-${offset + index}`, name: `${offset + index}.example`, status: "active", plan: { name: "Free" },
      }));
      return Response.json({ success: true, result });
    });
    vi.stubGlobal("fetch", upstream);

    const response = await worker.fetch(new Request("http://127.0.0.1/api/zones?account=test"), configuredEnv());
    const body = await response.json() as any;

    expect(response.status).toBe(200);
    expect(body.zones).toHaveLength(total);
    expect(body.zones.some((zone: any) => zone.id === "zone-1050")).toBe(true);
    expect(upstream).toHaveBeenCalledTimes(22);
  });

  it.each(["REST", "GraphQL", "JWKS"])("returns 504 when the %s response body times out", async (kind) => {
    const upstream = vi.fn(async (input: unknown, init?: RequestInit) => {
      if (kind === "GraphQL") {
        const zoneDetails = zoneDetailsResponse(input);
        if (zoneDetails) return zoneDetails;
        const query = String(JSON.parse(String(init?.body ?? "{}")).query ?? "");
        if (query.includes("query WafSettings")) {
          return Response.json({ data: { viewer: { zones: [{ settings: {
            firewallEventsAdaptive: { notOlderThan: 86400, maxDuration: 86400 },
          } }] } } });
        }
      }
      return new Response(new ReadableStream({
        start(controller) { controller.error(new DOMException("body timed out", "TimeoutError")); },
      }), { headers: { "content-type": "application/json" } });
    });
    vi.stubGlobal("fetch", upstream);
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const token = `${encode({ alg: "RS256", kid: "timeout-key" })}.${encode({})}.AA`;
    const response = kind === "JWKS"
      ? await worker.fetch(new Request("https://dashboard.test/api/accounts", {
          headers: { "cf-access-jwt-assertion": token },
        }), configuredEnv({ CF_ACCESS_TEAM_DOMAIN: "https://timeout-test.cloudflareaccess.com", CF_ACCESS_AUD: "app" }))
      : await worker.fetch(new Request(`http://127.0.0.1/api/log?account=test&zone=timeout-${kind}`), configuredEnv());

    expect(response.status).toBe(504);
    await expect(response.json()).resolves.toEqual({ error: "upstream request to Cloudflare timed out" });
  });

  it("maps a body AbortError to 504 when the request deadline has expired", async () => {
    const controller = new AbortController();
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(controller.signal);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(new ReadableStream({
      start(stream) {
        queueMicrotask(() => {
          controller.abort(new DOMException("deadline expired", "TimeoutError"));
          stream.error(new DOMException("body aborted", "AbortError"));
        });
      },
    }))));

    const response = await worker.fetch(new Request("http://127.0.0.1/api/zones?account=test"), configuredEnv());

    expect(response.status).toBe(504);
  });
});

describe("JWT claim validation", () => {
  const nowSeconds = Date.parse("2026-09-10T12:00:00Z") / 1000;
  const teamDomain = "https://signed-claims.cloudflareaccess.com";
  let keyPair: CryptoKeyPair;
  let publicJwk: JsonWebKey;

  beforeAll(async () => {
    keyPair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    ) as CryptoKeyPair;
    publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it.each([
    { name: "valid token", claims: {}, status: 200 },
    { name: "active not-before boundary", claims: { nbf: nowSeconds }, status: 200 },
    { name: "future not-before", claims: { nbf: nowSeconds + 300 }, status: 403 },
    { name: "invalid not-before type", claims: { nbf: String(nowSeconds) }, status: 403 },
    { name: "null not-before", claims: { nbf: null }, status: 403 },
    { name: "expiration boundary", claims: { exp: nowSeconds }, status: 403 },
    { name: "expired token", claims: { exp: nowSeconds - 1 }, status: 403 },
    { name: "invalid expiration type", claims: { exp: String(nowSeconds + 600) }, status: 403 },
    { name: "missing expiration", claims: { exp: undefined }, status: 403 },
    { name: "wrong issuer", claims: { iss: "https://other.cloudflareaccess.com" }, status: 403 },
    { name: "wrong audience", claims: { aud: ["other-app"] }, status: 403 },
  ])("validates a signed $name", async ({ claims, status }) => {
    vi.spyOn(Date, "now").mockReturnValue(nowSeconds * 1000);
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ keys: [{ ...publicJwk, kid: "test-key" }] })));
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const payload = { aud: ["test-app"], iss: teamDomain, exp: nowSeconds + 600, ...claims };
    const unsigned = `${encode({ alg: "RS256", kid: "test-key" })}.${encode(payload)}`;
    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5", keyPair.privateKey, new TextEncoder().encode(unsigned),
    );
    const response = await worker.fetch(
      new Request("https://dashboard.test/api/accounts", {
        headers: { "cf-access-jwt-assertion": `${unsigned}.${Buffer.from(signature).toString("base64url")}` },
      }),
      configuredEnv({ CF_ACCESS_TEAM_DOMAIN: teamDomain, CF_ACCESS_AUD: "test-app" }),
    );

    expect(response.status).toBe(status);
  });
});

describe("HTTP aggregation", () => {
  beforeEach(() => {
    vi.stubGlobal("caches", {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it.each([
    { hours: 24, delayMs: 0, dataset: "adaptive" },
    { hours: 24, delayMs: 1000, dataset: "adaptive" },
    { hours: 24, delayMs: 59000, dataset: "adaptive" },
    { hours: 72, delayMs: 1000, dataset: "hourly" },
    { hours: 72, delayMs: 59000, dataset: "hourly" },
  ])("retains the $dataset dataset at $hours h with a $delayMs ms delay", async ({ hours, delayMs, dataset }) => {
    const clientNow = Date.parse("2026-09-10T12:00:00Z");
    vi.spyOn(Date, "now").mockReturnValue(clientNow + delayMs);
    const since = new Date(clientNow - hours * hour).toISOString();
    const params = new URLSearchParams({
      account: "test", zone: `boundary-${hours}-${delayMs}`, since, until: new Date(clientNow).toISOString(),
    });
    let actualSince: string | undefined;
    vi.stubGlobal("fetch", vi.fn(async (input: unknown, init?: RequestInit) => {
      const details = zoneDetailsResponse(input);
      if (details) return details;
      const { query } = JSON.parse(String(init?.body));
      let result: Record<string, unknown>;
      if (query.includes("query HttpSettings")) result = { settings: {
        httpRequestsAdaptiveGroups: { notOlderThan: 86400, maxDuration: 86400 },
        httpRequests1hGroups: { notOlderThan: 259200, maxDuration: 259200 },
        httpRequests1dGroups: { notOlderThan: 2592000, maxDuration: 2592000 },
      } };
      else if (query.includes("query HttpCore") || query.includes("query RollupSeries")) {
        actualSince = query.match(/datetime_geq: "([^"]+)"/)?.[1];
        result = { series: [], country: [], status: [], host: [], path: [], total: [] };
      } else if (query.includes("query HttpPerf")) result = { series: [], overall: [] };
      else result = { g: [] };
      return Response.json({ data: { viewer: { zones: [result] } } });
    }));

    const response = await worker.fetch(new Request(`http://127.0.0.1/api/http-stats?${params}`), configuredEnv());
    const body = await response.json() as any;

    expect(response.status).toBe(200);
    expect(body.dataset).toBe(dataset);
    expect(body.range.clamped).toBe(delayMs > 0);
    expect(body.range.effectiveSeconds).toBe(hours * 3600 - delayMs / 1000);
    expect(actualSince).toBe(new Date(Date.parse(since) + delayMs).toISOString());
  });

  it("uses the no-dimension performance aggregate and seven upstream calls on an adaptive cold load", async () => {
    const params = timeParams();
    params.set("account", "test");
    params.set("zone", "zone-http-adaptive");
    const upstream = vi.fn(async (_input: unknown, init?: RequestInit) => {
      const zoneDetails = zoneDetailsResponse(_input);
      if (zoneDetails) return zoneDetails;
      const query = String(JSON.parse(String(init?.body ?? "{}")).query ?? "");
      if (query.includes("query HttpSettings")) {
        return Response.json({
          data: {
            viewer: {
              zones: [
                {
                  settings: {
                    httpRequestsAdaptiveGroups: { notOlderThan: 86400, maxDuration: 86400 },
                    httpRequests1hGroups: { notOlderThan: 259200, maxDuration: 259200 },
                    httpRequests1dGroups: { notOlderThan: 2592000, maxDuration: 2592000 },
                  },
                },
              ],
            },
          },
        });
      }
      if (query.includes("query HttpCore")) {
        return Response.json({
          data: {
            viewer: {
              zones: [
                {
                  series: [
                    {
                      count: 10,
                      sum: { edgeResponseBytes: 1000, visits: 2 },
                      dimensions: { datetimeMinute: "2026-08-10T10:00:00Z" },
                    },
                  ],
                  country: [],
                  status: [{ count: 10, dimensions: { edgeResponseStatus: 200 } }],
                  host: [],
                  path: [],
                },
              ],
            },
          },
        });
      }
      if (query.includes("query HttpPerf")) {
        return Response.json({
          data: {
            viewer: {
              zones: [
                {
                  series: [
                    {
                      avg: { edgeTimeToFirstByteMs: 100, originResponseDurationMs: null },
                      dimensions: { datetimeMinute: "2026-08-10T10:00:00Z" },
                    },
                  ],
                  overall: [{ avg: { edgeTimeToFirstByteMs: 150, originResponseDurationMs: 300 } }],
                },
              ],
            },
          },
        });
      }
      if (query.includes("query RollupMap")) {
        return Response.json({ data: { viewer: { zones: [{ g: [] }] } } });
      }
      if (query.includes("query HttpGroup")) {
        return Response.json({ data: { viewer: { zones: [{ g: [] }] } } });
      }
      throw new Error(`Unexpected GraphQL query: ${query}`);
    });
    vi.stubGlobal("fetch", upstream);

    const response = await worker.fetch(
      new Request(`http://127.0.0.1/api/http-stats?${params}`),
      configuredEnv(),
    );
    const body = (await response.json()) as any;

    expect(response.status).toBe(200);
    expect(body.perf).toMatchObject({ ttfbMs: 150, originMs: 300 });
    expect(body.totals).toMatchObject({ requests: 10, bytes: 1000, visits: 2, uniqueIps: null });
    expect(upstream).toHaveBeenCalledTimes(7);
  });

  it("returns seven daily buckets and one global unique-IP total", async () => {
    const params = timeParams(7 * 24);
    params.set("account", "test");
    params.set("zone", "zone-http-daily");
    const upstream = vi.fn(async (_input: unknown, init?: RequestInit) => {
      const zoneDetails = zoneDetailsResponse(_input);
      if (zoneDetails) return zoneDetails;
      const query = String(JSON.parse(String(init?.body ?? "{}")).query ?? "");
      if (query.includes("query HttpSettings")) {
        return Response.json({
          data: {
            viewer: {
              zones: [
                {
                  settings: {
                    httpRequestsAdaptiveGroups: { notOlderThan: 86400, maxDuration: 86400 },
                    httpRequests1hGroups: { notOlderThan: 259200, maxDuration: 259200 },
                    httpRequests1dGroups: { notOlderThan: 2592000, maxDuration: 2592000 },
                  },
                },
              ],
            },
          },
        });
      }
      if (query.includes("query RollupSeries")) {
        const series = Array.from({ length: 7 }, (_, index) => ({
          dimensions: { date: `2026-08-${String(index + 4).padStart(2, "0")}` },
          sum: { requests: 10, bytes: 100, cachedRequests: 5 },
        }));
        return Response.json({
          data: { viewer: { zones: [{ series, total: [{ uniq: { uniques: 5 } }] }] } },
        });
      }
      if (query.includes("query RollupMap")) {
        return Response.json({ data: { viewer: { zones: [{ g: [] }] } } });
      }
      throw new Error(`Unexpected GraphQL query: ${query}`);
    });
    vi.stubGlobal("fetch", upstream);

    const response = await worker.fetch(
      new Request(`http://127.0.0.1/api/http-stats?${params}`),
      configuredEnv(),
    );
    const body = (await response.json()) as any;

    expect(response.status).toBe(200);
    expect(body.dataset).toBe("daily");
    expect(body.range.calendarDays).toBe(7);
    expect(body.series).toHaveLength(7);
    expect(body.totals).toMatchObject({ visits: null, uniqueIps: 5 });
    expect(upstream).toHaveBeenCalledTimes(7);
  });

  it("uses a retained roll-up for a short historical window", async () => {
    const until = new Date(Date.now() - 7 * 24 * hour);
    const since = new Date(until.getTime() - hour);
    const params = new URLSearchParams({
      account: "test",
      zone: "zone-http-historical",
      since: since.toISOString(),
      until: until.toISOString(),
    });
    const upstream = vi.fn(async (_input: unknown, init?: RequestInit) => {
      const zoneDetails = zoneDetailsResponse(_input);
      if (zoneDetails) return zoneDetails;
      const query = String(JSON.parse(String(init?.body ?? "{}")).query ?? "");
      if (query.includes("query HttpSettings")) {
        return Response.json({
          data: {
            viewer: {
              zones: [
                {
                  settings: {
                    httpRequestsAdaptiveGroups: { notOlderThan: 86400, maxDuration: 86400 },
                    httpRequests1hGroups: { notOlderThan: 259200, maxDuration: 259200 },
                    httpRequests1dGroups: { notOlderThan: 2592000, maxDuration: 2592000 },
                  },
                },
              ],
            },
          },
        });
      }
      if (query.includes("query RollupSeries")) {
        return Response.json({
          data: {
            viewer: {
              zones: [
                {
                  series: [
                    {
                      dimensions: { date: until.toISOString().slice(0, 10) },
                      sum: { requests: 2, bytes: 20, cachedRequests: 1 },
                    },
                  ],
                  total: [{ uniq: { uniques: 1 } }],
                },
              ],
            },
          },
        });
      }
      if (query.includes("query RollupMap")) {
        return Response.json({ data: { viewer: { zones: [{ g: [] }] } } });
      }
      throw new Error(`Unexpected GraphQL query: ${query}`);
    });
    vi.stubGlobal("fetch", upstream);

    const response = await worker.fetch(
      new Request(`http://127.0.0.1/api/http-stats?${params}`),
      configuredEnv(),
    );
    const body = (await response.json()) as any;

    expect(response.status).toBe(200);
    expect(body.dataset).toBe("daily");
    expect(body.range.calendarDays).toBe(1);
    expect(body.totals.uniqueIps).toBe(1);
  });
});
