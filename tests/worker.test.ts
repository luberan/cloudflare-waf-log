import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { alignDailyRange, parseFilters, parseHttpRange } from "../src/index";

const hour = 60 * 60 * 1000;

describe("deployment configuration", () => {
  it("preserves dashboard-defined runtime variables during deploy", () => {
    const config = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");

    expect(config).toMatch(/"keep_vars"\s*:\s*true/);
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

  it("matches string ASNs and labels raw WAF rows as adaptively sampled", async () => {
    const params = timeParams();
    params.set("account", "test");
    params.set("zone", "zone-asn-sampling");
    params.set("asn", "13335");
    params.append("path", "/a,b");
    params.set("ua", "Bot/1.0 (alpha, beta)");

    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: unknown, init?: RequestInit) => {
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
                        clientAsn: "13335",
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
    expect(body.byAsn).toEqual([{ key: "13335", label: "Cloudflare", count: 1 }]);
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

describe("HTTP aggregation", () => {
  beforeEach(() => {
    vi.stubGlobal("caches", {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("uses the no-dimension performance aggregate and six upstream calls on an adaptive cold load", async () => {
    const params = timeParams();
    params.set("account", "test");
    params.set("zone", "zone-http-adaptive");
    const upstream = vi.fn(async (_input: unknown, init?: RequestInit) => {
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
    expect(upstream).toHaveBeenCalledTimes(6);
  });

  it("returns seven daily buckets and one global unique-IP total", async () => {
    const params = timeParams(7 * 24);
    params.set("account", "test");
    params.set("zone", "zone-http-daily");
    const upstream = vi.fn(async (_input: unknown, init?: RequestInit) => {
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
    expect(upstream).toHaveBeenCalledTimes(6);
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
