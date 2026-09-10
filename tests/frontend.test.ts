import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { JSDOM } from "jsdom";
import { afterEach, describe, expect, it, vi } from "vitest";

const root = resolve(import.meta.dirname, "..");
const html = readFileSync(resolve(root, "public/index.html"), "utf8");
const appScript = readFileSync(resolve(root, "public/app.js"), "utf8");

const emptyWafSummary = {
  byAction: [],
  byCountry: [],
  byHost: [],
  byPath: [],
  bySource: [],
  byRule: [],
  byAsn: [],
  byUserAgent: [],
  series: [],
  events: [],
  sampledRows: 0,
  matchedSampledRows: 0,
  sampling: { dataset: "firewallEventsAdaptive", adaptive: true, rowLimitReached: false },
  range: { requestedSeconds: 86400, effectiveSeconds: 86400, clamped: false, maxRangeSeconds: 86400 },
  cache: "MISS",
};

const emptyHttpSummary = {
  cache: "MISS",
  dataset: "adaptive",
  range: { requestedSeconds: 86400, effectiveSeconds: 86400, clamped: false, maxRangeSeconds: 2592000 },
  timeDim: "datetimeHour",
  totals: { requests: 0, bytes: 0, visits: 0, uniqueIps: null, cachedPct: null },
  series: [],
  byStatus: [],
  byCountry: [],
  byHost: [],
  byPath: [],
  byContentType: [],
  byHttpVersion: [],
  byCacheStatus: [],
  perf: null,
};

function deferred<T>() {
  let resolvePromise!: (value: T) => void;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

function response(data: unknown) {
  return {
    ok: true,
    statusText: "OK",
    json: async () => data,
    text: async () => JSON.stringify(data),
    blob: async () => new Blob([JSON.stringify(data)]),
    headers: { get: () => null },
  };
}

type ApiHandler = (url: URL) => unknown | Promise<unknown>;

function createDashboard(handler: ApiHandler) {
  const dom = new JSDOM(html, {
    url: "https://dashboard.test/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const requests: URL[] = [];
  const charts = new Map<string, ChartMock>();

  class ChartMock {
    canvas: HTMLCanvasElement;
    data: any;
    chartArea = { left: 40, right: 300, top: 10, bottom: 250 };

    constructor(canvas: HTMLCanvasElement, config: any) {
      this.canvas = canvas;
      this.data = config.data;
      charts.set(canvas.id, this);
    }

    destroy() { charts.delete(this.canvas.id); }
  }

  Object.assign(dom.window, {
    Chart: ChartMock,
    fetch: vi.fn(async (input: string | URL | Request) => {
      const url = new URL(String(input), dom.window.location.href);
      requests.push(url);
      return response(await handler(url));
    }),
  });
  dom.window.eval(appScript);
  return { dom, window: dom.window, document: dom.window.document, requests, charts };
}

async function waitUntil(predicate: () => boolean) {
  await vi.waitFor(() => expect(predicate()).toBe(true), { timeout: 2000, interval: 5 });
}

async function closeDashboard(dashboard: ReturnType<typeof createDashboard>) {
  await new Promise((resolve) => setTimeout(resolve, 20));
  dashboard.dom.window.close();
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("dashboard request coordination", () => {
  it.each(["empty", "failure"])("clears the previous account while loading an %s zone response", async (outcome) => {
    const nextZones = deferred<{ zones: never[] }>();
    const dashboard = createDashboard((url) => {
      if (url.pathname === "/api/accounts") return { accounts: [{ id: "a", label: "A" }, { id: "b", label: "B" }] };
      if (url.pathname === "/api/zones") {
        if (url.searchParams.get("account") === "a") return { zones: [{ id: "zone-a", name: "a.test", plan: "Free" }] };
        return nextZones.promise.then(value => {
          if (outcome === "failure") throw new Error("zone lookup failed");
          return value;
        });
      }
      if (url.pathname === "/api/waf-settings") return { maxRangeSeconds: 86400, source: "cloudflare" };
      if (url.pathname === "/api/stats") return {
        ...emptyWafSummary, byAction: [{ key: "block", count: 1 }], byCountry: [{ key: "US", count: 1 }],
        events: [{ action: "block", clientRequestHTTPHost: "a.test" }],
      };
      throw new Error(`Unexpected request: ${url}`);
    });
    await waitUntil(() => dashboard.document.querySelector("#kpiTotal")?.textContent === "1");
    const account = dashboard.document.querySelector("#account") as HTMLSelectElement;
    account.value = "b";
    account.dispatchEvent(new dashboard.window.Event("change"));

    expect((dashboard.document.querySelector("#zone") as HTMLSelectElement).value).toBe("");
    expect(dashboard.document.querySelector("#kpiTotal")?.textContent).toBe("-");
    expect(dashboard.document.querySelectorAll("#tblEvents tbody tr, #chartCountryControls button")).toHaveLength(0);
    expect((dashboard.document.querySelector("#refresh") as HTMLButtonElement).disabled).toBe(true);
    expect((dashboard.document.querySelector("#exportCsv") as HTMLButtonElement).disabled).toBe(true);

    nextZones.resolve({ zones: [] });
    await waitUntil(() => Boolean(dashboard.document.querySelector("#error")?.textContent));
    expect((dashboard.document.querySelector("#zone") as HTMLSelectElement).value).toBe("");
    expect(dashboard.document.querySelector("#kpiTotal")?.textContent).toBe("-");
    (dashboard.document.querySelector("#refresh") as HTMLButtonElement).click();
    expect(dashboard.requests.filter(url => url.pathname === "/api/stats")).toHaveLength(1);
    await closeDashboard(dashboard);
  });

  it("keeps the snapshot interval for facets and starts a new interval on Load", async () => {
    const dashboard = createDashboard((url) => {
      if (url.pathname === "/api/accounts") return { accounts: [{ id: "a", label: "A" }] };
      if (url.pathname === "/api/zones") return { zones: [{ id: "zone-a", name: "a.test", plan: "Free" }] };
      if (url.pathname === "/api/waf-settings") return { maxRangeSeconds: 86400, source: "cloudflare" };
      if (url.pathname === "/api/stats") return { ...emptyWafSummary, byCountry: [{ key: "US", count: 1 }] };
      throw new Error(`Unexpected request: ${url}`);
    });
    await waitUntil(() => dashboard.document.querySelector("#kpiTotal")?.textContent === "0");
    const first = dashboard.requests.find(url => url.pathname === "/api/stats")!;
    const later = Date.parse(first.searchParams.get("until")!) + 240000;
    vi.spyOn(dashboard.window.Date, "now").mockReturnValue(later);
    (dashboard.document.querySelector("#chartCountryControls button") as HTMLButtonElement).click();
    await waitUntil(() => dashboard.requests.filter(url => url.pathname === "/api/stats").length === 2);
    const facet = dashboard.requests.filter(url => url.pathname === "/api/stats").at(-1)!;

    expect(facet.searchParams.get("since")).toBe(first.searchParams.get("since"));
    expect(facet.searchParams.get("until")).toBe(first.searchParams.get("until"));
    await waitUntil(() => !(dashboard.document.querySelector("#refresh") as HTMLButtonElement).disabled);
    (dashboard.document.querySelector("#refresh") as HTMLButtonElement).click();
    await waitUntil(() => dashboard.requests.filter(url => url.pathname === "/api/stats").length === 3);
    const refreshed = dashboard.requests.filter(url => url.pathname === "/api/stats").at(-1)!;
    expect(refreshed.searchParams.get("until")).toBe(new Date(later).toISOString());
    await closeDashboard(dashboard);
  });

  it("does not let an old account response replace the current zones", async () => {
    const zonesA = deferred<{ zones: { id: string; name: string; plan: string }[] }>();
    const dashboard = createDashboard((url) => {
      if (url.pathname === "/api/accounts") return { accounts: [{ id: "a", label: "A" }, { id: "b", label: "B" }] };
      if (url.pathname === "/api/zones" && url.searchParams.get("account") === "a") return zonesA.promise;
      if (url.pathname === "/api/zones") return { zones: [{ id: "zone-b", name: "b.test", plan: "Free" }] };
      if (url.pathname === "/api/waf-settings") return { maxRangeSeconds: 86400, source: "cloudflare" };
      if (url.pathname === "/api/stats") return emptyWafSummary;
      throw new Error(`Unexpected request: ${url}`);
    });

    await waitUntil(() => dashboard.document.querySelectorAll("#account option").length === 2);
    const account = dashboard.document.querySelector("#account") as HTMLSelectElement;
    account.value = "b";
    account.dispatchEvent(new dashboard.window.Event("change"));
    await waitUntil(() => (dashboard.document.querySelector("#zone") as HTMLSelectElement).value === "zone-b");

    zonesA.resolve({ zones: [{ id: "zone-a", name: "a.test", plan: "Free" }] });
    await Promise.resolve();
    await Promise.resolve();

    expect(account.value).toBe("b");
    expect((dashboard.document.querySelector("#zone") as HTMLSelectElement).value).toBe("zone-b");
    await closeDashboard(dashboard);
  });

  it("does not let a late HTTP response change the active WAF range", async () => {
    const httpStats = deferred<typeof emptyHttpSummary>();
    let httpRequested = false;
    const dashboard = createDashboard((url) => {
      if (url.pathname === "/api/accounts") return { accounts: [{ id: "a", label: "A" }] };
      if (url.pathname === "/api/zones") return { zones: [{ id: "zone-a", name: "a.test", plan: "Free" }] };
      if (url.pathname === "/api/waf-settings") return { maxRangeSeconds: 86400, source: "cloudflare" };
      if (url.pathname === "/api/stats") return emptyWafSummary;
      if (url.pathname === "/api/http-stats") {
        httpRequested = true;
        return httpStats.promise;
      }
      throw new Error(`Unexpected request: ${url}`);
    });

    await waitUntil(() => (dashboard.document.querySelector("#kpiTotal")?.textContent ?? "") === "0");
    (dashboard.document.querySelector("#tab-http") as HTMLButtonElement).click();
    await waitUntil(() => httpRequested);
    expect(dashboard.window.getComputedStyle(dashboard.document.querySelector("#view-waf")!).display).toBe("none");
    (dashboard.document.querySelector("#tab-waf") as HTMLButtonElement).click();
    await waitUntil(() => dashboard.document.querySelector("#view-waf")?.hasAttribute("hidden") === false);
    expect(dashboard.window.getComputedStyle(dashboard.document.querySelector("#view-http")!).display).toBe("none");

    httpStats.resolve(emptyHttpSummary);
    await Promise.resolve();
    await Promise.resolve();

    const range = dashboard.document.querySelector("#range") as HTMLSelectElement;
    expect(range.value).toBe("24");
    expect([...range.options].map((option) => option.value)).toEqual(["1", "6", "24"]);
    expect(dashboard.document.querySelector("#tab-waf")?.getAttribute("aria-selected")).toBe("true");
    await closeDashboard(dashboard);
  });
});

describe("dashboard time axes", () => {
  it("includes leading, internal and trailing empty hours in WAF charts", async () => {
    const dashboard = createDashboard((url) => {
      if (url.pathname === "/api/accounts") return { accounts: [{ id: "a", label: "A" }] };
      if (url.pathname === "/api/zones") return { zones: [{ id: "zone-a", name: "a.test", plan: "Free" }] };
      if (url.pathname === "/api/waf-settings") return { maxRangeSeconds: 86400, source: "cloudflare" };
      if (url.pathname === "/api/stats") return {
        ...emptyWafSummary,
        range: { ...emptyWafSummary.range, effectiveSince: "2026-09-10T00:00:00Z", effectiveUntil: "2026-09-10T07:59:59Z" },
        byAction: [{ key: "block", count: 5 }],
        series: [
          { hour: "2026-09-10T01:00:00Z", action: "block", count: 2 },
          { hour: "2026-09-10T06:00:00Z", action: "block", count: 3 },
        ],
      };
      throw new Error(`Unexpected request: ${url}`);
    });
    await waitUntil(() => dashboard.document.querySelector("#kpiTotal")?.textContent === "5");

    const chart = dashboard.charts.get("chartSeries")!;
    expect(chart.data.labels).toHaveLength(8);
    expect(chart.data.labels[0]).toBe("09-10 00:00");
    expect(chart.data.labels[7]).toBe("09-10 07:00");
    expect(chart.data.datasets[0].data).toEqual([0, 2, 0, 0, 0, 0, 3, 0]);
    await closeDashboard(dashboard);
  });

  it.each([
    { dim: "datetimeMinute", since: "2026-09-10T10:00:00Z", until: "2026-09-10T10:04:59Z", first: "2026-09-10T10:01:00Z", last: "2026-09-10T10:03:00Z" },
    { dim: "datetimeHour", since: "2026-09-10T00:00:00Z", until: "2026-09-10T04:59:59Z", first: "2026-09-10T01:00:00Z", last: "2026-09-10T03:00:00Z" },
    { dim: "datetime", since: "2026-09-10T00:00:00Z", until: "2026-09-10T04:59:59Z", first: "2026-09-10T01:00:00Z", last: "2026-09-10T03:00:00Z" },
    { dim: "date", since: "2026-09-01T00:00:00Z", until: "2026-09-05T23:59:59Z", first: "2026-09-02", last: "2026-09-04" },
  ])("fills $dim traffic gaps and leaves missing performance as null", async ({ dim, since, until, first, last }) => {
    const dashboard = createDashboard((url) => {
      if (url.pathname === "/api/accounts") return { accounts: [{ id: "a", label: "A" }] };
      if (url.pathname === "/api/zones") return { zones: [{ id: "zone-a", name: "a.test", plan: "Free" }] };
      if (url.pathname === "/api/waf-settings") return { maxRangeSeconds: 86400, source: "cloudflare" };
      if (url.pathname === "/api/stats") return emptyWafSummary;
      if (url.pathname === "/api/http-stats") return {
        ...emptyHttpSummary, timeDim: dim,
        range: { ...emptyHttpSummary.range, effectiveSince: since, effectiveUntil: until },
        totals: { ...emptyHttpSummary.totals, requests: 12 },
        series: [{ t: first, requests: 5, bytes: 50 }, { t: last, requests: 7, bytes: 70 }],
        perf: {
          ttfbMs: 30, originMs: 60,
          series: [{ t: first, ttfbMs: 20, originMs: 40 }, { t: last, ttfbMs: 40, originMs: 80 }],
        },
      };
      throw new Error(`Unexpected request: ${url}`);
    });
    await waitUntil(() => dashboard.document.querySelector("#kpiTotal")?.textContent === "0");
    (dashboard.document.querySelector("#tab-http") as HTMLButtonElement).click();
    await waitUntil(() => dashboard.document.querySelector("#hkpiReq")?.textContent === "12");

    const traffic = dashboard.charts.get("chartHttpSeries")!;
    expect(traffic.data.labels).toHaveLength(5);
    expect(traffic.data.datasets[0].data).toEqual([0, 5, 0, 7, 0]);
    expect(traffic.data.datasets[1].data).toEqual([0, 50, 0, 70, 0]);
    const perf = dashboard.charts.get("chartHttpPerf")!;
    expect(perf.data.datasets[0].data).toEqual([null, 40, null, 80, null]);
    expect(perf.data.datasets[0].spanGaps).toBe(false);
    expect(perf.data.datasets[0].pointRadius).toBeGreaterThan(0);
    expect(perf.data.datasets[1].data).toEqual([null, 20, null, 40, null]);
    await closeDashboard(dashboard);
  });
});

describe("dashboard filters and accessibility", () => {
  it.each([
    { inputId: "countryFilter", initial: "us,US", parameter: "country", value: "US", selector: "#chartCountryControls button" },
    { inputId: "asnFilter", initial: "AS013335,13335", parameter: "asn", value: "13335", selector: '#tblAsn tr[data-asn="13335"]' },
    { inputId: "asnFilter", initial: "AS0", parameter: "asn", value: "0", selector: '#tblAsn tr[data-asn="0"]' },
  ])("normalizes $initial for highlighting, queries and toggling", async ({ inputId, initial, parameter, value, selector }) => {
    const dashboard = createDashboard((url) => {
      if (url.pathname === "/api/accounts") return { accounts: [{ id: "a", label: "A" }] };
      if (url.pathname === "/api/zones") return { zones: [{ id: "zone-a", name: "a.test", plan: "Free" }] };
      if (url.pathname === "/api/waf-settings") return { maxRangeSeconds: 86400, source: "cloudflare" };
      if (url.pathname === "/api/stats") return {
        ...emptyWafSummary, byCountry: [{ key: "US", count: 1 }],
        byAsn: [{ key: "13335", label: "Cloudflare", count: 1 }, { key: "0", label: "(unknown)", count: 1 }],
      };
      throw new Error(`Unexpected request: ${url}`);
    });
    await waitUntil(() => dashboard.document.querySelector("#kpiTotal")?.textContent === "0");
    const input = dashboard.document.querySelector(`#${inputId}`) as HTMLInputElement;
    input.value = initial;
    (dashboard.document.querySelector("#refresh") as HTMLButtonElement).click();
    await waitUntil(() => dashboard.document.querySelector(selector)?.getAttribute("aria-pressed") === "true");
    const filtered = dashboard.requests.filter(url => url.pathname === "/api/stats").at(-1)!;
    expect(filtered.searchParams.getAll(parameter)).toEqual([value]);

    (dashboard.document.querySelector(selector) as HTMLElement).click();
    await waitUntil(() => dashboard.requests.filter(url => url.pathname === "/api/stats").length === 3);
    const cleared = dashboard.requests.filter(url => url.pathname === "/api/stats").at(-1)!;
    expect(input.value).toBe("");
    expect(cleared.searchParams.getAll(parameter)).toEqual([]);
    await closeDashboard(dashboard);
  });

  it("sends exact comma-containing path and UA values and exposes chart filter buttons", async () => {
    const dashboard = createDashboard((url) => {
      if (url.pathname === "/api/accounts") return { accounts: [{ id: "a", label: "A" }] };
      if (url.pathname === "/api/zones") return { zones: [{ id: "zone-a", name: "a.test", plan: "Free" }] };
      if (url.pathname === "/api/waf-settings") return { maxRangeSeconds: 86400, source: "cloudflare" };
      if (url.pathname === "/api/stats") {
        return {
          ...emptyWafSummary,
          byCountry: [{ key: "US", count: 4 }],
          byHost: [{ key: "a.test", count: 4 }],
        };
      }
      throw new Error(`Unexpected request: ${url}`);
    });

    await waitUntil(() => dashboard.requests.some((url) => url.pathname === "/api/stats"));
    (dashboard.document.querySelector("#pathFilter") as HTMLTextAreaElement).value = "/a,b\n/second";
    (dashboard.document.querySelector("#uaFilter") as HTMLTextAreaElement).value =
      "Bot/1.0 (alpha, beta)\nBrowser/2.0 (gamma, delta)";
    (dashboard.document.querySelector("#refresh") as HTMLButtonElement).click();
    await waitUntil(() => dashboard.requests.filter((url) => url.pathname === "/api/stats").length === 2);

    const statsUrl = dashboard.requests.filter((url) => url.pathname === "/api/stats").at(-1)!;
    expect(statsUrl.searchParams.getAll("path")).toEqual(["/a,b", "/second"]);
    expect(statsUrl.searchParams.getAll("ua")).toEqual([
      "Bot/1.0 (alpha, beta)",
      "Browser/2.0 (gamma, delta)",
    ]);

    const countryControl = dashboard.document.querySelector("#chartCountryControls button") as HTMLButtonElement;
    expect(countryControl.tagName).toBe("BUTTON");
    expect(countryControl.getAttribute("aria-pressed")).toBe("false");
    countryControl.click();
    await waitUntil(() => dashboard.requests.filter((url) => url.pathname === "/api/stats").length === 3);
    const filteredUrl = dashboard.requests.filter((url) => url.pathname === "/api/stats").at(-1)!;
    expect(filteredUrl.searchParams.getAll("country")).toEqual(["US"]);

    const action = dashboard.document.querySelector("#actionChips .chip") as HTMLButtonElement;
    expect(action.tagName).toBe("BUTTON");
    expect(action.getAttribute("aria-pressed")).toBe("false");
    action.click();
    expect(action.getAttribute("aria-pressed")).toBe("true");
    expect(dashboard.document.querySelectorAll('canvas[role="img"][aria-label]').length).toBeGreaterThan(0);
    await closeDashboard(dashboard);
  });
});
