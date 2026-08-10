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

  class ChartMock {
    canvas: HTMLCanvasElement;
    data: any;
    chartArea = { left: 40, right: 300, top: 10, bottom: 250 };

    constructor(canvas: HTMLCanvasElement, config: any) {
      this.canvas = canvas;
      this.data = config.data;
    }

    destroy() {}
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
  return { dom, window: dom.window, document: dom.window.document, requests };
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

describe("dashboard filters and accessibility", () => {
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
