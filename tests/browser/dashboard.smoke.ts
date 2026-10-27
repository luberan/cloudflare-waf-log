import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test as base, type Page } from "@playwright/test";

const csv = "datetime,action\r\n2026-10-20T12:00:00Z,block\r\n";
const assets = new Map([
  ["/", { path: "../../public/index.html", contentType: "text/html" }],
  ["/app.js", { path: "../../public/app.js", contentType: "text/javascript" }],
  ["/vendor/chart.umd.min.js", { path: "../../public/vendor/chart.umd.min.js", contentType: "text/javascript" }],
]);

function responseRange(url: URL) {
  const since = url.searchParams.get("since");
  const until = url.searchParams.get("until");
  if (!since || !until) throw new Error(`Missing time bounds: ${url}`);
  const seconds = (Date.parse(until) - Date.parse(since)) / 1000;
  if (!Number.isFinite(seconds) || seconds <= 0) throw new Error(`Invalid time bounds: ${url}`);
  return {
    effectiveSince: since,
    effectiveUntil: until,
    requestedSeconds: seconds,
    effectiveSeconds: seconds,
    maxRangeSeconds: 86400,
    limitSource: "cloudflare",
    clamped: false,
  };
}

function wafSummary(url: URL) {
  const range = responseRange(url);
  const hour = new Date(Math.ceil(Date.parse(range.effectiveSince) / 3600000) * 3600000).toISOString();
  return {
    cache: "MISS",
    byAction: [{ key: "block", count: 2 }, { key: "allow", count: 1 }],
    byCountry: [{ key: "US", count: 2 }, { key: "CZ", count: 1 }],
    byHost: [{ key: "example.test", count: 3 }],
    bySource: [{ key: "waf", count: 3 }],
    byRule: [{ key: "smoke-rule", count: 3 }],
    byPath: [{ key: "/login", count: 3 }],
    byAsn: [],
    byUserAgent: [],
    series: [{ hour, action: "block", count: 2 }, { hour, action: "allow", count: 1 }],
    events: ["block", "block", "allow"].map((action, index) => ({
      datetime: hour,
      action,
      source: "waf",
      clientCountryName: index < 2 ? "US" : "CZ",
      clientIP: `192.0.2.${index + 1}`,
      clientAsn: 64500,
      clientRequestHTTPHost: "example.test",
      clientRequestPath: "/login",
      clientRequestHTTPMethodName: "GET",
      ruleId: "smoke-rule",
      rayName: `smoke-ray-${index}`,
    })),
    sampledRows: 3,
    matchedSampledRows: 3,
    sampling: { dataset: "firewallEventsAdaptive", adaptive: true, rowLimitReached: false },
    range,
  };
}

function httpSummary(url: URL) {
  const range = responseRange(url);
  return {
    cache: "MISS",
    dataset: "adaptive",
    timeDim: "datetimeHour",
    range,
    totals: { requests: 120, bytes: 2048, visits: 6, uniqueIps: null, cachedPct: 75 },
    series: [{ t: range.effectiveSince, requests: 120, bytes: 2048 }],
    byStatus: [{ key: "200", requests: 120 }],
    byCountry: [{ key: "US", requests: 120 }],
    byHost: [{ key: "example.test", requests: 120 }],
    byPath: [{ key: "/login", requests: 120, bytes: 2048 }],
    byContentType: [{ key: "text/html", requests: 120 }],
    byHttpVersion: [{ key: "HTTP/2", requests: 120 }],
    byCacheStatus: [{ key: "hit", requests: 90 }, { key: "miss", requests: 30 }],
    perf: null,
  };
}

const test = base.extend({
  page: async ({ page }, use) => {
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("console", message => {
      if (message.type() === "error") errors.push(message.text());
    });
    await page.route("**/*", async route => {
      const url = new URL(route.request().url());
      if (url.origin !== "https://dashboard.test") throw new Error(`Unexpected external request: ${url}`);
      const asset = assets.get(url.pathname);
      if (asset) {
        await route.fulfill({
          path: fileURLToPath(new URL(asset.path, import.meta.url)),
          contentType: asset.contentType,
        });
        return;
      }
      switch (url.pathname) {
        case "/favicon.ico":
          await route.fulfill({ status: 204 });
          return;
        case "/api/accounts":
          await route.fulfill({ json: { accounts: [{ id: "smoke", label: "Smoke account" }] } });
          return;
        case "/api/zones":
          await route.fulfill({ json: { zones: [{ id: "smoke-zone", name: "example.test", plan: "Free" }] } });
          return;
        case "/api/waf-settings":
          await route.fulfill({ json: { maxRangeSeconds: 86400, source: "cloudflare" } });
          return;
        case "/api/stats":
          await route.fulfill({ json: wafSummary(url) });
          return;
        case "/api/http-stats":
          await route.fulfill({ json: httpSummary(url) });
          return;
        case "/api/export.csv":
          await route.fulfill({
            body: csv,
            contentType: "text/csv",
            headers: { "content-disposition": 'attachment; filename="waf-smoke.csv"' },
          });
          return;
        default:
          throw new Error(`Unexpected smoke-test request: ${url}`);
      }
    });
    await use(page);
    expect(errors, "Dashboard must not produce browser errors").toEqual([]);
  },
});

async function openDashboard(page: Page) {
  await page.goto("/");
  await expect(page.locator("#kpiTotal")).toHaveText("3");
  await expect(page.getByRole("button", { name: "Load", exact: true })).toBeEnabled();
  await expect(page.getByRole("alert")).toBeHidden();
}

async function expectRenderedChart(page: Page, selector: string) {
  await expect.poll(() => page.locator(selector).evaluate(canvas => {
    if (!(canvas instanceof HTMLCanvasElement)) throw new Error("Expected a chart canvas");
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Canvas rendering is unavailable");
    return context.getImageData(0, 0, canvas.width, canvas.height).data.some(value => value !== 0);
  })).toBe(true);
}

test("renders WAF events and real Chart.js canvases", async ({ page }) => {
  await openDashboard(page);
  await expect(page.getByLabel("Account:")).toHaveValue("smoke");
  await expect(page.getByLabel("Zone:")).toHaveValue("smoke-zone");
  await expect(page.locator("#kpiBlock")).toHaveText("2");
  await expect(page.locator("#tblEvents tbody tr")).toHaveCount(3);
  await expectRenderedChart(page, "#chartSeries");
  await expectRenderedChart(page, "#chartCountry");
});

test("sends country filters and exports the same time snapshot", async ({ page }) => {
  await openDashboard(page);
  await page.locator("#filtersDetails summary").click();
  await page.getByLabel("Country", { exact: true }).fill("US");
  const statsRequest = page.waitForRequest(request => {
    const url = new URL(request.url());
    return url.pathname === "/api/stats" && url.searchParams.get("country") === "US";
  });
  await page.getByRole("button", { name: "Load", exact: true }).click();
  const statsUrl = new URL((await statsRequest).url());
  await expect(page.locator("#filtersActiveCount")).toHaveText("1");
  await expect(page.getByRole("button", { name: "Export CSV", exact: true })).toBeEnabled();

  const exportRequest = page.waitForRequest(request => new URL(request.url()).pathname === "/api/export.csv");
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export CSV", exact: true }).click();
  const exportUrl = new URL((await exportRequest).url());
  for (const key of ["account", "zone", "country", "since", "until"]) {
    expect(exportUrl.searchParams.get(key)).toBe(statsUrl.searchParams.get(key));
  }
  const download = await downloaded;
  expect(download.suggestedFilename()).toBe("waf-smoke.csv");
  const path = await download.path();
  if (!path) throw new Error("CSV download was not saved");
  expect(await readFile(path, "utf8")).toBe(csv);
});

test("switches between WAF and HTTP with keyboard navigation", async ({ page }) => {
  await openDashboard(page);
  await page.locator("#tab-waf").focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.locator("#tab-http")).toBeFocused();
  await expect(page.locator("#tab-http")).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("#view-waf")).toBeHidden();
  await expect(page.locator("#hkpiReq")).toHaveText("120");
  await expect(page.getByRole("button", { name: "Export CSV", exact: true })).toBeHidden();
  await expect(page.locator("#tblHttpStatus tbody tr")).toHaveCount(1);
  await expectRenderedChart(page, "#chartHttpSeries");

  await page.keyboard.press("ArrowLeft");
  await expect(page.locator("#tab-waf")).toBeFocused();
  await expect(page.locator("#view-http")).toBeHidden();
  await expect(page.locator("#kpiTotal")).toHaveText("3");
  await expect(page.getByRole("alert")).toBeHidden();
});
