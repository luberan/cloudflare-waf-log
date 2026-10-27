import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

let directory: string;
const bundle = "globalThis.Chart = { version: 'test' };\n";
const license = "Synthetic license fixture\n";

function runVendor(...args: string[]) {
  return spawnSync(process.execPath, [join(directory, "scripts", "vendor-chart.mjs"), ...args], {
    cwd: directory,
    encoding: "utf8",
  });
}

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "waf-chart-vendor-"));
  mkdirSync(join(directory, "scripts"));
  copyFileSync(
    new URL("../scripts/vendor-chart.mjs", import.meta.url),
    join(directory, "scripts", "vendor-chart.mjs"),
  );
  mkdirSync(join(directory, "node_modules", "chart.js", "dist"), { recursive: true });
  writeFileSync(join(directory, "node_modules", "chart.js", "dist", "chart.umd.js"), bundle);
  writeFileSync(join(directory, "node_modules", "chart.js", "LICENSE.md"), license);
});

afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
});

describe("vendored Chart.js", () => {
  it("copies both the locked bundle and its license", () => {
    const result = runVendor();

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(join(directory, "public", "vendor", "chart.umd.min.js"), "utf8")).toBe(bundle);
    expect(readFileSync(join(directory, "public", "vendor", "chart.js.LICENSE.md"), "utf8")).toBe(license);
    const check = runVendor("--check");
    expect(check.status, check.stderr).toBe(0);
  });

  it.each(["chart.umd.min.js", "chart.js.LICENSE.md"])("rejects a stale %s without rewriting it", filename => {
    const generated = runVendor();
    expect(generated.status, generated.stderr).toBe(0);
    const path = join(directory, "public", "vendor", filename);
    writeFileSync(path, "stale\n");

    const result = runVendor("--check");

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("differs from the locked Chart.js package");
    expect(result.stderr).toContain("npm run vendor:chart");
    expect(readFileSync(path, "utf8")).toBe("stale\n");
  });

  it("accepts Git's CRLF conversion without modifying the files", () => {
    const generated = runVendor();
    expect(generated.status, generated.stderr).toBe(0);
    const path = join(directory, "public", "vendor", "chart.umd.min.js");
    writeFileSync(path, bundle.replaceAll("\n", "\r\n"));

    const result = runVendor("--check");

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(path, "utf8")).toBe(bundle.replaceAll("\n", "\r\n"));
  });
});
