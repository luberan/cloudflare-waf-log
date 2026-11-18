import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const advisoryUrl = "https://github.com/advisories/GHSA-fc5q-39xc-vjpf";
const audit = spawnSync("npm", ["audit", "--audit-level=high", "--json"], { encoding: "utf8" });

if (audit.error) {
  console.error(audit.error);
  process.exitCode = 1;
} else {
  let report;
  try {
    report = JSON.parse(audit.stdout);
  } catch {
    console.error("npm audit did not return valid JSON.");
    process.stderr.write(audit.stderr);
    process.stdout.write(audit.stdout);
    process.exitCode = audit.status || 1;
  }

  if (report && audit.status === 0) {
    console.log("Dependency audit passed.");
  } else if (report && audit.status !== 1) {
    console.error(audit.stderr || "npm audit failed.");
    process.exitCode = audit.status || 1;
  } else if (report) {
    const lockfile = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
    const picomatchPackages = Object.entries(lockfile.packages)
      .filter(([path]) => path.endsWith("node_modules/picomatch"));
    const picomatchFinding = report.vulnerabilities?.picomatch;
    const hasExpectedAdvisory = picomatchFinding?.severity === "high"
      && picomatchFinding.via?.some(
        finding => typeof finding === "object"
          && finding.name === "picomatch"
          && finding.severity === "high"
          && finding.url === advisoryUrl,
      );
    const onlyDevelopmentPicomatch = picomatchPackages.length > 0
      && picomatchPackages.every(([, pkg]) => pkg.version === "4.0.7" && pkg.dev === true);

    function causedOnlyByExpectedAdvisory(packageName, ancestors = new Set()) {
      if (ancestors.has(packageName)) return false;
      const finding = report.vulnerabilities?.[packageName];
      if (!finding?.via?.length) return false;

      const nextAncestors = new Set(ancestors).add(packageName);
      return finding.via.every(item => {
        if (typeof item === "string") {
          return causedOnlyByExpectedAdvisory(item, nextAncestors);
        }
        return packageName === "picomatch"
          && item.name === "picomatch"
          && item.url === advisoryUrl;
      });
    }

    const highOrCritical = Object.entries(report.vulnerabilities || {})
      .filter(([, finding]) => finding.severity === "high" || finding.severity === "critical");
    const isOnlyExpectedAdvisory = highOrCritical.length > 0
      && highOrCritical.every(([name]) => causedOnlyByExpectedAdvisory(name));

    if (hasExpectedAdvisory && onlyDevelopmentPicomatch && isOnlyExpectedAdvisory) {
      console.warn(
        `Allowing ${advisoryUrl}: no patched release is available, and the affected picomatch@4.0.7 copies are development-only.`,
      );
    } else {
      process.stderr.write(audit.stderr);
      process.stdout.write(audit.stdout);
      process.exitCode = audit.status || 1;
    }
  }
}
