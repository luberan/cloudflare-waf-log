import { mkdir, readFile, writeFile } from "node:fs/promises";

const check = process.argv.includes("--check");
if (process.argv.slice(2).some(argument => argument !== "--check")) {
  throw new Error("Usage: node scripts/vendor-chart.mjs [--check]");
}

const root = new URL("../", import.meta.url);
const files = [
  ["node_modules/chart.js/dist/chart.umd.js", "public/vendor/chart.umd.min.js"],
  ["node_modules/chart.js/LICENSE.md", "public/vendor/chart.js.LICENSE.md"],
];

if (!check) await mkdir(new URL("public/vendor/", root), { recursive: true });

for (const [source, destination] of files) {
  const expected = (await readFile(new URL(source, root), "utf8")).replaceAll("\r\n", "\n");
  if (check) {
    const actual = (await readFile(new URL(destination, root), "utf8")).replaceAll("\r\n", "\n");
    if (actual !== expected) {
      throw new Error(`${destination} differs from the locked Chart.js package. Run npm run vendor:chart.`);
    }
    console.log(`Verified ${destination}`);
  } else {
    await writeFile(new URL(destination, root), expected);
    console.log(`Updated ${destination}`);
  }
}
