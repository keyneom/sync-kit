import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const files = [
  "easybc-web-android-gzip.json",
  "easybc-web-uncompressed.json",
  "failures.json",
  "family-chores-web-uncompressed.json",
  "profiles.json",
];
const before = await readFixtures();
const generated = spawnSync(process.execPath, ["scripts/generate-v1-fixtures.mjs"], {
  cwd: new URL("..", import.meta.url),
  encoding: "utf8",
});
if (generated.status !== 0) {
  throw new Error(generated.stderr || "Fixture generation failed.");
}
const after = await readFixtures();
for (const file of files) {
  if (before.get(file) !== after.get(file)) {
    throw new Error(`Fixture ${file} is not deterministic.`);
  }
}

async function readFixtures() {
  return new Map(
    await Promise.all(
      files.map(async (file) => [
        file,
        await readFile(new URL(`../fixtures/v1/${file}`, import.meta.url), "utf8"),
      ]),
    ),
  );
}
