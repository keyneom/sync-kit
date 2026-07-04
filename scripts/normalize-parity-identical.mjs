import { readFileSync, writeFileSync } from "node:fs";

const [inputPath, outputPath] = process.argv.slice(2);
if (!inputPath || !outputPath) {
  console.error(
    "Usage: node scripts/normalize-parity-identical.mjs <report.json> <out.json>",
  );
  process.exit(2);
}

const report = JSON.parse(readFileSync(inputPath, "utf8"));
const identical = report.identical;
const normalizeRejection = (value) => ({
  rejected: value.rejected,
  code: value.code ?? null,
});

const omitNullCompression = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const next = { ...value };
  if (next.compression == null) delete next.compression;
  return next;
};

const normalized = {
  contentKeys: identical.contentKeys,
  fixtureSummaries: Object.fromEntries(
    Object.entries(identical.fixtureSummaries).map(([key, value]) => [
      key,
      omitNullCompression(value),
    ]),
  ),
  parseRejections: Object.fromEntries(
    Object.entries(identical.parseRejections).map(([key, value]) => [
      key,
      normalizeRejection(value),
    ]),
  ),
  encryptUncompressed: omitNullCompression(identical.encryptUncompressed),
  encryptFamilyChores: omitNullCompression(identical.encryptFamilyChores),
  wrongSecretRejected: normalizeRejection(identical.wrongSecretRejected),
};

writeFileSync(outputPath, `${JSON.stringify(normalized, null, 2)}\n`);
