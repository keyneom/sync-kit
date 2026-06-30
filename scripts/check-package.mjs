import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = new URL("..", import.meta.url);
const packageJson = JSON.parse(
  await readFile(new URL("package.json", root), "utf8"),
);

if (
  packageJson.private !== false ||
  packageJson.publishConfig?.access !== "public"
) {
  throw new Error("The package is not configured for public publication.");
}
if (!packageJson.license) throw new Error("A public package license is required.");

const temporaryDirectory = await mkdtemp(join(tmpdir(), "sync-kit-pack-"));
try {
  const packed = run(
    "npm",
    [
      "pack",
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      temporaryDirectory,
    ],
    root,
  );
  const report = JSON.parse(packed)[0];
  const paths = new Set(report.files.map((file) => file.path));
  for (const required of [
    "LICENSE",
    "README.md",
    "dist/index.js",
    "dist/index.d.ts",
    "fixtures/v1/easybc-web-android-gzip.json",
    "fixtures/v1/family-chores-web-uncompressed.json",
  ]) {
    if (!paths.has(required)) {
      throw new Error(`Packed artifact is missing ${required}.`);
    }
  }

  const tarball = join(temporaryDirectory, report.filename);
  await verifyInstalledPackage("npm", tarball);
  await verifyInstalledPackage("pnpm", tarball);
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

async function verifyInstalledPackage(packageManager, tarball) {
  const consumer = join(temporaryDirectory, `${packageManager}-consumer`);
  const source = `
    await import("@keyneom/sync-kit");
    await import("@keyneom/sync-kit/core");
    await import("@keyneom/sync-kit/crypto");
    await import("@keyneom/sync-kit/snapshot");
    await import("@keyneom/sync-kit/snapshot/lifecycle");
    await import("@keyneom/sync-kit/keys/web-passkey");
    await import("@keyneom/sync-kit/auth/google-web");
    await import("@keyneom/sync-kit/stores/google-drive");
  `;
  await mkdir(consumer, { recursive: true });
  await writeFile(
    join(consumer, "package.json"),
    '{"name":"consumer","private":true,"type":"module"}\n',
  );
  await writeFile(join(consumer, "index.mjs"), source);

  if (packageManager === "npm") {
    run(
      "npm",
      ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
      consumer,
    );
  } else {
    run(
      "pnpm",
      [
        "add",
        "--ignore-scripts",
        "--store-dir",
        join(temporaryDirectory, "pnpm-store"),
        tarball,
      ],
      consumer,
    );
  }
  run(process.execPath, ["index.mjs"], consumer);
}

function run(command, arguments_, cwd) {
  const result = spawnSync(command, arguments_, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      npm_config_cache: join(temporaryDirectory, "npm-cache"),
    },
  });
  if (result.status !== 0) {
    throw new Error(
      result.stderr || result.stdout || `${command} exited unsuccessfully.`,
    );
  }
  return result.stdout;
}
