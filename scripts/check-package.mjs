import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
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

// Every exported subpath is import-tested, derived from the exports map so a
// new subpath cannot ship untested.
const exportSpecifiers = Object.keys(packageJson.exports).map((key) =>
  key === "." ? packageJson.name : `${packageJson.name}${key.slice(1)}`,
);
// Names and subpaths the documentation tells consumers to import, verified
// against the installed tarball rather than the source tree: the exports map
// is invisible from src/, so a wrong subpath reads as correct there.
const documentedReferences = await collectDocumentedReferences();
await verifyAndroidInstallVersion();

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
  ]) {
    if (!paths.has(required)) {
      throw new Error(`Packed artifact is missing ${required}.`);
    }
  }
  if ([...paths].some((path) => path.startsWith("fixtures/"))) {
    throw new Error("Consumer-specific fixtures must not be published.");
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
    import { readFile } from "node:fs/promises";

    for (const specifier of ${JSON.stringify(exportSpecifiers)}) {
      await import(specifier);
    }

    async function declarationText(url, seen = new Set()) {
      const path = url.replace(/\\.js$/, ".d.ts");
      if (seen.has(path)) return "";
      seen.add(path);
      let text;
      try {
        text = await readFile(new URL(path), "utf8");
      } catch {
        return "";
      }
      for (const match of text.matchAll(/export \\* from ["']([^"']+)["']/g)) {
        text += await declarationText(new URL(match[1], path).href, seen);
      }
      return text;
    }
    const unresolved = [];
    for (const { file, specifier, names } of ${JSON.stringify(documentedReferences)}) {
      let module;
      try {
        module = await import(specifier);
      } catch {
        unresolved.push(file + ": cannot import " + specifier);
        continue;
      }
      const declarations = await declarationText(import.meta.resolve(specifier));
      for (const name of names) {
        if (name in module) continue;
        const declared = new RegExp(
          "\\\\b(?:class|interface|type|function|const|enum)\\\\s+" + name + "\\\\b" +
            "|\\\\bas\\\\s+" + name + "\\\\b" +
            // Named re-exports, including type-only ones: export type { A, B } from "..."
            "|export\\\\s+(?:type\\\\s+)?\\\\{[^}]*\\\\b" + name + "\\\\b[^}]*\\\\}",
        );
        if (declared.test(declarations)) continue;
        unresolved.push(file + ": " + name + " is not exported from " + specifier);
      }
    }
    if (unresolved.length > 0) {
      throw new Error(
        "Documentation references that do not resolve against the packed artifact:\\n  " +
          unresolved.join("\\n  "),
      );
    }

    const sharing = await import("@keyneom/sync-kit/sharing/web-crypto");
    const owner = await sharing.createWebCryptoSharingIdentity();
    const recipient = await sharing.createWebCryptoSharingIdentity();
    const invitation = await sharing.createSharingInvitationV1(owner, {
      appId: "packed-consumer",
      appFolderId: "folder",
      recipientDrivePermissionId: "permission",
      requestedGrants: [{ datasetId: "profile", role: "writer" }],
    });
    const response = await sharing.createSharingPublicKeyResponseV1(recipient, {
      appId: "packed-consumer",
      exchangeId: invitation.exchangeId,
    });
    const accepted = await sharing.acceptSharingPublicKeyResponseV1(
      invitation,
      response,
      {
        acceptedByKeyId: owner.publicKey.keyId,
        drivePermissionId: "permission",
      },
    );
    if (accepted.length !== 1 || accepted[0].datasetId !== "profile") {
      throw new Error("Packed sharing exchange failed.");
    }
    const codec = {
      serialize: value => value,
      parse: value => value,
    };
    const envelope = await sharing.createSharedBackupEnvelopeV1(
      { packed: true },
      codec,
      owner,
      {
        appId: "packed-consumer",
        backupId: "profile",
        participants: [
          { publicKey: owner.publicKey, role: "owner" },
          accepted[0].participant,
        ],
      },
    );
    const decrypted = await sharing.decryptSharedBackupEnvelopeV1(
      envelope,
      codec,
      recipient,
    );
    if (decrypted.packed !== true) {
      throw new Error("Packed sharing decryption failed.");
    }
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

async function collectDocumentedReferences() {
  // Release notes are excluded: they record the package as it was at that
  // release, so a later rename must not fail the build on history, and they
  // illustrate patterns with placeholders. Current guidance must match today.
  const docs = (await readdir(new URL("docs/", root)))
    .filter((name) => name.endsWith(".md") && !name.startsWith("release-notes-"))
    .map((name) => `docs/${name}`);
  const references = [];
  for (const file of ["README.md", ...docs]) {
    const text = await readFile(new URL(file, root), "utf8");
    // import { a, type B } from "@keyneom/sync-kit/..."
    for (const match of text.matchAll(
      /import\s*(?:type\s*)?\{([^}]+)\}\s*from\s*["'](@keyneom\/sync-kit[^"']*)["']/g,
    )) {
      const names = match[1]
        .split(",")
        .map((part) => part.trim().replace(/^type\s+/, "").split(/\s+as\s+/)[0])
        .filter(Boolean);
      references.push({ file, specifier: match[2], names });
    }
    // `Name` (`/subpath`) — the table shape that shipped a wrong subpath in 0.4.3.
    for (const match of text.matchAll(/`([A-Za-z][A-Za-z0-9]*)`\s*\(`(\/[a-z][a-z0-9/-]*)`\)/g)) {
      references.push({ file, specifier: `${packageJson.name}${match[2]}`, names: [match[1]] });
    }
    // `/subpath` — `Name`, the README export-list shape.
    for (const match of text.matchAll(/`(\/[a-z][a-z0-9/-]*)`\s*—\s*`([A-Za-z][A-Za-z0-9]*)`/g)) {
      references.push({ file, specifier: `${packageJson.name}${match[1]}`, names: [match[2]] });
    }
  }
  return references;
}

// The Android install snippet drifted to a pre-mutator version for four
// releases; it must name the version being published.
async function verifyAndroidInstallVersion() {
  const text = await readFile(new URL("docs/android-library.md", root), "utf8");
  const versions = [...text.matchAll(/sync-kit-android:([^"'`\s)]+)/g)].map((match) => match[1]);
  if (versions.length === 0) {
    throw new Error("docs/android-library.md has no sync-kit-android install coordinate.");
  }
  const stale = versions.filter((version) => version !== packageJson.version);
  if (stale.length > 0) {
    throw new Error(
      `docs/android-library.md installs sync-kit-android ${stale.join(", ")}; this release is ${packageJson.version}.`,
    );
  }
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
