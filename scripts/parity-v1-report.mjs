/**
 * Emit a deterministic v1 parity report for comparison with the Kotlin library.
 * Requires `npm run build` first (imports from dist/).
 * Usage: node scripts/parity-v1-report.mjs > report.json
 */
import { readFile } from "node:fs/promises";
import { createHash, hkdfSync } from "node:crypto";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  createWebCryptoBackend,
  decryptSyncEnvelopeV1,
  defineV1CompatibilityProfile,
  deriveContentKey,
  encryptSyncEnvelopeV1,
  parseSyncEnvelopeV1,
} from "../dist/crypto/index.js";

const backend = createWebCryptoBackend();
const fixturesDir = new URL("../fixtures/v1/", import.meta.url);

const easyBcTestProfile = defineV1CompatibilityProfile({
  appId: "easy-bc",
  filename: "easybc-sync-v1.json",
  aad: "easy-bc-sync-envelope-v1",
  hkdfInfo: "easy-bc-cloud-content-key-v1",
  compression: "gzip-if-smaller",
  passkey: {
    rpName: "EasyBC",
    userName: "encrypted-sync",
    userDisplayName: "EasyBC encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
});

const familyChoresTestProfile = defineV1CompatibilityProfile({
  appId: "family-chores",
  filename: "family-chores-sync-v1.json",
  aad: "family-chores-sync-envelope-v1",
  hkdfInfo: "family-chores-cloud-content-key-v1",
  compression: "none",
  passkey: {
    rpName: "Family Chores",
    userName: "encrypted-sync",
    userDisplayName: "Family Chores encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
});

const secret = sequence(0, 32);
const salt = sequence(32, 32);
const nonce = sequence(64, 12);
const prfInput = sequence(96, 32);

const identityCodec = {
  serialize: (value) => value,
  parse: (value) => value,
  merge: (local) => local,
  fingerprint: (value) => stableFingerprint(value),
  updatedAt: (value) => value.exportedAt,
};

const metadata = {
  credentialId: "parity-credential",
  rpId: "keyneom.github.io",
  prfInput,
  kdfSalt: salt,
};

const smallPayload = {
  schemaVersion: 1,
  exportedAt: "2026-07-04T00:00:00.000Z",
  text: "parity-vector",
};

const compressiblePayload = {
  schemaVersion: 1,
  exportedAt: "2026-07-04T00:00:00.000Z",
  text: "repeated private journal text ".repeat(200),
};

const report = {
  version: 1,
  platform: "js",
  identical: {
    contentKeys: {
      "easy-bc": bytesToBase64Url(rawContentKey(easyBcTestProfile)),
      "family-chores": bytesToBase64Url(rawContentKey(familyChoresTestProfile)),
    },
    fixtureSummaries: {},
    parseRejections: {},
    encryptUncompressed: null,
    encryptFamilyChores: null,
  },
  peerChallenge: {
    description:
      "Compressed EasyBC envelope for the other platform to decrypt (gzip bytes may differ by platform).",
    profileAppId: "easy-bc",
    secret: bytesToBase64Url(secret),
    envelope: null,
    payloadFingerprint: stableFingerprint(compressiblePayload),
  },
};

const easyBcUncompressed = await loadFixture("easybc-web-uncompressed.json");
const easyBcGzip = await loadFixture("easybc-web-android-gzip.json");
const familyChores = await loadFixture("family-chores-web-uncompressed.json");
const failures = JSON.parse(
  await readFile(new URL("failures.json", fixturesDir), "utf8"),
);

report.identical.fixtureSummaries = {
  "easybc-web-uncompressed": await summarizeFixture(
    easyBcUncompressed,
    easyBcTestProfile,
  ),
  "easybc-web-android-gzip": await summarizeFixture(easyBcGzip, easyBcTestProfile),
  "family-chores-web-uncompressed": await summarizeFixture(
    familyChores,
    familyChoresTestProfile,
  ),
};

report.identical.parseRejections = {
  shortPrfInput: rejectParse({
    ...easyBcUncompressed.envelope,
    prfInput: "AA",
  }, easyBcTestProfile),
  malformedEnvelope: rejectParse(failures.malformedEnvelope, easyBcTestProfile),
  wrongLengthNonce: rejectParse({
    ...easyBcUncompressed.envelope,
    nonce: "AA",
  }, easyBcTestProfile),
};

const easyBcKey = await deriveContentKey(
  easyBcTestProfile,
  secret,
  salt,
  backend,
);
const familyKey = await deriveContentKey(
  familyChoresTestProfile,
  secret,
  salt,
  backend,
);

report.identical.encryptUncompressed = await encryptSyncEnvelopeV1(
  smallPayload,
  easyBcKey,
  metadata,
  easyBcTestProfile,
  identityCodec,
  backend,
  { nonce },
);

report.identical.encryptFamilyChores = await encryptSyncEnvelopeV1(
  smallPayload,
  familyKey,
  metadata,
  familyChoresTestProfile,
  identityCodec,
  backend,
  { nonce },
);

if (report.identical.encryptUncompressed.compression) {
  throw new Error("Expected small EasyBC parity payload to stay uncompressed.");
}
if (report.identical.encryptFamilyChores.compression) {
  throw new Error("Expected Family Chores parity payload to stay uncompressed.");
}

for (const [name, envelope, profile, key] of [
  [
    "encryptUncompressed",
    report.identical.encryptUncompressed,
    easyBcTestProfile,
    easyBcKey,
  ],
  [
    "encryptFamilyChores",
    report.identical.encryptFamilyChores,
    familyChoresTestProfile,
    familyKey,
  ],
]) {
  const payload = await decryptSyncEnvelopeV1(
    envelope,
    key,
    profile,
    identityCodec,
    backend,
  );
  if (stableFingerprint(payload) !== stableFingerprint(smallPayload)) {
    throw new Error(`JS failed to round-trip ${name}.`);
  }
}

report.peerChallenge.envelope = await encryptSyncEnvelopeV1(
  compressiblePayload,
  easyBcKey,
  metadata,
  easyBcTestProfile,
  identityCodec,
  backend,
  { nonce },
);
if (report.peerChallenge.envelope.compression !== "gzip") {
  throw new Error("Expected compressible parity payload to use gzip.");
}

const wrongKey = await deriveContentKey(
  easyBcTestProfile,
  sequence(224, 32),
  salt,
  backend,
);
report.identical.wrongSecretRejected = await rejectDecrypt(
  easyBcUncompressed.envelope,
  wrongKey,
  easyBcTestProfile,
);

process.stdout.write(`${JSON.stringify(report)}\n`);

async function loadFixture(name) {
  return JSON.parse(await readFile(new URL(name, fixturesDir), "utf8"));
}

async function summarizeFixture(fixture, profile) {
  const key = await deriveContentKey(
    profile,
    base64UrlToBytes(fixture.secret),
    base64UrlToBytes(fixture.envelope.kdfSalt),
    backend,
  );
  const payload = await decryptSyncEnvelopeV1(
    fixture.envelope,
    key,
    profile,
    identityCodec,
    backend,
  );
  return {
    payloadFingerprint: stableFingerprint(payload),
    exportedAt: payload.exportedAt,
    envelopeUpdatedAt: fixture.envelope.updatedAt,
    compression: fixture.envelope.compression ?? null,
    ciphertextSha256: sha256Base64Url(fixture.envelope.ciphertext),
  };
}

function rejectParse(envelope, profile) {
  try {
    parseSyncEnvelopeV1(envelope, profile);
    return { rejected: false };
  } catch (error) {
    return {
      rejected: true,
      code: error?.code ?? "unknown",
      message: String(error?.message ?? error),
    };
  }
}

async function rejectDecrypt(envelope, key, profile) {
  try {
    await decryptSyncEnvelopeV1(envelope, key, profile, identityCodec, backend);
    return { rejected: false };
  } catch (error) {
    return {
      rejected: true,
      code: error?.code ?? "unknown",
      message: String(error?.message ?? error),
    };
  }
}

function rawContentKey(profile) {
  return hkdfSync(
    "sha256",
    secret,
    salt,
    Buffer.from(profile.hkdfInfo),
    32,
  );
}

function sequence(start, length) {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function stableFingerprint(value) {
  return createHash("sha256")
    .update(canonicalJson(value))
    .digest("base64url");
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function sha256Base64Url(value) {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}
