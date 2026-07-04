/**
 * Decrypt the Kotlin peerChallenge envelope with the JS crypto stack.
 * Usage: node scripts/parity-v1-cross-decrypt.mjs <kotlin-report.json>
 */
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import {
  base64UrlToBytes,
  createWebCryptoBackend,
  decryptSyncEnvelopeV1,
  defineV1CompatibilityProfile,
  deriveContentKey,
} from "../dist/crypto/index.js";

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

const reportPath = process.argv[2];
if (!reportPath) {
  console.error("Usage: node scripts/parity-v1-cross-decrypt.mjs <kotlin-report.json>");
  process.exit(2);
}

const report = JSON.parse(await readFile(reportPath, "utf8"));
const challenge = report.peerChallenge;
if (challenge.profileAppId !== "easy-bc") {
  throw new Error(`Unexpected peer profile ${challenge.profileAppId}`);
}

const backend = createWebCryptoBackend();
const secret = base64UrlToBytes(challenge.secret);
const salt = sequence(32, 32);
const key = await deriveContentKey(easyBcTestProfile, secret, salt, backend);
const identityCodec = {
  serialize: (value) => value,
  parse: (value) => value,
  merge: (local) => local,
  fingerprint: (value) => stableFingerprint(value),
  updatedAt: (value) => value.exportedAt,
};

const payload = await decryptSyncEnvelopeV1(
  challenge.envelope,
  key,
  easyBcTestProfile,
  identityCodec,
  backend,
);
const fingerprint = stableFingerprint(payload);
if (fingerprint !== challenge.payloadFingerprint) {
  throw new Error(
    `JS could not validate Kotlin peer payload: ${fingerprint} != ${challenge.payloadFingerprint}`,
  );
}

process.stdout.write(
  `${JSON.stringify({ ok: true, platform: "js", peerPlatform: report.platform, fingerprint })}\n`,
);

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
