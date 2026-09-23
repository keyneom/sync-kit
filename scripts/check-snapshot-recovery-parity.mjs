// Opens an Android-built v2 snapshot with the web package, both with the
// passkey secret and with the Android-sealed recovery code.
import { readFile } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";
import {
  createV1EnvelopeCrypto,
  createWebCryptoBackend,
  defineV1CompatibilityProfile,
  deriveContentKey,
} from "../dist/crypto/index.js";

const report = JSON.parse(await readFile(process.argv[2], "utf8"));
const fail = (message) => {
  console.error(`snapshot-recovery parity: ${message}`);
  process.exit(1);
};
const backend = createWebCryptoBackend();
const profile = defineV1CompatibilityProfile({
  ...report.profile,
  filename: `${report.profile.appId}.json`,
  compression: "gzip-if-smaller",
  passkey: {
    rpName: "Recovery App",
    userName: "user",
    userDisplayName: "User",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60000,
  },
  readVersions: [1, 2],
});
const codec = {
  serialize: (value) => value,
  parse: (value) => value,
  merge: (local) => local,
  fingerprint: (value) => JSON.stringify(value),
  updatedAt: (value) => value.updatedAt,
};
const crypto = createV1EnvelopeCrypto(profile, codec, backend);
if (report.envelope.schemaVersion !== 2) fail("the Android snapshot is not v2");
const key = await deriveContentKey(
  profile,
  Buffer.from(report.prfSecret, "base64url"),
  Buffer.from(report.envelope.kdfSalt, "base64url"),
  backend,
);
if (!isDeepStrictEqual(await crypto.decrypt(report.envelope, key), report.expected)) {
  fail("the passkey did not decrypt the expected value");
}
if (!isDeepStrictEqual(await crypto.decryptWithRecoveryCode(report.envelope, report.recoveryCode), report.expected)) {
  fail("the recovery code did not decrypt the expected value");
}
console.log("OK: web opens Android v2 snapshots with the passkey and the recovery code.");
