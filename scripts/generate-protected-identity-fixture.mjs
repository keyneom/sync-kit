// Generates a cross-language conformance vector for the passkey-wrapped sharing
// identity (ProtectedSharingIdentityV1). The record is produced by the real
// WebCrypto implementation and unlocked by both the TS and Kotlin sync-kit
// suites, proving a web-wrapped identity round-trips on Android (and, with the
// symmetric wrap format + PKCS#8-both-ways probes, the reverse).
//
// Run: node scripts/generate-protected-identity-fixture.mjs (after `npm run build`)

import { mkdir, writeFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import {
  createProtectedSharingIdentityV1,
} from "../dist/sharing/web-passkey.js";
import { bytesToBase64Url } from "../dist/crypto/index.js";

const outputDir = new URL("../fixtures/sharing-v1/", import.meta.url);

// Deterministic-looking but arbitrary inputs; the wrapping key stands in for the
// passkey-PRF-derived content key so the vector needs no authenticator.
const sequence = (start, length) =>
  Uint8Array.from({ length }, (_, index) => (start + index) % 256);

const wrappingKeyBytes = sequence(0, 32);
const prfInput = sequence(64, 32);
const kdfSalt = sequence(128, 32);
const credentialId = bytesToBase64Url(sequence(200, 20));
const rpId = "keyneom.github.io";
const appId = "easy-bc";

const wrappingKey = await webcrypto.subtle.importKey(
  "raw",
  wrappingKeyBytes,
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"],
);

const { record } = await createProtectedSharingIdentityV1(
  appId,
  { credentialId, rpId, prfInput, kdfSalt },
  wrappingKey,
  webcrypto,
);

const fixture = {
  provenance: "Synthetic ProtectedSharingIdentityV1 WebCrypto conformance vector",
  wrappingKey: bytesToBase64Url(wrappingKeyBytes),
  record,
  expected: {
    keyId: record.publicKey.keyId,
    encryptionPublicKey: record.publicKey.encryptionPublicKey,
    signingPublicKey: record.publicKey.signingPublicKey,
  },
};

await mkdir(outputDir, { recursive: true });
await writeFile(
  new URL("protected-identity.json", outputDir),
  JSON.stringify(fixture, null, 2) + "\n",
  "utf8",
);
console.log("Wrote fixtures/sharing-v1/protected-identity.json");
