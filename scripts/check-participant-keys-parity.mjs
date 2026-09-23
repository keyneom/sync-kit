// Verifies an Android-built participant-keys history with the web package:
// every revision verifies against the pinned owner, the Android-sealed recovery
// key opens here from its code alone, and it decrypts each revision.
import { readFile } from "node:fs/promises";
import { webcrypto as crypto } from "node:crypto";
import { sharedBackupAdditionalKeys } from "../dist/sharing/index.js";
import { openSharingRecoveryKeyFromEnvelopeV1 } from "../dist/sharing/participant-keys.js";
import {
  decryptSharedBackupEnvelopeV1,
  verifySharedBackupEnvelopeV1,
} from "../dist/sharing/web-crypto.js";

const report = JSON.parse(await readFile(process.argv[2], "utf8"));
const codec = { serialize: (value) => value, parse: (value) => value };
const fail = (message) => {
  console.error(`participant-keys parity: ${message}`);
  process.exit(1);
};

for (const [name, envelope] of Object.entries(report.envelopes)) {
  await verifySharedBackupEnvelopeV1(envelope, crypto, { trustedOwnerKeyId: report.ownerKeyId });
  if (envelope.schemaVersion !== 2) fail(`${name} is not schemaVersion 2`);
}
const opened = await openSharingRecoveryKeyFromEnvelopeV1(
  { code: report.recoveryCode, envelope: report.envelopes.withRecovery },
  { crypto },
);
if (opened.identity.publicKey.keyId !== report.recoveryKeyId) {
  fail("the recovery code opened the wrong key");
}
for (const [name, secret] of Object.entries(report.secrets)) {
  const value = await decryptSharedBackupEnvelopeV1(report.envelopes[name], codec, opened.identity, crypto);
  if (value.secret !== secret) fail(`${name} decrypted to ${JSON.stringify(value)}`);
}
const moved = sharedBackupAdditionalKeys(report.envelopes.rotated)[0]?.principalKeyId;
if (moved !== report.replacementKeyId) fail("the rotation did not move the recovery key");
console.log("OK: web verifies Android participant keys and opens its sealed recovery key.");
