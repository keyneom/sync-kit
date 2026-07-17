import { readFile, writeFile } from "node:fs/promises";
import { webcrypto as crypto } from "node:crypto";
import {
  acceptSharedBackupOwnershipTransferV1,
  createSharedBackupEnvelopeV1,
  createSharedBackupOwnershipTransferProposalV1,
} from "../dist/sharing/web-crypto.js";

const sourceUrl = new URL(
  "../fixtures/sharing-v1/webcrypto-owner-viewer.json",
  import.meta.url,
);
const outputUrl = new URL(
  "../fixtures/sharing-v1/ownership-transfer-wire.json",
  import.meta.url,
);
const source = JSON.parse(await readFile(sourceUrl, "utf8"));

async function identityFromFixture(value) {
  return {
    publicKey: value.publicKey,
    encryptionPrivateKey: await crypto.subtle.importKey(
      "jwk",
      value.privateKeys.encryption,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    ),
    signingPrivateKey: await crypto.subtle.importKey(
      "jwk",
      value.privateKeys.signing,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    ),
  };
}

const owner = await identityFromFixture(source.owner);
const recipient = await identityFromFixture(source.viewer);
const accepted = {
  exchangeId: "ownership-transfer-exchange",
  drivePermissionId: "recipient-permission",
  acceptedAt: "2026-07-17T12:00:00.000Z",
  acceptedByKeyId: owner.publicKey.keyId,
};
const codec = {
  serialize: (value) => value,
  parse: (value) => value,
};
const before = await createSharedBackupEnvelopeV1(
  source.payload,
  codec,
  owner,
  {
    appId: "fixture-app",
    backupId: "fixture-backup",
    participants: [
      { publicKey: owner.publicKey, role: "owner" },
      { publicKey: recipient.publicKey, role: "writer", accepted },
    ],
    revisionId: "ownership-before",
    createdAt: "2026-07-17T12:00:00.000Z",
  },
);
const proposal = await createSharedBackupOwnershipTransferProposalV1(
  [before],
  owner,
  {
    toKeyId: recipient.publicKey.keyId,
    previousOwnerRole: "admin",
    providerPermissionIds: {
      "fixture-backup": "recipient-permission",
    },
    providerObjects: [
      {
        kind: "app-folder",
        fileId: "app-folder",
        providerPermissionId: "recipient-permission",
      },
      {
        kind: "exchanges-folder",
        fileId: "exchanges-folder",
        providerPermissionId: "recipient-permission",
      },
    ],
    transferId: "ownership-transfer-fixture",
    createdAt: "2026-07-17T12:01:00.000Z",
  },
);
const transfer = await acceptSharedBackupOwnershipTransferV1(
  proposal,
  [before],
  recipient,
);
const after = await createSharedBackupEnvelopeV1(
  source.payload,
  codec,
  recipient,
  {
    appId: "fixture-app",
    backupId: "fixture-backup",
    participants: [
      { publicKey: owner.publicKey, role: "admin" },
      { publicKey: recipient.publicKey, role: "owner", accepted },
    ],
    previous: before,
    ownershipTransfer: transfer,
    revisionId: "ownership-after",
    createdAt: "2026-07-17T12:02:00.000Z",
  },
);

await writeFile(
  outputUrl,
  `${JSON.stringify({
    payload: source.payload,
    owner: source.owner,
    recipient: source.viewer,
    before,
    transfer,
    after,
  }, null, 2)}\n`,
);
console.log("Wrote fixtures/sharing-v1/ownership-transfer-wire.json");
