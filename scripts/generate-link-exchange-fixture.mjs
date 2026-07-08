// Cross-language conformance vector for the link-carried key exchange. The
// invitation and key response are created + encoded by the real WebCrypto
// implementation; the Kotlin suite decodes and verifies them (and vice-versa
// the format is symmetric base64url(JSON)), so the wire format can't drift.
//
// Run: node scripts/generate-link-exchange-fixture.mjs (after `npm run build`)

import { mkdir, writeFile } from "node:fs/promises";
import {
  createSharingInvitationV1,
  createSharingPublicKeyResponseV1,
  createWebCryptoSharingIdentity,
} from "../dist/sharing/web-crypto.js";
import {
  buildSharingJoinLinkV1,
  buildSharingResponseLinkV1,
  encodeSharingInvitationV1,
  encodeSharingPublicKeyResponseV1,
} from "../dist/sharing/index.js";

const outputDir = new URL("../fixtures/sharing-v1/", import.meta.url);
const landing = "https://keyneom.github.io/easy-bc/";

const owner = await createWebCryptoSharingIdentity();
const recipient = await createWebCryptoSharingIdentity();

const invitation = await createSharingInvitationV1(owner, {
  appId: "easy-bc",
  appFolderId: "app-folder-1",
  exchangeId: "exchange-1",
  recipientDrivePermissionId: "link",
  requestedGrants: [
    { datasetId: "primary", role: "viewer" },
    { datasetId: "secondary", role: "writer" },
  ],
  createdAt: "2026-07-08T12:00:00.000Z",
});

const response = await createSharingPublicKeyResponseV1(recipient, {
  appId: "easy-bc",
  exchangeId: "exchange-1",
  createdAt: "2026-07-08T12:05:00.000Z",
});

const files = [
  { datasetId: "primary", fileId: "file-primary", role: "viewer" },
  { datasetId: "secondary", fileId: "file-secondary", role: "writer" },
];

const fixture = {
  provenance: "Synthetic link-exchange WebCrypto conformance vector",
  encodedInvitation: encodeSharingInvitationV1(invitation),
  encodedResponse: encodeSharingPublicKeyResponseV1(response),
  joinLink: buildSharingJoinLinkV1({ landingUrl: landing, invitation, files }),
  responseLink: buildSharingResponseLinkV1({ landingUrl: landing, response }),
  expected: {
    ownerKeyId: owner.publicKey.keyId,
    recipientKeyId: recipient.publicKey.keyId,
    exchangeId: "exchange-1",
    appFolderId: "app-folder-1",
    files,
  },
};

await mkdir(outputDir, { recursive: true });
await writeFile(
  new URL("link-exchange.json", outputDir),
  JSON.stringify(fixture, null, 2) + "\n",
  "utf8",
);
console.log("Wrote fixtures/sharing-v1/link-exchange.json");
