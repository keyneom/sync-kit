import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  createSharingInvitationV1,
  createSharingPublicKeyResponseV1,
  createWebCryptoSharingIdentity,
  verifySharingInvitationV1,
  verifySharingPublicKeyResponseV1,
} from "../src/sharing/web-crypto.js";
import {
  buildSharingJoinLinkV1,
  buildSharingResponseLinkV1,
  decodeSharingInvitationV1,
  decodeSharingPublicKeyResponseV1,
  encodeSharingInvitationV1,
  encodeSharingPublicKeyResponseV1,
  parseSharingJoinLinkV1,
  parseSharingResponseLinkV1,
  type SharingDatasetFileV1,
  verifySharingLinkDatasetFilesV1,
} from "../src/sharing/link-exchange.js";

const landing = "https://keyneom.github.io/easy-bc/";

async function makeInvitation() {
  const owner = await createWebCryptoSharingIdentity();
  const invitation = await createSharingInvitationV1(owner, {
    appId: "easy-bc",
    appFolderId: "app-folder-1",
    exchangeId: "exchange-1",
    recipientDrivePermissionId: "perm-1",
    requestedGrants: [
      { datasetId: "primary", role: "viewer" },
      { datasetId: "secondary", role: "writer" },
    ],
    createdAt: "2026-07-08T12:00:00.000Z",
  });
  return { owner, invitation };
}

describe("link-carried sharing exchange", () => {
  it("round-trips a signed invitation through encode/decode and still verifies", async () => {
    const { invitation } = await makeInvitation();
    const decoded = decodeSharingInvitationV1(encodeSharingInvitationV1(invitation));
    expect(decoded).toEqual(invitation);
    await expect(
      verifySharingInvitationV1(decoded, {
        now: () => new Date("2026-07-08T12:30:00.000Z"),
      }),
    ).resolves.toEqual(invitation);
  });

  it("round-trips a signed key response and still verifies", async () => {
    const recipient = await createWebCryptoSharingIdentity();
    const response = await createSharingPublicKeyResponseV1(recipient, {
      appId: "easy-bc",
      exchangeId: "exchange-1",
      createdAt: "2026-07-08T12:05:00.000Z",
    });
    const decoded = decodeSharingPublicKeyResponseV1(
      encodeSharingPublicKeyResponseV1(response),
    );
    expect(decoded).toEqual(response);
    await expect(verifySharingPublicKeyResponseV1(decoded)).resolves.toEqual(response);
  });

  it("builds and parses a join link carrying the invitation + files", async () => {
    const { invitation } = await makeInvitation();
    const files: SharingDatasetFileV1[] = [
      { datasetId: "primary", fileId: "file-primary", role: "viewer" },
      { datasetId: "secondary", fileId: "file-secondary", role: "writer" },
    ];
    const link = buildSharingJoinLinkV1({ landingUrl: landing, invitation, files });
    expect(link.startsWith(landing)).toBe(true);

    const parsed = parseSharingJoinLinkV1(link);
    if (!parsed) throw new Error("join link did not parse");
    expect(parsed.invitation).toEqual(invitation);
    expect(parsed.files).toEqual(files);
    // The signature survives the link round-trip.
    await expect(
      verifySharingInvitationV1(parsed.invitation, {
        now: () => new Date("2026-07-08T12:30:00.000Z"),
      }),
    ).resolves.toBeTruthy();
  });

  it("builds and parses a response link", async () => {
    const recipient = await createWebCryptoSharingIdentity();
    const response = await createSharingPublicKeyResponseV1(recipient, {
      appId: "easy-bc",
      exchangeId: "exchange-1",
      createdAt: "2026-07-08T12:05:00.000Z",
    });
    const link = buildSharingResponseLinkV1({ landingUrl: landing, response });
    const parsed = parseSharingResponseLinkV1(link);
    expect(parsed?.response).toEqual(response);
  });

  it("decodes and verifies the frozen cross-language fixture", async () => {
    // The same fixture the Kotlin LinkExchangeTest decodes + verifies.
    const fixture = JSON.parse(
      await readFile(
        new URL("../fixtures/sharing-v1/link-exchange.json", import.meta.url),
        "utf8",
      ),
    ) as {
      encodedInvitation: string;
      encodedResponse: string;
      joinLink: string;
      expected: { ownerKeyId: string; recipientKeyId: string };
    };
    const invitation = decodeSharingInvitationV1(fixture.encodedInvitation);
    const verified = await verifySharingInvitationV1(invitation, {
      now: () => new Date("2026-07-08T12:30:00.000Z"),
    });
    expect(verified.owner.keyId).toBe(fixture.expected.ownerKeyId);
    const response = decodeSharingPublicKeyResponseV1(fixture.encodedResponse);
    expect((await verifySharingPublicKeyResponseV1(response)).keyId).toBe(
      fixture.expected.recipientKeyId,
    );
    expect(parseSharingJoinLinkV1(fixture.joinLink)?.files.length).toBe(2);
    const parsedJoin = parseSharingJoinLinkV1(fixture.joinLink);
    if (!parsedJoin) throw new Error("fixture join link did not parse");
    await expect(
      verifySharingLinkDatasetFilesV1(
        parsedJoin.invitation,
        parsedJoin.files,
      ),
    ).resolves.toEqual(parsedJoin.files);
  });

  it("returns null for links that are not the expected kind", () => {
    expect(parseSharingJoinLinkV1(`${landing}?foo=bar`)).toBeNull();
    expect(parseSharingResponseLinkV1(`${landing}?sk-resp=1`)).toBeNull();
  });

  it("rejects a malformed dataset file list", async () => {
    const { invitation } = await makeInvitation();
    expect(() =>
      buildSharingJoinLinkV1({
        landingUrl: landing,
        invitation,
        files: [{ datasetId: "d", fileId: "f", role: "owner" as never }],
      }),
    ).toThrow();
  });
});
