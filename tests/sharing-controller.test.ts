import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  createSharedBackupController,
  MemorySharedBackupRegistry,
  type SharedBackupControllerCodec,
} from "../src/sharing/controller.js";
import type {
  SharedBackupEnvelopeV1,
  SharingAccountBindingV1,
  SharingInvitationV1,
  SharingPublicKeyResponseV1,
  SharingRole,
} from "../src/sharing/index.js";
import {
  sharedBackupParticipant,
  sharedBackupParticipants,
} from "../src/sharing/index.js";
import type {
  SharedBackupStorage,
  SharedBackupTransport,
  SharedDatasetFile,
  SharedDatasetPermission,
  SharedExchangeFile,
  SharedKeyResponseFile,
  VersionedSharedDataset,
} from "../src/sharing/transport.js";
import {
  createSharedBackupEnvelopeV1,
  createSharingInvitationV1,
  createWebCryptoSharingIdentity,
  type WebCryptoSharingIdentity,
} from "../src/sharing/web-crypto.js";
import {
  buildSharingJoinLinkV1,
  buildSharingResponseLinkV1,
  parseSharingJoinLinkV1,
  parseSharingResponseLinkV1,
} from "../src/sharing/link-exchange.js";

type Payload = {
  items: string[];
};

type RoutedPayload = {
  kind: "application" | "control";
  items?: string[];
  entries?: string[];
};

type CodecCalls = {
  serialize: number;
  parse: number;
  merge: number;
  fingerprint: number;
};

type CodecRoutingFixture = {
  applicationDatasetId: string;
  controlDatasetId: string;
  applicationPayload: RoutedPayload;
  controlPayload: RoutedPayload;
  updatedControlPayload: RoutedPayload;
  branchControlPayload: RoutedPayload;
};

const codecRoutingFixture = JSON.parse(
  readFileSync(
    new URL(
      "../fixtures/sharing-v1/dataset-codec-routing.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as CodecRoutingFixture;

const codec: SharedBackupControllerCodec<Payload> = {
  serialize: (value) => value,
  parse: (value) => value as Payload,
  merge: (local, remote) => ({
    items: [...new Set([...remote.items, ...local.items])],
  }),
  fingerprint: (value) => JSON.stringify([...value.items].sort()),
};

describe("shared-backup controller", () => {
  it("completes a backendless invite, response, acceptance, and read flow", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const recipientRegistry = new MemorySharedBackupRegistry();
    const ownerController = controller(owner, transport, ownerRegistry);
    const recipientController = controller(
      recipient,
      transport,
      recipientRegistry,
    );

    await ownerController.createDataset("tasks", { items: ["owner"] });
    const invited = await ownerController.inviteParticipant({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
      expiresAt: "2026-07-08T12:00:00.000Z",
    });
    const submitted = await recipientController.submitKeyResponse(
      invited.invitationFileId,
    );
    const accepted = await ownerController.acceptKeyResponse({
      invitation: invited.invitation,
      responseFileId: submitted.responseFileId,
      recipientEmailAddress: "recipient@example.com",
    });

    expect(accepted).toMatchObject([
      {
        datasetId: "tasks",
        status: "accepted",
        permissionId: "permission-recipient@example.com",
      },
    ]);
    await expect(recipientController.loadDataset("tasks")).resolves.toMatchObject({
      value: { items: ["owner"] },
      outcome: "loaded",
    });
    await expect(
      recipientController.syncDataset("tasks", {
        items: ["owner", "recipient"],
      }),
    ).resolves.toMatchObject({
      value: { items: ["owner", "recipient"] },
      outcome: "updated",
    });
  });

  it("creates, requires, and verifies account binding during acceptance", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const binding: SharingAccountBindingV1 = {
      schemaVersion: 1,
      kind: "sync-kit-sharing-account-binding",
      challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      googleIdToken: "fixture.jwt.token",
      passkey: {
        credentialId: "Y3JlZGVudGlhbC0x",
        credentialPublicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
        authenticatorData: "AQ",
        clientDataJSON: "AQ",
        signature: "AQ",
      },
    };
    const ownerController = controller(
      owner,
      transport,
      new MemorySharedBackupRegistry(),
      {
        requireAccountBinding: true,
        verifyAccountBinding: async (received, context) => {
          expect(received).toEqual(binding);
          expect(context).toMatchObject({
            appId: "fixture-app",
            sharingKeyId: recipient.publicKey.keyId,
            credentialId: "Y3JlZGVudGlhbC0x",
          });
          return { subject: "google-subject" };
        },
      },
    );
    const recipientController = controller(
      recipient,
      transport,
      new MemorySharedBackupRegistry(),
      { createAccountBinding: async () => binding },
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });
    const invited = await ownerController.inviteParticipant({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
    });
    const submitted = await recipientController.submitKeyResponse(invited.invitationFileId);

    await ownerController.acceptKeyResponse({
      invitation: invited.invitation,
      responseFileId: submitted.responseFileId,
      recipientEmailAddress: "recipient@example.com",
    });

    const participants = await ownerController.getDatasetParticipants("tasks");
    expect(
      participants.participants.find(
        (participant) => participant.keyId === recipient.publicKey.keyId,
      )?.accepted?.googleSubject,
    ).toBe("google-subject");
  });

  it("completes a link-carried invite, response, and acceptance flow", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const ownerController = controller(
      owner,
      transport,
      ownerRegistry,
    );
    const recipientController = controller(
      recipient,
      transport,
      new MemorySharedBackupRegistry(),
    );
    const landing = "https://keyneom.github.io/easy-bc/";

    await ownerController.createDataset("tasks", { items: ["owner"] });

    // Owner: per-email-share the file(s) + sign the invitation, embed in a link.
    const invite = await ownerController.inviteParticipantForLink({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
    });
    expect(invite.files).toEqual([
      { datasetId: "tasks", fileId: "dataset-tasks", role: "writer" },
    ]);
    const joinLink = buildSharingJoinLinkV1({
      landingUrl: landing,
      invitation: invite.invitation,
      files: invite.files,
    });

    // Recipient: parse the link, produce a response link. No Drive exchange read.
    const parsedJoin = parseSharingJoinLinkV1(joinLink);
    if (!parsedJoin) throw new Error("join link did not parse");
    const response = await recipientController.submitKeyResponseFromInvitation(
      parsedJoin.invitation,
      parsedJoin.files,
    );
    const responseLink = buildSharingResponseLinkV1({ landingUrl: landing, response });

    // Owner: parse the response link, accept (keyGrant + per-email share).
    const parsedResponse = parseSharingResponseLinkV1(responseLink);
    if (!parsedResponse) throw new Error("response link did not parse");
    const accepted = await ownerController.acceptKeyResponseFromPayload({
      invitation: invite.invitation,
      response: parsedResponse.response,
      recipientEmailAddress: "recipient@example.com",
    });
    expect(accepted).toMatchObject([{ datasetId: "tasks", status: "accepted" }]);

    // Recipient can now read and write the dataset — no exchange files touched.
    await expect(recipientController.loadDataset("tasks")).resolves.toMatchObject({
      value: { items: ["owner"] },
    });
    await expect(
      recipientController.syncDataset("tasks", { items: ["owner", "recipient"] }),
    ).resolves.toMatchObject({
      value: { items: ["owner", "recipient"] },
      outcome: "updated",
    });
  });

  it("keeps participant roles and Drive permissions aligned", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const ownerController = controller(
      owner,
      transport,
      ownerRegistry,
    );
    const recipientController = controller(
      recipient,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });
    const invite = await ownerController.inviteParticipantForLink({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
    });
    const response = await recipientController.submitKeyResponseFromInvitation(
      invite.invitation,
      invite.files,
    );
    await ownerController.acceptKeyResponseFromPayload({
      invitation: invite.invitation,
      response,
      recipientEmailAddress: "recipient@example.com",
    });
    const registryRecord = await ownerRegistry.get("tasks");
    if (!registryRecord) throw new Error("Expected owner registry record.");
    await ownerRegistry.set({
      ...registryRecord,
      participantPermissionIds: {},
    });

    await ownerController.setDatasetRole({
      datasetId: "tasks",
      keyId: recipient.publicKey.keyId,
      role: "viewer",
      emailAddress: "recipient@example.com",
    });

    const stored = await transport.readDataset("dataset-tasks");
    expect(
      sharedBackupParticipant(stored.envelope, recipient.publicKey.keyId)?.role,
    ).toBe("viewer");
    expect(await transport.listDatasetPermissions(stored.fileId)).toMatchObject([
      { role: "reader", emailAddress: "recipient@example.com" },
    ]);
  });

  it("makes participant revocation retryable after encryption membership changes", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const ownerController = controller(
      owner,
      transport,
      ownerRegistry,
    );
    const recipientController = controller(
      recipient,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });
    const invite = await ownerController.inviteParticipantForLink({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
    });
    const response = await recipientController.submitKeyResponseFromInvitation(
      invite.invitation,
      invite.files,
    );
    await ownerController.acceptKeyResponseFromPayload({
      invitation: invite.invitation,
      response,
      recipientEmailAddress: "recipient@example.com",
    });
    const registryRecord = await ownerRegistry.get("tasks");
    if (!registryRecord) throw new Error("Expected owner registry record.");
    await ownerRegistry.set({
      ...registryRecord,
      participantPermissionIds: {},
    });

    await expect(
      ownerController.revokeDatasetKey({
        datasetId: "tasks",
        keyId: recipient.publicKey.keyId,
        emailAddress: "recipient@example.com",
      }),
    ).resolves.toMatchObject({ outcome: "updated" });
    await expect(
      ownerController.revokeDatasetKey({
        datasetId: "tasks",
        keyId: recipient.publicKey.keyId,
      }),
    ).resolves.toMatchObject({ outcome: "unchanged" });

    const stored = await transport.readDataset("dataset-tasks");
    expect(
      sharedBackupParticipant(stored.envelope, recipient.publicKey.keyId),
    ).toBeNull();
    expect(await transport.listDatasetPermissions(stored.fileId)).toEqual([]);
  });

  it("removes Drive access before writing a revocation envelope", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerController = controller(
      owner,
      transport,
      new MemorySharedBackupRegistry(),
    );
    const recipientController = controller(
      recipient,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });
    const invite = await ownerController.inviteParticipantForLink({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
    });
    const response = await recipientController.submitKeyResponseFromInvitation(
      invite.invitation,
      invite.files,
    );
    await ownerController.acceptKeyResponseFromPayload({
      invitation: invite.invitation,
      response,
      recipientEmailAddress: "recipient@example.com",
    });

    transport.conflictNextWrite = true;
    await expect(
      ownerController.revokeDatasetKey({
        datasetId: "tasks",
        keyId: recipient.publicKey.keyId,
        emailAddress: "recipient@example.com",
      }),
    ).rejects.toMatchObject({ code: "conflict" });

    const stored = await transport.readDataset("dataset-tasks");
    expect(
      sharedBackupParticipant(stored.envelope, recipient.publicKey.keyId)?.role,
    ).toBe("writer");
    expect(await transport.listDatasetPermissions(stored.fileId)).toEqual([]);
  });

  it("rejects a stale conditional write instead of losing another writer", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const sharing = controller(owner, transport, registry);
    await sharing.createDataset("profile", { items: ["one"] });

    transport.conflictNextWrite = true;
    await expect(
      sharing.syncDataset("profile", { items: ["one", "two"] }),
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("preserves an existing owner pin and rejects a conflicting invitation", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const attacker = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const recipientRegistry = new MemorySharedBackupRegistry();
    const ownerController = controller(owner, transport, ownerRegistry);
    const recipientController = controller(
      recipient,
      transport,
      recipientRegistry,
    );
    const created = await ownerController.createDataset("tasks", {
      items: ["owner"],
    });
    await recipientRegistry.set({
      datasetId: "tasks",
      fileId: created.fileId,
      trustedOwnerKeyId: owner.publicKey.keyId,
      lastRevisionId: created.revisionId,
      seenRevisionIds: ["older", created.revisionId],
    });
    const invited = await ownerController.inviteParticipant({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "viewer" }],
    });

    await recipientController.submitKeyResponse(invited.invitationFileId);
    await expect(recipientRegistry.get("tasks")).resolves.toMatchObject({
      trustedOwnerKeyId: owner.publicKey.keyId,
      lastRevisionId: created.revisionId,
      seenRevisionIds: ["older", created.revisionId],
    });

    const malicious = await createSharingInvitationV1(attacker, {
      appId: "fixture-app",
      appFolderId: transport.storage.appFolderId,
      recipientDrivePermissionId: "permission-recipient@example.com",
      requestedGrants: [
        { datasetId: "attacker-new", role: "viewer" },
        { datasetId: "tasks", role: "viewer" },
      ],
      trustedOwnerKeyId: attacker.publicKey.keyId,
    });
    const maliciousFileId = await transport.createInvitation(malicious);
    await expect(
      recipientController.submitKeyResponse(maliciousFileId),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(recipientRegistry.get("tasks")).resolves.toMatchObject({
      trustedOwnerKeyId: owner.publicKey.keyId,
      lastRevisionId: created.revisionId,
      seenRevisionIds: ["older", created.revisionId],
    });
    await expect(recipientRegistry.get("attacker-new")).resolves.toBeNull();
  });

  it("checks the pinned owner before authorizing an invitation", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const attacker = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const ownerController = controller(owner, transport, registry);
    await ownerController.createDataset("tasks", { items: ["owner"] });
    const current = await transport.readDataset("dataset-tasks");
    const substituted = await createSharedBackupEnvelopeV1(
      { items: ["substituted"] },
      codec,
      attacker,
      {
        appId: "fixture-app",
        backupId: "tasks",
        participants: [
          { publicKey: attacker.publicKey, role: "owner" },
        ],
      },
    );
    transport.datasets.set("dataset-tasks", {
      ...current,
      envelope: substituted,
      version: '"substituted"',
    });

    await expect(
      controller(attacker, transport, registry).inviteParticipant({
        emailAddress: "recipient@example.com",
        requestedGrants: [{ datasetId: "tasks", role: "viewer" }],
      }),
    ).rejects.toMatchObject({ code: "authorization" });
  });

  it("rotates the local owner identity without changing ownership", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const replacement = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const original = controller(owner, transport, registry);
    await original.createDataset("profile", { items: ["one"] });

    await expect(
      original.rotateLocalKey(replacement, ["profile"]),
    ).resolves.toMatchObject([
      { datasetId: "profile", status: "rotated" },
    ]);
    await expect(
      controller(replacement, transport, registry).loadDataset("profile"),
    ).resolves.toMatchObject({ value: { items: ["one"] } });
  });

  it("merges a divergent signed head only through the consumer fork policy", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const sharing = controller(owner, transport, registry, {
      resolveFork: async () => "merge",
    });
    await sharing.createDataset("profile", { items: ["genesis"] });
    const genesis = await transport.readDataset("dataset-profile");
    await sharing.syncDataset("profile", {
      items: ["genesis", "local-first"],
    });
    const branchEnvelope = await createSharedBackupEnvelopeV1(
      { items: ["genesis", "remote-branch"] },
      codec,
      owner,
      {
        appId: "fixture-app",
        backupId: "profile",
        participants: [
          { publicKey: owner.publicKey, role: "owner" },
        ],
        previous: genesis.envelope,
        revisionId: "remote-branch",
      },
    );
    const current = await transport.readDataset("dataset-profile");
    transport.datasets.set("dataset-profile", {
      ...current,
      envelope: branchEnvelope,
      version: '"fork"',
    });

    await expect(
      sharing.syncDataset("profile", {
        items: ["genesis", "local-first", "local-second"],
      }),
    ).resolves.toMatchObject({
      value: {
        items: [
          "genesis",
          "remote-branch",
          "local-first",
          "local-second",
        ],
      },
      outcome: "updated",
    });
  });

  it("appends a folder join URL to invite email messages when configured", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const sharing = controller(owner, transport, registry);
    await sharing.createDataset("tasks", { items: ["owner"] });

    await sharing.inviteParticipant({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
      joinLandingUrl: "https://example.com/easy-bc/",
      appDisplayName: "EasyBC",
    });

    expect(transport.lastInviteEmailMessage).toContain(
      "https://example.com/easy-bc/",
    );
    expect(transport.lastInviteEmailMessage).toContain("folder=app-folder");
    expect(transport.lastInviteEmailMessage).not.toContain("exchange=");
  });

  it("does not remove Drive permissions for skipped participants with correct ACLs", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const recipientRegistry = new MemorySharedBackupRegistry();
    const ownerController = controller(owner, transport, ownerRegistry);
    const recipientController = controller(
      recipient,
      transport,
      recipientRegistry,
    );

    await ownerController.createDataset("tasks", { items: ["owner"] });
    const invited = await ownerController.inviteParticipant({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
    });
    const submitted = await recipientController.submitKeyResponse(
      invited.invitationFileId,
    );
    await ownerController.acceptKeyResponse({
      invitation: invited.invitation,
      responseFileId: submitted.responseFileId,
      recipientEmailAddress: "recipient@example.com",
    });

    const reconciled = await ownerController.reconcileDrivePermissions({
      datasetId: "tasks",
      participantEmails: {},
    });

    expect(reconciled.actions).toContainEqual({
      kind: "unchanged",
      keyId: recipient.publicKey.keyId,
    });
    expect(
      transport.permissions
        .get("dataset-tasks")
        ?.has("permission-recipient@example.com"),
    ).toBe(true);
  });

  it("does not remove Drive permissions for skipped participants with drifted ACLs", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const recipientRegistry = new MemorySharedBackupRegistry();
    const ownerController = controller(owner, transport, ownerRegistry);
    const recipientController = controller(
      recipient,
      transport,
      recipientRegistry,
    );

    await ownerController.createDataset("tasks", { items: ["owner"] });
    const invited = await ownerController.inviteParticipant({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
    });
    const submitted = await recipientController.submitKeyResponse(
      invited.invitationFileId,
    );
    await ownerController.acceptKeyResponse({
      invitation: invited.invitation,
      responseFileId: submitted.responseFileId,
      recipientEmailAddress: "recipient@example.com",
    });

    const stored = await transport.readDataset("dataset-tasks");
    const filePermissions = transport.permissions.get(stored.fileId);
    expect(filePermissions).toBeDefined();
    if (!filePermissions) {
      throw new Error("Expected dataset permissions to exist.");
    }
    for (const [permissionId, permission] of filePermissions.entries()) {
      if (permission.emailAddress === "recipient@example.com") {
        filePermissions.set(permissionId, {
          ...permission,
          role: "reader",
        });
      }
    }

    const reconciled = await ownerController.reconcileDrivePermissions({
      datasetId: "tasks",
      participantEmails: {},
    });

    expect(reconciled.actions).toContainEqual({
      kind: "skipped",
      keyId: recipient.publicKey.keyId,
      reason: "No email address was provided for reconciliation.",
    });
    expect(reconciled.actions).not.toContainEqual({
      kind: "removed",
      permissionId: "permission-recipient@example.com",
    });
    expect(
      transport.permissions
        .get("dataset-tasks")
        ?.has("permission-recipient@example.com"),
    ).toBe(true);
  });

  it("reconciles drifted Drive permissions for known participants", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const recipientRegistry = new MemorySharedBackupRegistry();
    const ownerController = controller(owner, transport, ownerRegistry);
    const recipientController = controller(
      recipient,
      transport,
      recipientRegistry,
    );

    await ownerController.createDataset("tasks", { items: ["owner"] });
    const invited = await ownerController.inviteParticipant({
      emailAddress: "recipient@example.com",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
    });
    const submitted = await recipientController.submitKeyResponse(
      invited.invitationFileId,
    );
    await ownerController.acceptKeyResponse({
      invitation: invited.invitation,
      responseFileId: submitted.responseFileId,
      recipientEmailAddress: "recipient@example.com",
    });

    const stored = await transport.readDataset("dataset-tasks");
    const filePermissions = transport.permissions.get(stored.fileId);
    expect(filePermissions).toBeDefined();
    if (!filePermissions) {
      throw new Error("Expected dataset permissions to exist.");
    }
    for (const [permissionId, permission] of filePermissions.entries()) {
      if (permission.emailAddress === "recipient@example.com") {
        filePermissions.set(permissionId, {
          ...permission,
          role: "reader",
        });
      }
    }

    const reconciled = await ownerController.reconcileDrivePermissions({
      datasetId: "tasks",
      participantEmails: {
        [recipient.publicKey.keyId]: "recipient@example.com",
      },
    });

    expect(reconciled.actions).toContainEqual({
      kind: "updated",
      keyId: recipient.publicKey.keyId,
      permissionId: "permission-recipient@example.com",
      role: "writer",
    });
  });
});

describe("shared-backup controller adoption", () => {
  it("adopts an owned dataset after the registry is lost", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const stranger = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    await controller(owner, transport, new MemorySharedBackupRegistry())
      .createDataset("tasks", { items: ["owner"] });

    const adopted = await controller(
      owner,
      transport,
      new MemorySharedBackupRegistry(),
    ).adoptDataset("tasks", { requireOwned: true });
    expect(adopted.outcome).toBe("adopted");
    expect(adopted.value.items).toEqual(["owner"]);

    await expect(
      controller(stranger, transport, new MemorySharedBackupRegistry())
        .adoptDataset("tasks", { requireOwned: true }),
    ).rejects.toThrow("does not own dataset");
  });

  it("deleteDataset removes the file and the local record", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const ownerController = controller(owner, transport, registry);
    await ownerController.createDataset("tasks", { items: ["owner"] });

    await ownerController.deleteDataset("tasks");

    expect(await ownerController.listDatasets()).toEqual([]);
    expect(await registry.get("tasks")).toBeNull();
  });

  it("trashDataset moves the file to the provider trash and forgets the record", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const ownerController = controller(owner, transport, registry);
    await ownerController.createDataset("tasks", { items: ["owner"] });

    await ownerController.trashDataset("tasks");

    expect(await ownerController.listDatasets()).toEqual([]);
    expect(await registry.get("tasks")).toBeNull();
    expect(transport.trashed.has("dataset-tasks")).toBe(true);
  });

  it("addDatasetParticipant grants access to a known public key without an exchange", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerController = controller(
      owner,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });

    await ownerController.addDatasetParticipant({
      datasetId: "tasks",
      participant: { publicKey: recipient.publicKey, role: "writer" },
      emailAddress: "recipient@example.com",
    });

    const recipientController = controller(
      recipient,
      transport,
      new MemorySharedBackupRegistry(),
    );
    const adopted = await recipientController.adoptDataset("tasks");
    expect(adopted.value.items).toEqual(["owner"]);
    const stored = await transport.readDataset("dataset-tasks");
    const self = sharedBackupParticipant(
      stored.envelope,
      recipient.publicKey.keyId,
    );
    expect(self?.role).toBe("writer");
    // The dataset file was per-email shared on the transport.
    const permissions = transport.permissions.get("dataset-tasks");
    expect(
      [...(permissions?.values() ?? [])].some(
        (permission) => permission.emailAddress === "recipient@example.com",
      ),
    ).toBe(true);
  });

  it("addDatasetParticipant reuses inherited read access for viewers", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerController = controller(
      owner,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });

    await ownerController.addDatasetParticipant({
      datasetId: "tasks",
      participant: { publicKey: recipient.publicKey, role: "viewer" },
      emailAddress: "recipient@example.com",
    });

    expect(transport.permissions.get("dataset-tasks")).toBeUndefined();
    expect(
      sharedBackupParticipant(
        (await transport.readDataset("dataset-tasks")).envelope,
        recipient.publicKey.keyId,
      )?.role,
    ).toBe("viewer");
  });

  it("addDatasetParticipant does not grant a Drive ACL when the signed write fails", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerController = controller(
      owner,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });
    transport.conflictNextWrite = true;

    await expect(
      ownerController.addDatasetParticipant({
        datasetId: "tasks",
        participant: { publicKey: recipient.publicKey, role: "writer" },
        emailAddress: "recipient@example.com",
      }),
    ).rejects.toThrow(/Conflict/);

    expect(transport.permissions.get("dataset-tasks")).toBeUndefined();
    expect(
      sharedBackupParticipant(
        (await transport.readDataset("dataset-tasks")).envelope,
        recipient.publicKey.keyId,
      ),
    ).toBeNull();
  });

  it("addDatasetParticipant upserts the role when the key is already granted", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerController = controller(
      owner,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });
    await ownerController.addDatasetParticipant({
      datasetId: "tasks",
      participant: { publicKey: recipient.publicKey, role: "viewer" },
      emailAddress: "recipient@example.com",
    });

    await ownerController.addDatasetParticipant({
      datasetId: "tasks",
      participant: { publicKey: recipient.publicKey, role: "writer" },
      emailAddress: "recipient@example.com",
    });

    const stored = await transport.readDataset("dataset-tasks");
    const granted = sharedBackupParticipant(
      stored.envelope,
      recipient.publicKey.keyId,
    );
    expect(granted?.role).toBe("writer");
    // Exactly one participant entry for the key — upsert, not duplicate.
    expect(
      sharedBackupParticipants(stored.envelope).filter(
        (participant) => participant.keyId === recipient.publicKey.keyId,
      ),
    ).toHaveLength(1);
  });

  it("addDatasetParticipant rejects a non-administering actor", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const stranger = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerController = controller(
      owner,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await ownerController.createDataset("tasks", { items: ["owner"] });
    await ownerController.addDatasetParticipant({
      datasetId: "tasks",
      participant: { publicKey: recipient.publicKey, role: "viewer" },
      emailAddress: "recipient@example.com",
    });

    const recipientController = controller(
      recipient,
      transport,
      new MemorySharedBackupRegistry(),
    );
    await recipientController.adoptDataset("tasks");
    await expect(
      recipientController.addDatasetParticipant({
        datasetId: "tasks",
        participant: { publicKey: stranger.publicKey, role: "viewer" },
        emailAddress: "stranger@example.com",
      }),
    ).rejects.toThrow(/owner or admin/);
  });

  it("routes create, adopt, load, sync, roles, revocation, and rotation by dataset ID", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const replacement = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const calls = {
      application: emptyCodecCalls(),
      control: emptyCodecCalls(),
    };
    const applicationCodec = routedCodec("application", calls.application);
    const controlCodec = routedCodec("control", calls.control);
    const ownerController = routedController(
      owner,
      transport,
      ownerRegistry,
      applicationCodec,
      controlCodec,
    );

    await ownerController.createDataset(
      codecRoutingFixture.applicationDatasetId,
      codecRoutingFixture.applicationPayload,
    );
    await ownerController.createDataset(
      codecRoutingFixture.controlDatasetId,
      codecRoutingFixture.controlPayload,
    );

    const recoveryRegistry = new MemorySharedBackupRegistry();
    const recoveryController = routedController(
      owner,
      transport,
      recoveryRegistry,
      applicationCodec,
      controlCodec,
    );
    await recoveryController.adoptDataset(codecRoutingFixture.applicationDatasetId, {
      requireOwned: true,
    });
    await recoveryController.adoptDataset(codecRoutingFixture.controlDatasetId, {
      requireOwned: true,
    });
    await recoveryController.loadDataset(codecRoutingFixture.controlDatasetId);
    await recoveryController.syncDataset(
      codecRoutingFixture.controlDatasetId,
      codecRoutingFixture.updatedControlPayload,
    );
    await recoveryController.addDatasetParticipant({
      datasetId: codecRoutingFixture.controlDatasetId,
      participant: { publicKey: recipient.publicKey, role: "viewer" },
      emailAddress: "recipient@example.test",
    });
    await recoveryController.setDatasetRole({
      datasetId: codecRoutingFixture.controlDatasetId,
      keyId: recipient.publicKey.keyId,
      role: "writer",
      emailAddress: "recipient@example.test",
    });
    await recoveryController.revokeDatasetKey({
      datasetId: codecRoutingFixture.controlDatasetId,
      keyId: recipient.publicKey.keyId,
      emailAddress: "recipient@example.test",
    });
    await expect(
      recoveryController.rotateLocalKey(replacement, [
        codecRoutingFixture.controlDatasetId,
      ]),
    ).resolves.toMatchObject([
      { datasetId: codecRoutingFixture.controlDatasetId, status: "rotated" },
    ]);

    expect(calls.application.serialize).toBeGreaterThan(0);
    expect(calls.application.parse).toBeGreaterThan(0);
    expect(calls.control.serialize).toBeGreaterThan(0);
    expect(calls.control.parse).toBeGreaterThan(0);
    expect(calls.control.merge).toBeGreaterThan(0);
    expect(calls.control.fingerprint).toBeGreaterThan(0);
  });

  it("leaves the remote file and verified head unchanged when an override codec rejects", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const applicationCodec = routedCodec("application", emptyCodecCalls());
    const controlCodec = routedCodec("control", emptyCodecCalls());
    const sharing = routedController(
      owner,
      transport,
      registry,
      applicationCodec,
      controlCodec,
    );
    await sharing.createDataset(
      codecRoutingFixture.controlDatasetId,
      codecRoutingFixture.controlPayload,
    );
    const beforeRemote = await transport.readDataset(
      `dataset-${codecRoutingFixture.controlDatasetId}`,
    );
    const beforeHead = await registry.get(codecRoutingFixture.controlDatasetId);
    const rejecting = routedController(
      owner,
      transport,
      registry,
      applicationCodec,
      {
        ...controlCodec,
        parse: () => {
          throw new TypeError("Sentinel control codec rejected the payload.");
        },
      },
    );

    await expect(
      rejecting.syncDataset(
        codecRoutingFixture.controlDatasetId,
        codecRoutingFixture.updatedControlPayload,
      ),
    ).rejects.toMatchObject({ code: "serialization" });
    await expect(
      transport.readDataset(`dataset-${codecRoutingFixture.controlDatasetId}`),
    ).resolves.toEqual(beforeRemote);
    await expect(registry.get(codecRoutingFixture.controlDatasetId)).resolves.toEqual(
      beforeHead,
    );
  });

  it("rereads and merges a divergent control head with the same selected codec", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const transport = new MemorySharingTransport();
    const registry = new MemorySharedBackupRegistry();
    const applicationCalls = emptyCodecCalls();
    const controlCalls = emptyCodecCalls();
    const applicationCodec = routedCodec("application", applicationCalls);
    const controlCodec = routedCodec("control", controlCalls);
    const sharing = routedController(
      owner,
      transport,
      registry,
      applicationCodec,
      controlCodec,
      async () => "merge",
    );
    await sharing.createDataset(
      codecRoutingFixture.controlDatasetId,
      codecRoutingFixture.controlPayload,
    );
    const genesis = await transport.readDataset(
      `dataset-${codecRoutingFixture.controlDatasetId}`,
    );
    await sharing.syncDataset(
      codecRoutingFixture.controlDatasetId,
      codecRoutingFixture.updatedControlPayload,
    );
    const branch = await createSharedBackupEnvelopeV1(
      codecRoutingFixture.branchControlPayload,
      controlCodec,
      owner,
      {
        appId: "fixture-app",
        backupId: codecRoutingFixture.controlDatasetId,
        participants: [{ publicKey: owner.publicKey, role: "owner" }],
        previous: genesis.envelope,
        revisionId: "control-remote-branch",
      },
    );
    const current = await transport.readDataset(
      `dataset-${codecRoutingFixture.controlDatasetId}`,
    );
    transport.datasets.set(`dataset-${codecRoutingFixture.controlDatasetId}`, {
      ...current,
      envelope: branch,
      version: '"control-fork"',
    });

    await expect(
      sharing.syncDataset(
        codecRoutingFixture.controlDatasetId,
        codecRoutingFixture.updatedControlPayload,
      ),
    ).resolves.toMatchObject({
      outcome: "updated",
      value: {
        kind: "control",
        entries: [
          "member:owner",
          "migration:remote-branch",
          "migration:split-profile",
        ],
      },
    });
    expect(applicationCalls).toEqual(emptyCodecCalls());
    expect(controlCalls.parse).toBeGreaterThan(0);
    expect(controlCalls.merge).toBeGreaterThan(0);
    expect(controlCalls.fingerprint).toBeGreaterThan(0);
    expect(controlCalls.serialize).toBeGreaterThan(0);
  });
});

function emptyCodecCalls(): CodecCalls {
  return { serialize: 0, parse: 0, merge: 0, fingerprint: 0 };
}

function routedCodec(
  expectedKind: RoutedPayload["kind"],
  calls: CodecCalls,
): SharedBackupControllerCodec<RoutedPayload> {
  const assertKind = (value: RoutedPayload): RoutedPayload => {
    if (value.kind !== expectedKind) {
      throw new TypeError(
        `${expectedKind} codec received ${value.kind} payload.`,
      );
    }
    return structuredClone(value);
  };
  return {
    serialize: (value) => {
      calls.serialize += 1;
      return assertKind(value);
    },
    parse: (value) => {
      calls.parse += 1;
      return assertKind(value as RoutedPayload);
    },
    merge: (local, remote) => {
      calls.merge += 1;
      assertKind(local);
      assertKind(remote);
      if (expectedKind === "application") {
        return {
          kind: expectedKind,
          items: [...new Set([...(remote.items ?? []), ...(local.items ?? [])])],
        };
      }
      return {
        kind: expectedKind,
        entries: [
          ...new Set([...(remote.entries ?? []), ...(local.entries ?? [])]),
        ],
      };
    },
    fingerprint: (value) => {
      calls.fingerprint += 1;
      return JSON.stringify(assertKind(value));
    },
  };
}

function routedController(
  identity: WebCryptoSharingIdentity,
  transport: SharedBackupTransport,
  registry: MemorySharedBackupRegistry,
  applicationCodec: SharedBackupControllerCodec<RoutedPayload>,
  controlCodec: SharedBackupControllerCodec<RoutedPayload>,
  resolveFork?: () => Promise<"merge" | "reject">,
) {
  return createSharedBackupController({
    appId: "fixture-app",
    codec: applicationCodec,
    codecForDataset: (datasetId) =>
      datasetId === codecRoutingFixture.controlDatasetId
        ? controlCodec
        : undefined,
    identity: async () => identity,
    transport,
    registry,
    now: () => new Date("2026-07-17T00:00:00.000Z"),
    randomUUID: incrementingUuid(),
    ...(resolveFork ? { resolveFork } : {}),
  });
}

function controller(
  identity: WebCryptoSharingIdentity,
  transport: SharedBackupTransport,
  registry: MemorySharedBackupRegistry,
  overrides: Partial<
    Parameters<typeof createSharedBackupController<Payload>>[0]
  > = {},
) {
  return createSharedBackupController({
    appId: "fixture-app",
    codec,
    identity: async () => identity,
    transport,
    registry,
    now: () => new Date("2026-07-01T12:00:00.000Z"),
    randomUUID: incrementingUuid(),
    ...overrides,
  });
}

function incrementingUuid(): () => string {
  return () => `generated-${++uuidCount}`;
}

let uuidCount = 0;

class MemorySharingTransport implements SharedBackupTransport {
  readonly storage: SharedBackupStorage = {
    appFolderId: "app-folder",
    exchangesFolderId: "exchanges-folder",
  };
  readonly datasets = new Map<string, VersionedSharedDataset>();
  readonly invitations = new Map<string, SharingInvitationV1>();
  readonly responses = new Map<string, SharingPublicKeyResponseV1>();
  readonly permissions = new Map<
    string,
    Map<
      string,
      {
        role: "reader" | "writer";
        emailAddress?: string;
        inherited: boolean;
      }
    >
  >();
  conflictNextWrite = false;
  lastInviteEmailMessage: string | undefined;
  private counter = 0;

  async ensureStorage(): Promise<SharedBackupStorage> {
    return this.storage;
  }

  async listDatasets(): Promise<SharedDatasetFile[]> {
    return [...this.datasets.values()].map(
      ({ datasetId, fileId, name, canEdit }) => ({
        datasetId,
        fileId,
        name,
        ...(canEdit === undefined ? {} : { canEdit }),
      }),
    );
  }

  async readDataset(fileId: string): Promise<VersionedSharedDataset> {
    const stored = this.datasets.get(fileId);
    if (!stored) throw new Error(`Missing ${fileId}`);
    return structuredClone(stored);
  }

  async createDataset(
    datasetId: string,
    envelope: SharedBackupEnvelopeV1,
  ): Promise<VersionedSharedDataset> {
    const fileId = `dataset-${datasetId}`;
    const stored = {
      datasetId,
      fileId,
      name: `${datasetId}.sync-kit.json`,
      canEdit: true,
      envelope: structuredClone(envelope),
      version: `"${++this.counter}"`,
    };
    this.datasets.set(fileId, stored);
    return structuredClone(stored);
  }

  async deleteDataset(fileId: string): Promise<void> {
    this.datasets.delete(fileId);
  }

  readonly trashed = new Set<string>();
  async trashDataset(fileId: string): Promise<void> {
    this.datasets.delete(fileId);
    this.trashed.add(fileId);
  }

  async writeDataset(
    current: VersionedSharedDataset,
    envelope: SharedBackupEnvelopeV1,
  ): Promise<VersionedSharedDataset> {
    const actual = this.datasets.get(current.fileId);
    if (
      this.conflictNextWrite ||
      actual?.version !== current.version
    ) {
      this.conflictNextWrite = false;
      throw Object.assign(new Error("Conflict"), { code: "conflict" });
    }
    const updated = {
      ...actual,
      envelope: structuredClone(envelope),
      version: `"${++this.counter}"`,
    };
    this.datasets.set(current.fileId, updated);
    return structuredClone(updated);
  }

  async grantExchangeAccess(
    emailAddress: string,
    options: {
      sendNotificationEmail?: boolean;
      emailMessage?: string;
    } = {},
  ): Promise<{ drivePermissionId: string; appFolderId: string }> {
    this.lastInviteEmailMessage = options.emailMessage;
    return {
      drivePermissionId: `permission-${emailAddress}`,
      appFolderId: this.storage.appFolderId,
    };
  }

  async createInvitation(invitation: SharingInvitationV1): Promise<string> {
    const fileId = `invitation-${invitation.exchangeId}`;
    this.invitations.set(fileId, structuredClone(invitation));
    return fileId;
  }

  async createKeyResponse(
    response: SharingPublicKeyResponseV1,
  ): Promise<string> {
    const fileId = `response-${response.exchangeId}`;
    this.responses.set(fileId, structuredClone(response));
    return fileId;
  }

  async listExchanges(
    options: {
      exchangeId?: string;
      kind?: SharedExchangeFile["kind"];
    } = {},
  ): Promise<SharedExchangeFile[]> {
    return [
      ...[...this.invitations.entries()].map(([fileId, invitation]) => ({
        fileId,
        exchangeId: invitation.exchangeId,
        kind: "invitation" as const,
      })),
      ...[...this.responses.entries()].map(([fileId, response]) => ({
        fileId,
        exchangeId: response.exchangeId,
        kind: "key-response" as const,
        keyId: response.keyId,
      })),
    ].filter((file) => {
      if (options.exchangeId && file.exchangeId !== options.exchangeId) {
        return false;
      }
      if (options.kind && file.kind !== options.kind) return false;
      return true;
    });
  }

  async readInvitation(fileId: string): Promise<SharingInvitationV1> {
    const invitation = this.invitations.get(fileId);
    if (!invitation) throw new Error(`Missing ${fileId}`);
    return structuredClone(invitation);
  }

  async readKeyResponse(
    fileId: string,
    expectedDrivePermissionId: string,
  ): Promise<SharedKeyResponseFile> {
    const response = this.responses.get(fileId);
    if (!response) throw new Error(`Missing ${fileId}`);
    return {
      fileId,
      response: structuredClone(response),
      ownerPermissionId: expectedDrivePermissionId,
    };
  }

  async deleteExchange(fileId: string): Promise<void> {
    this.invitations.delete(fileId);
    this.responses.delete(fileId);
  }

  async setDatasetPermission(
    fileId: string,
    emailAddress: string,
    role: Exclude<SharingRole, "owner">,
    options: {
      existingDirectPermissionId?: string;
      hasInheritedReadAccess?: boolean;
    } = {},
  ): Promise<SharedDatasetPermission> {
    if (
      !options.existingDirectPermissionId &&
      role === "viewer" &&
      options.hasInheritedReadAccess
    ) {
      return { role: "reader" };
    }
    const permissionId =
      options.existingDirectPermissionId ??
      `permission-${emailAddress}`;
    const driveRole = role === "viewer" ? "reader" : "writer";
    const filePermissions =
      this.permissions.get(fileId) ?? new Map<string, {
        role: "reader" | "writer";
        emailAddress?: string;
        inherited: boolean;
      }>();
    filePermissions.set(permissionId, {
      role: driveRole,
      emailAddress,
      inherited: false,
    });
    this.permissions.set(fileId, filePermissions);
    return {
      permissionId,
      role: driveRole,
    };
  }

  async listDatasetPermissions(fileId: string) {
    const filePermissions = this.permissions.get(fileId);
    if (!filePermissions) return [];
    return [...filePermissions.entries()].map(([permissionId, permission]) => ({
      permissionId,
      role: permission.role,
      ...(permission.emailAddress
        ? { emailAddress: permission.emailAddress }
        : {}),
      inherited: permission.inherited,
    }));
  }

  async listDatasetHeads() {
    return [...this.datasets.values()].map(
      ({ datasetId, fileId, version }) => ({
        datasetId,
        fileId,
        version,
        etag: version,
      }),
    );
  }

  async removeDatasetPermission(
    fileId: string,
    permissionId: string,
  ): Promise<void> {
    this.permissions.get(fileId)?.delete(permissionId);
  }
}
