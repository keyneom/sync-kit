import { describe, expect, it } from "vitest";
import { SyncKitError } from "../src/core/errors.js";
import {
  createSharingControlCodec,
  createSharingControlDataset,
  verifySharingControlStateV1,
  type SharingControlStateV1,
} from "../src/sharing/control.js";
import {
  createSharedBackupController,
  MemorySharedBackupRegistry,
  type SharedBackupControllerCodec,
} from "../src/sharing/controller.js";
import type {
  SharedBackupEnvelopeV1,
  SharingInvitationV1,
} from "../src/sharing/index.js";
import type {
  SharedBackupStorage,
  SharedBackupTransport,
  SharedDatasetDrivePermission,
  SharedDatasetFile,
  SharedDatasetPermission,
  SharedExchangeFile,
  SharedKeyResponseFile,
  VersionedSharedDataset,
} from "../src/sharing/transport.js";
import {
  createWebCryptoSharingIdentity,
  type WebCryptoSharingIdentity,
} from "../src/sharing/web-crypto.js";

type Payload = { items: string[] };

const CONTROL_DATASET_ID = "profile-control";
const payloadCodec: SharedBackupControllerCodec<Payload> = {
  serialize: (value) => value,
  parse: (value) => {
    const candidate = value as Partial<Payload>;
    if (!Array.isArray(candidate.items) || !candidate.items.every((item) => typeof item === "string")) {
      throw new TypeError("Invalid payload.");
    }
    return { items: candidate.items };
  },
  merge: (local, remote) => ({ items: [...new Set([...remote.items, ...local.items])] }),
  fingerprint: (value) => JSON.stringify(value.items),
};

describe("sharing control dataset", () => {
  it("enrolls the control file in a mixed-codec invitation and closes only after a verified Picker acknowledgement", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const transport = new ControlTransport();
    const ownerRegistry = new MemorySharedBackupRegistry();
    const recipientRegistry = new MemorySharedBackupRegistry();
    const controlCodec = createSharingControlCodec();
    const ownerData = payloadController(owner, transport, ownerRegistry, controlCodec);
    const recipientData = payloadController(recipient, transport, recipientRegistry, controlCodec);
    const ownerControl = controlDataset(owner, transport, ownerRegistry, controlCodec, "owner");
    const recipientControl = controlDataset(recipient, transport, recipientRegistry, controlCodec, "recipient");

    const data = await ownerData.createDataset("primary", { items: ["owner"] });
    await ownerControl.create({ email: "owner@example.test", googleSubject: "owner-sub" });

    const invitation = await ownerData.inviteParticipantForLink({
      emailAddress: "recipient@example.test",
      requestedGrants: [
        { datasetId: "primary", role: "viewer" },
        { datasetId: CONTROL_DATASET_ID, role: "writer" },
      ],
    });
    const response = await recipientData.submitKeyResponseFromInvitation(
      invitation.invitation,
      invitation.files,
    );
    await expect(
      ownerData.acceptKeyResponseFromPayload({
        invitation: invitation.invitation,
        response,
        recipientEmailAddress: "recipient@example.test",
      }),
    ).resolves.toMatchObject([
      { datasetId: "primary", status: "accepted" },
      { datasetId: CONTROL_DATASET_ID, status: "accepted" },
    ]);

    await ownerControl.synchronizeMembers({
      [recipient.publicKey.keyId]: {
        email: "recipient@example.test",
        googleSubject: "recipient-sub",
      },
    });
    await recipientControl.read();
    await ownerControl.announceMigration({
      migrationId: "split-primary",
      sourceDatasetIds: ["primary"],
      targets: [{ datasetId: "primary", fileId: data.fileId, revisionId: data.revisionId }],
      requiredAcks: [{ keyId: recipient.publicKey.keyId, targetFileIds: [data.fileId] }],
      mode: "hard-cutover",
    });

    await expect(
      recipientControl.acknowledgeMigration({
        migrationId: "split-primary",
        openedFileIds: [],
      }),
    ).rejects.toMatchObject({ code: "state" });
    await expect(
      recipientControl.acknowledgeMigration({
        migrationId: "split-primary",
        openedFileIds: [data.fileId, "unexpected-file"],
      }),
    ).rejects.toMatchObject({ code: "state" });
    await expect(ownerControl.closeMigration({ migrationId: "split-primary" })).rejects.toMatchObject({ code: "state" });

    await recipientData.loadDataset("primary");
    await recipientControl.acknowledgeMigration({
      migrationId: "split-primary",
      openedFileIds: [data.fileId],
    });
    await ownerControl.closeMigration({ migrationId: "split-primary" });
    await expect(ownerControl.migrationStatus("split-primary")).resolves.toMatchObject({
      pendingKeyIds: [],
      closed: true,
    });
  });

  it("rejects a state whose signed control event has been tampered with", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const transport = new ControlTransport();
    const registry = new MemorySharedBackupRegistry();
    const codec = createSharingControlCodec();
    const control = controlDataset(owner, transport, registry, codec, "owner");
    await control.create({ email: "owner@example.test" });
    const state = (await control.read()).state;
    const tampered = structuredClone(state);
    const event = tampered.events[0];
    if (event?.type !== "member-upsert") throw new Error("Expected owner event.");
    event.member.email = "attacker@example.test";

    await expect(
      verifySharingControlStateV1(tampered, crypto, {
        trustedOwnerKeyId: owner.publicKey.keyId,
      }),
    ).rejects.toMatchObject({ code: "crypto" });
  });
});

function payloadController(
  identity: WebCryptoSharingIdentity,
  transport: ControlTransport,
  registry: MemorySharedBackupRegistry,
  controlCodec: SharedBackupControllerCodec<SharingControlStateV1>,
) {
  return createSharedBackupController({
    appId: "fixture-app",
    codec: payloadCodec,
    codecForDataset: (datasetId) => datasetId === CONTROL_DATASET_ID ? controlCodec : undefined,
    identity: async () => identity,
    transport,
    registry,
    now: () => new Date("2026-07-09T12:00:00.000Z"),
    randomUUID: idFactory("payload"),
  });
}

function controlDataset(
  identity: WebCryptoSharingIdentity,
  transport: ControlTransport,
  registry: MemorySharedBackupRegistry,
  codec: SharedBackupControllerCodec<SharingControlStateV1>,
  prefix: string,
) {
  const controller = createSharedBackupController({
    appId: "fixture-app",
    codec,
    identity: async () => identity,
    transport,
    registry,
    now: () => new Date("2026-07-09T12:00:00.000Z"),
    randomUUID: idFactory(`${prefix}-controller`),
  });
  return createSharingControlDataset({
    controller,
    datasetId: CONTROL_DATASET_ID,
    profileId: "profile-1",
    identity: async () => identity,
    now: () => new Date("2026-07-09T12:00:00.000Z"),
    randomUUID: idFactory(`${prefix}-event`),
  });
}

function idFactory(prefix: string): () => string {
  let counter = 0;
  return () => `${prefix}-${++counter}`;
}

class ControlTransport implements SharedBackupTransport {
  readonly storage: SharedBackupStorage = { appFolderId: "folder", exchangesFolderId: "exchanges" };
  readonly datasets = new Map<string, VersionedSharedDataset>();
  private revision = 0;

  ensureStorage(): Promise<SharedBackupStorage> { return Promise.resolve(this.storage); }
  listDatasets(): Promise<SharedDatasetFile[]> {
    return Promise.resolve([...this.datasets.values()].map(({ datasetId, fileId, name, canEdit }) => ({
      datasetId,
      fileId,
      name,
      ...(canEdit === undefined ? {} : { canEdit }),
    })));
  }
  async readDataset(fileId: string): Promise<VersionedSharedDataset> {
    const value = this.datasets.get(fileId);
    if (!value) throw new SyncKitError("not-found", `Missing ${fileId}.`);
    return structuredClone(value);
  }
  async createDataset(datasetId: string, envelope: SharedBackupEnvelopeV1): Promise<VersionedSharedDataset> {
    const value: VersionedSharedDataset = {
      datasetId,
      fileId: `file-${datasetId}`,
      name: `${datasetId}.json`,
      canEdit: true,
      envelope: structuredClone(envelope),
      version: `v${++this.revision}`,
    };
    this.datasets.set(value.fileId, value);
    return structuredClone(value);
  }
  async writeDataset(current: VersionedSharedDataset, envelope: SharedBackupEnvelopeV1): Promise<VersionedSharedDataset> {
    const actual = this.datasets.get(current.fileId);
    if (actual?.version !== current.version) throw new SyncKitError("conflict", "Stale dataset write.");
    const updated = { ...actual, envelope: structuredClone(envelope), version: `v${++this.revision}` };
    this.datasets.set(current.fileId, updated);
    return structuredClone(updated);
  }
  deleteDataset(fileId: string): Promise<void> { this.datasets.delete(fileId); return Promise.resolve(); }
  grantExchangeAccess(): Promise<{ drivePermissionId: string; appFolderId: string }> { throw new Error("Not used by link flow."); }
  createInvitation(): Promise<string> { throw new Error("Not used by link flow."); }
  createKeyResponse(): Promise<string> { throw new Error("Not used by link flow."); }
  listExchanges(): Promise<SharedExchangeFile[]> { return Promise.resolve([]); }
  readInvitation(): Promise<SharingInvitationV1> { throw new Error("Not used by link flow."); }
  readKeyResponse(): Promise<SharedKeyResponseFile> { throw new Error("Not used by link flow."); }
  deleteExchange(): Promise<void> { return Promise.resolve(); }
  setDatasetPermission(_fileId: string, emailAddress: string, role: "admin" | "writer" | "viewer"): Promise<SharedDatasetPermission> {
    return Promise.resolve({ permissionId: `permission-${emailAddress}`, role: role === "viewer" ? "reader" : "writer" });
  }
  removeDatasetPermission(): Promise<void> { return Promise.resolve(); }
  listDatasetPermissions(): Promise<SharedDatasetDrivePermission[]> { return Promise.resolve([]); }
  listDatasetHeads(): Promise<[]> { return Promise.resolve([]); }
}
