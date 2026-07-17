import { SyncKitError } from "../core/errors.js";
import {
  canAdministerSharedBackup,
  parseSharedBackupEnvelopeV1,
  sharedBackupParticipant,
  sharedBackupParticipants,
  type SharedBackupCodec,
  type SharedBackupEnvelopeV1,
  type SharingAccountBindingV1,
  type SharingDatasetGrantV1,
  type SharingInvitationV1,
  type SharingPublicKeyResponseV1,
  type SharingRole,
  type SharedBackupParticipantV1,
} from "./index.js";
import {
  createSharingLinkPermissionIdV1,
  verifySharingLinkDatasetFilesV1,
  type SharingDatasetFileV1,
} from "./link-exchange.js";
import type {
  SharedBackupStorage,
  SharedBackupTransport,
  SharedDatasetDrivePermission,
  SharedDatasetFile,
  SharedExchangeFile,
  VersionedSharedDataset,
} from "./transport.js";
import {
  acceptSharingPublicKeyResponseV1,
  createSharedBackupEnvelopeV1,
  createSharingInvitationV1,
  createSharingPublicKeyResponseV1,
  decryptSharedBackupEnvelopeV1,
  verifySharedBackupEnvelopeV1,
  verifySharingInvitationV1,
  type SharedBackupParticipantInput,
  type WebCryptoSharingIdentity,
  type WebCryptoSharingOptions,
} from "./web-crypto.js";
import { formatSharingInviteEmailMessage, appendSharingJoinParams } from "./join.js";
export { IndexedDbSharedBackupRegistry } from "./registry-indexeddb.js";

export type SharedBackupControllerCodec<T> = SharedBackupCodec<T> & {
  merge(local: T, remote: T): T;
  fingerprint(value: T): string;
};

export type SharedDatasetRegistryRecord = {
  datasetId: string;
  fileId?: string;
  trustedOwnerKeyId: string;
  lastRevisionId?: string;
  seenRevisionIds?: string[];
  participantPermissionIds?: Record<string, string>;
};

export interface SharedBackupRegistry {
  get(datasetId: string): Promise<SharedDatasetRegistryRecord | null>;
  set(record: SharedDatasetRegistryRecord): Promise<void>;
  delete(datasetId: string): Promise<void>;
}

export class MemorySharedBackupRegistry implements SharedBackupRegistry {
  private readonly records = new Map<string, SharedDatasetRegistryRecord>();

  get(datasetId: string): Promise<SharedDatasetRegistryRecord | null> {
    const record = this.records.get(datasetId);
    return Promise.resolve(record ? structuredClone(record) : null);
  }

  set(record: SharedDatasetRegistryRecord): Promise<void> {
    this.records.set(record.datasetId, structuredClone(record));
    return Promise.resolve();
  }

  delete(datasetId: string): Promise<void> {
    this.records.delete(datasetId);
    return Promise.resolve();
  }
}

export type SharedDatasetResult<T> = {
  datasetId: string;
  fileId: string;
  revisionId: string;
  value: T;
  outcome: "created" | "adopted" | "loaded" | "updated" | "unchanged";
};

export type SharingInvitationResult = {
  invitation: SharingInvitationV1;
  invitationFileId: string;
  drivePermissionId: string;
};

export type AcceptedDatasetResult = {
  datasetId: string;
  fileId?: string;
  revisionId?: string;
  permissionId?: string;
  status: "accepted" | "failed";
  error?: unknown;
};

export type RotatedDatasetResult = {
  datasetId: string;
  status: "rotated" | "failed";
  revisionId?: string;
  error?: unknown;
};

export type DrivePermissionReconciliationAction =
  | {
      kind: "granted" | "updated";
      keyId: string;
      permissionId: string;
      role: "reader" | "writer";
    }
  | { kind: "removed"; permissionId: string }
  | { kind: "unchanged"; keyId: string }
  | { kind: "skipped"; keyId: string; reason: string };

export type DrivePermissionReconciliationResult = {
  datasetId: string;
  actions: DrivePermissionReconciliationAction[];
};

export type SharedBackupControllerOptions<T> = {
  appId: string;
  codec: SharedBackupControllerCodec<T>;
  /**
   * Optional codec override selected by dataset ID for every operation that
   * serializes, parses, merges, fingerprints, or republishes that dataset.
   * Unknown dataset IDs fall back to `codec`. This lets one controller safely
   * coordinate application datasets and protocol-owned companions such as a
   * sharing control ledger without ever parsing with one codec and rewriting
   * with another.
   */
  codecForDataset?(datasetId: string): SharedBackupControllerCodec<unknown> | undefined;
  identity(): Promise<WebCryptoSharingIdentity>;
  transport: SharedBackupTransport;
  registry: SharedBackupRegistry;
  crypto?: Crypto;
  now?: () => Date;
  randomUUID?: () => string;
  createAccountBinding?(context: {
    appId: string;
    exchangeId: string;
    sharingKeyId: string;
  }): Promise<SharingAccountBindingV1>;
  verifyAccountBinding?(
    binding: SharingAccountBindingV1,
    context: {
      appId: string;
      exchangeId: string;
      sharingKeyId: string;
      credentialId: string;
    },
  ): Promise<{ subject: string }>;
  requireAccountBinding?: boolean;
  resolveFork?(context: {
    datasetId: string;
    lastVerifiedRevisionId: string;
    remoteRevisionId: string;
    localValue: T;
    remoteValue: T;
  }): Promise<"merge" | "reject">;
};

/**
 * Headless, backend-independent sharing orchestration. Consumers own UI,
 * persistence, lifecycle policy, and conflict resolution.
 */
export class SharedBackupController<T> {
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly options: SharedBackupControllerOptions<T>) {
    if (!options.appId.trim()) throw new TypeError("appId must not be empty.");
  }

  ensureStorage(): Promise<SharedBackupStorage> {
    return this.options.transport.ensureStorage();
  }

  listDatasets(): Promise<SharedDatasetFile[]> {
    return this.options.transport.listDatasets();
  }

  /** Returns the locally pinned genesis owner for a previously trusted dataset. */
  async getDatasetTrust(datasetId: string): Promise<{ trustedOwnerKeyId: string }> {
    const record = await this.requiredRegistry(datasetId);
    return { trustedOwnerKeyId: record.trustedOwnerKeyId };
  }

  /**
   * Reads the verified cryptographic membership for a dataset. This is useful
   * for a companion control ledger that mirrors key provenance and user-facing
   * contact metadata without making application payloads authoritative.
   */
  async getDatasetParticipants(datasetId: string): Promise<{
    trustedOwnerKeyId: string;
    participants: SharedBackupParticipantV1[];
  }> {
    const stored = await this.readDatasetById(datasetId);
    const record = await this.requiredRegistry(datasetId);
    await this.verifyHead(stored, record);
    return {
      trustedOwnerKeyId: record.trustedOwnerKeyId,
      participants: sharedBackupParticipants(stored.envelope),
    };
  }

  createDataset(
    datasetId: string,
    value: T,
  ): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      requireNonEmpty(datasetId, "datasetId");
      const duplicate = (await this.options.transport.listDatasets()).find(
        (dataset) => dataset.datasetId === datasetId,
      );
      if (duplicate) {
        throw new SyncKitError(
          "conflict",
          `Dataset ${datasetId} already exists.`,
        );
      }
      const codec = this.codecForDataset(datasetId);
      const identity = await this.options.identity();
      const envelope = await createSharedBackupEnvelopeV1(
        value,
        codec,
        identity,
        {
          appId: this.options.appId,
          backupId: datasetId,
          participants: [
            { publicKey: identity.publicKey, role: "owner" },
          ],
        },
        this.cryptoOptions(),
      );
      const stored = await this.options.transport.createDataset(
        datasetId,
        envelope,
      );
      await this.persistHead(stored, identity.publicKey.keyId);
      return result(stored, value, "created");
    });
  }

  /**
   * Reconnect to an existing dataset this identity can already decrypt —
   * e.g. after a reinstall, or when an interrupted setup left the remote
   * file without a local registry record. The owner key is pinned from the
   * envelope itself (trust-on-first-use), so callers recovering their own
   * dataset should pass `requireOwned` to insist this identity is the
   * dataset's owner.
   */
  adoptDataset(
    datasetId: string,
    options?: { requireOwned?: boolean },
  ): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      const stored = await this.readDatasetById(datasetId);
      const previous = await this.options.registry.get(datasetId);
      const record = previous ?? this.initialOwnerRecord(stored);
      await verifySharedBackupEnvelopeV1(stored.envelope, this.crypto(), {
        trustedOwnerKeyId: record.trustedOwnerKeyId,
      });
      const identity = await this.options.identity();
      const codec = this.codecForDataset(datasetId);
      if (options?.requireOwned) {
        const self = sharedBackupParticipant(
          stored.envelope,
          identity.publicKey.keyId,
        );
        if (self?.role !== "owner") {
          throw new SyncKitError(
            "authorization",
            `This identity does not own dataset ${datasetId}.`,
          );
        }
      }
      const value = await decryptSharedBackupEnvelopeV1(
        stored.envelope,
        codec,
        identity,
        this.crypto(),
        { trustedOwnerKeyId: record.trustedOwnerKeyId },
      );
      await this.persistHead(
        stored,
        record.trustedOwnerKeyId,
        previous ?? undefined,
      );
      return result(stored, value, "adopted");
    });
  }

  /** Delete a dataset file from the transport and forget its local record. */
  deleteDataset(datasetId: string): Promise<void> {
    return this.serialized(async () => {
      requireNonEmpty(datasetId, "datasetId");
      const stored = await this.readDatasetById(datasetId);
      const record = await this.requiredRegistry(datasetId);
      await this.verifyHead(stored, record);
      await this.requireDatasetOwner(stored);
      if (!this.options.transport.deleteDataset) {
        throw new SyncKitError(
          "state",
          "This transport does not support deleting datasets.",
        );
      }
      await this.options.transport.deleteDataset(stored.fileId);
      await this.options.registry.delete(datasetId);
    });
  }

  /**
   * Move a dataset file to the provider's trash and forget its local record.
   * The recovery-safe disposal for a topology migration's retired source
   * file: the owner can still restore it during the provider's grace window,
   * but it stops resolving as a live dataset
   * (docs/sharing-control-datasets.md, hard-cutover step 5).
   */
  trashDataset(datasetId: string): Promise<void> {
    return this.serialized(async () => {
      requireNonEmpty(datasetId, "datasetId");
      const stored = await this.readDatasetById(datasetId);
      const record = await this.requiredRegistry(datasetId);
      await this.verifyHead(stored, record);
      await this.requireDatasetOwner(stored);
      if (!this.options.transport.trashDataset) {
        throw new SyncKitError(
          "state",
          "This transport does not support trashing datasets.",
        );
      }
      await this.options.transport.trashDataset(stored.fileId);
      await this.options.registry.delete(datasetId);
    });
  }

  private async requireDatasetOwner(
    stored: VersionedSharedDataset,
  ): Promise<void> {
    const currentIdentity = await this.options.identity();
    const participant = sharedBackupParticipant(
      stored.envelope,
      currentIdentity.publicKey.keyId,
    );
    if (participant?.role !== "owner") {
      throw new SyncKitError(
        "authorization",
        `Only the cryptographic owner may dispose of dataset ${stored.datasetId}.`,
      );
    }
  }

  loadDataset(datasetId: string): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      const stored = await this.readDatasetById(datasetId);
      const record = await this.requiredRegistry(datasetId);
      await this.verifyHead(stored, record);
      const codec = this.codecForDataset(datasetId);
      const value = await decryptSharedBackupEnvelopeV1(
        stored.envelope,
        codec,
        await this.options.identity(),
        this.crypto(),
        { trustedOwnerKeyId: record.trustedOwnerKeyId },
      );
      await this.persistHead(stored, record.trustedOwnerKeyId, record);
      return result(stored, value, "loaded");
    });
  }

  syncDataset(
    datasetId: string,
    localValue: T,
  ): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      const stored = await this.readDatasetById(datasetId);
      const record = await this.requiredRegistry(datasetId);
      const forked = await this.verifyHead(stored, record, true);
      const identity = await this.options.identity();
      const codec = this.codecForDataset(datasetId);
      const remoteValue = await decryptSharedBackupEnvelopeV1(
        stored.envelope,
        codec,
        identity,
        this.crypto(),
        { trustedOwnerKeyId: record.trustedOwnerKeyId },
      );
      if (forked) {
        const decision = await this.options.resolveFork?.({
          datasetId,
          lastVerifiedRevisionId: record.lastRevisionId ?? "",
          remoteRevisionId: stored.envelope.revisionId,
          localValue,
          remoteValue,
        });
        if (decision !== "merge") {
          throw new SyncKitError(
            "conflict",
            `Dataset ${datasetId} has a divergent signed head.`,
          );
        }
      }
      const merged = codec.merge(localValue, remoteValue);
      if (
        codec.fingerprint(merged) ===
        codec.fingerprint(remoteValue)
      ) {
        await this.persistHead(stored, record.trustedOwnerKeyId, record);
        return result(stored, merged, "unchanged");
      }
      const next = await createSharedBackupEnvelopeV1(
        merged,
        codec,
        identity,
        {
          appId: this.options.appId,
          backupId: datasetId,
          participants: participantInputs(stored.envelope),
          previous: stored.envelope,
        },
        this.cryptoOptions(),
      );
      const updated = await this.options.transport.writeDataset(stored, next);
      await this.persistHead(updated, record.trustedOwnerKeyId, record);
      return result(updated, merged, "updated");
    });
  }

  inviteParticipant(input: {
    emailAddress: string;
    requestedGrants: SharingDatasetGrantV1[];
    expiresAt?: string;
    sendNotificationEmail?: boolean;
    emailMessage?: string;
  /** Consumer landing URL; folder ID is appended before the Drive notification. */
    joinLandingUrl?: string;
    /** Fully built join URL; must already include the app folder ID when used. */
    joinUrl?: string;
    appDisplayName?: string;
  }): Promise<SharingInvitationResult> {
    return this.serialized(async () => {
      const identity = await this.options.identity();
      const trustedOwnerKeyIds = new Set<string>();
      for (const grant of input.requestedGrants) {
        const stored = await this.readDatasetById(grant.datasetId);
        const record = await this.requiredRegistry(grant.datasetId);
        const verified = await verifySharedBackupEnvelopeV1(
          stored.envelope,
          this.crypto(),
          { trustedOwnerKeyId: record.trustedOwnerKeyId },
        );
        const actor = sharedBackupParticipant(
          verified,
          identity.publicKey.keyId,
        );
        if (!actor || !canAdministerSharedBackup(actor.role)) {
          throw new SyncKitError(
            "authorization",
            `This identity cannot invite participants to ${grant.datasetId}.`,
          );
        }
        trustedOwnerKeyIds.add(record.trustedOwnerKeyId);
      }
      if (trustedOwnerKeyIds.size !== 1) {
        throw new SyncKitError(
          "configuration",
          "One invitation cannot combine datasets with different owner trust roots.",
        );
      }
      const trustedOwnerKeyId = [...trustedOwnerKeyIds][0];
      if (!trustedOwnerKeyId) {
        throw new SyncKitError(
          "state",
          "The invitation has no owner trust root.",
        );
      }
      const storage = await this.options.transport.ensureStorage();
      const appDisplayName = input.appDisplayName?.trim() ?? this.options.appId;
      const emailMessage =
        input.emailMessage ??
        (input.joinLandingUrl
          ? formatSharingInviteEmailMessage({
              joinUrl: appendSharingJoinParams(input.joinLandingUrl, {
                appFolderId: storage.appFolderId,
              }),
              appDisplayName,
            })
          : input.joinUrl
            ? formatSharingInviteEmailMessage({
                joinUrl: input.joinUrl,
                appDisplayName,
              })
            : undefined);
      const access = await this.options.transport.grantExchangeAccess(
        input.emailAddress,
        {
          ...(input.sendNotificationEmail === undefined
            ? {}
            : { sendNotificationEmail: input.sendNotificationEmail }),
          ...(emailMessage ? { emailMessage } : {}),
        },
      );
      const invitation = await createSharingInvitationV1(
        identity,
        {
          appId: this.options.appId,
          appFolderId: access.appFolderId,
          recipientDrivePermissionId: access.drivePermissionId,
          requestedGrants: input.requestedGrants,
          trustedOwnerKeyId,
          ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
        },
        this.cryptoOptions(),
      );
      return {
        invitation,
        invitationFileId:
          await this.options.transport.createInvitation(invitation),
        drivePermissionId: access.drivePermissionId,
      };
    });
  }

  listExchanges(options?: {
    exchangeId?: string;
    kind?: SharedExchangeFile["kind"];
  }): Promise<SharedExchangeFile[]> {
    return this.options.transport.listExchanges(options);
  }

  submitKeyResponse(
    invitationFileId: string,
  ): Promise<{ responseFileId: string; exchangeId: string }> {
    return this.serialized(async () => {
      const invitation = await verifySharingInvitationV1(
        await this.options.transport.readInvitation(invitationFileId),
        {
          crypto: this.crypto(),
          ...(this.options.now ? { now: this.options.now } : {}),
        },
      );
      const storage = await this.options.transport.ensureStorage();
      if (
        invitation.appId !== this.options.appId ||
        invitation.appFolderId !== storage.appFolderId
      ) {
        throw new SyncKitError(
          "compatibility",
          "The invitation belongs to another app storage hierarchy.",
        );
      }
      const identity = await this.options.identity();
      const accountBinding = await this.options.createAccountBinding?.({
        appId: this.options.appId,
        exchangeId: invitation.exchangeId,
        sharingKeyId: identity.publicKey.keyId,
      });
      const response = await createSharingPublicKeyResponseV1(
        identity,
        {
          appId: this.options.appId,
          exchangeId: invitation.exchangeId,
          ...(accountBinding ? { accountBinding } : {}),
        },
        this.cryptoOptions(),
      );
      const datasets = await this.options.transport.listDatasets();
      const registrations = await Promise.all(
        invitation.requestedGrants.map(async (grant) => {
          const file = datasets.find(
            (dataset) => dataset.datasetId === grant.datasetId,
          );
          const existing = await this.options.registry.get(grant.datasetId);
          return { grant, file, existing };
        }),
      );
      for (const { grant, existing } of registrations) {
        if (
          existing &&
          existing.trustedOwnerKeyId !== invitation.trustedOwnerKeyId
        ) {
          throw new SyncKitError(
            "conflict",
            `Dataset ${grant.datasetId} is already pinned to another owner key.`,
          );
        }
      }
      for (const { grant, file, existing } of registrations) {
        await this.options.registry.set(
          existing
            ? {
                ...existing,
                ...(file ? { fileId: file.fileId } : {}),
              }
            : {
                datasetId: grant.datasetId,
                ...(file ? { fileId: file.fileId } : {}),
                trustedOwnerKeyId: invitation.trustedOwnerKeyId,
              },
        );
      }
      return {
        responseFileId:
          await this.options.transport.createKeyResponse(response),
        exchangeId: invitation.exchangeId,
      };
    });
  }

  acceptKeyResponse(input: {
    invitation: SharingInvitationV1;
    responseFileId: string;
    recipientEmailAddress: string;
  }): Promise<AcceptedDatasetResult[]> {
    return this.serialized(async () => {
      this.requireConfiguredAccountBindingVerifier();
      const identity = await this.options.identity();
      const responseFile = await this.options.transport.readKeyResponse(
        input.responseFileId,
        input.invitation.recipientDrivePermissionId,
      );
      const binding = responseFile.response.accountBinding;
      if (this.options.requireAccountBinding && !binding) {
        throw new SyncKitError(
          "authorization",
          "The key response has no required Google/passkey account binding.",
        );
      }
      const verifiedAccount =
        binding && this.options.verifyAccountBinding
          ? await this.options.verifyAccountBinding(binding, {
              appId: this.options.appId,
              exchangeId: input.invitation.exchangeId,
              sharingKeyId: responseFile.response.keyId,
              credentialId: binding.passkey.credentialId,
            })
          : undefined;
      const accepted = await acceptSharingPublicKeyResponseV1(
        input.invitation,
        responseFile.response,
        {
          acceptedByKeyId: identity.publicKey.keyId,
          drivePermissionId: responseFile.ownerPermissionId,
          ...(verifiedAccount
            ? { googleSubject: verifiedAccount.subject }
            : {}),
        },
        this.cryptoOptions(),
      );
      if (verifiedAccount) {
        await this.options.transport.deleteExchange(input.responseFileId);
      }
      return this.applyAcceptedGrants(
        accepted,
        identity,
        input.recipientEmailAddress,
      );
    });
  }

  /**
   * Applies verified acceptance grants to each dataset: add the participant,
   * re-encrypt, write, and per-email-share the dataset file. Shared by the
   * Drive-file accept path and the link-payload accept path.
   */
  private async applyAcceptedGrants(
    accepted: Awaited<ReturnType<typeof acceptSharingPublicKeyResponseV1>>,
    identity: WebCryptoSharingIdentity,
    recipientEmailAddress: string,
  ): Promise<AcceptedDatasetResult[]> {
    const results: AcceptedDatasetResult[] = [];
    for (const grant of accepted) {
      try {
        const stored = await this.readDatasetById(grant.datasetId);
        const record =
          (await this.options.registry.get(grant.datasetId)) ??
          this.initialOwnerRecord(stored);
        await this.verifyHead(stored, record);
        const { updated, permissionId } =
          await this.upsertDatasetParticipant({
            datasetId: grant.datasetId,
            participant: grant.participant,
            emailAddress: recipientEmailAddress,
            identity,
            stored,
            record,
          });
        results.push({
          datasetId: grant.datasetId,
          fileId: updated.fileId,
          revisionId: updated.envelope.revisionId,
          ...(permissionId ? { permissionId } : {}),
          status: "accepted",
        });
      } catch (error) {
        results.push({
          datasetId: grant.datasetId,
          status: "failed",
          error,
        });
      }
    }
    return results;
  }

  /**
   * Owner side of the link-carried exchange. Shares each granted dataset file
   * with the recipient's email (so it lands in their Picker) and returns the
   * signed invitation plus the file list to embed in the join link. Unlike
   * {@link inviteParticipant} it writes no Drive `exchanges/` invitation file.
   */
  inviteParticipantForLink(input: {
    emailAddress: string;
    requestedGrants: SharingDatasetGrantV1[];
    expiresAt?: string;
  }): Promise<{
    invitation: SharingInvitationV1;
    files: SharingDatasetFileV1[];
  }> {
    return this.serialized(async () => {
      const identity = await this.options.identity();
      const trustedOwnerKeyIds = new Set<string>();
      const files: SharingDatasetFileV1[] = [];
      for (const grant of input.requestedGrants) {
        const stored = await this.readDatasetById(grant.datasetId);
        const record = await this.requiredRegistry(grant.datasetId);
        const verified = await verifySharedBackupEnvelopeV1(
          stored.envelope,
          this.crypto(),
          { trustedOwnerKeyId: record.trustedOwnerKeyId },
        );
        const actor = sharedBackupParticipant(
          verified,
          identity.publicKey.keyId,
        );
        if (!actor || !canAdministerSharedBackup(actor.role)) {
          throw new SyncKitError(
            "authorization",
            `This identity cannot invite participants to ${grant.datasetId}.`,
          );
        }
        trustedOwnerKeyIds.add(record.trustedOwnerKeyId);
        await this.options.transport.setDatasetPermission(
          stored.fileId,
          input.emailAddress,
          "viewer",
          { hasInheritedReadAccess: false },
        );
        files.push({
          datasetId: grant.datasetId,
          fileId: stored.fileId,
          role: grant.role,
        });
      }
      if (trustedOwnerKeyIds.size !== 1) {
        throw new SyncKitError(
          "configuration",
          "One invitation cannot combine datasets with different owner trust roots.",
        );
      }
      const trustedOwnerKeyId = [...trustedOwnerKeyIds][0];
      if (!trustedOwnerKeyId) {
        throw new SyncKitError("state", "The invitation has no owner trust root.");
      }
      const storage = await this.options.transport.ensureStorage();
      const invitation = await createSharingInvitationV1(
        identity,
        {
          appId: this.options.appId,
          appFolderId: storage.appFolderId,
          recipientDrivePermissionId:
            await createSharingLinkPermissionIdV1(files, this.crypto()),
          requestedGrants: input.requestedGrants,
          trustedOwnerKeyId,
          ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
        },
        this.cryptoOptions(),
      );
      return { invitation, files };
    });
  }

  /**
   * Recipient side of the link-carried exchange. Verifies the invitation carried
   * in the join link, registers the granted datasets with their file ids (so
   * later reads/writes resolve without listing the owner's folder), and returns
   * a signed key response to send back to the owner. Reads/writes no Drive
   * `exchanges/` file.
   */
  submitKeyResponseFromInvitation(
    invitation: SharingInvitationV1,
    datasetFiles: SharingDatasetFileV1[],
  ): Promise<SharingPublicKeyResponseV1> {
    return this.serialized(async () => {
      const verified = await verifySharingInvitationV1(invitation, {
        crypto: this.crypto(),
        ...(this.options.now ? { now: this.options.now } : {}),
      });
      if (verified.appId !== this.options.appId) {
        throw new SyncKitError(
          "compatibility",
          "The invitation belongs to another app.",
        );
      }
      const verifiedFiles = await verifySharingLinkDatasetFilesV1(
        verified,
        datasetFiles,
        this.crypto(),
      );
      const identity = await this.options.identity();
      const accountBinding = await this.options.createAccountBinding?.({
        appId: this.options.appId,
        exchangeId: verified.exchangeId,
        sharingKeyId: identity.publicKey.keyId,
      });
      const response = await createSharingPublicKeyResponseV1(
        identity,
        {
          appId: this.options.appId,
          exchangeId: verified.exchangeId,
          ...(accountBinding ? { accountBinding } : {}),
        },
        this.cryptoOptions(),
      );
      const fileById = new Map(
        verifiedFiles.map((file) => [file.datasetId, file.fileId]),
      );
      for (const grant of verified.requestedGrants) {
        const existing = await this.options.registry.get(grant.datasetId);
        if (
          existing &&
          existing.trustedOwnerKeyId !== verified.trustedOwnerKeyId
        ) {
          throw new SyncKitError(
            "conflict",
            `Dataset ${grant.datasetId} is already pinned to another owner key.`,
          );
        }
        const fileId = fileById.get(grant.datasetId);
        await this.options.registry.set(
          existing
            ? { ...existing, ...(fileId ? { fileId } : {}) }
            : {
                datasetId: grant.datasetId,
                ...(fileId ? { fileId } : {}),
                trustedOwnerKeyId: verified.trustedOwnerKeyId,
              },
        );
      }
      return response;
    });
  }

  /**
   * Owner side. Accepts a key response carried in a response link (no Drive
   * `exchanges/` read), adds the recipient to each granted dataset, and
   * per-email shares the dataset files (re-affirming the invite-time share).
   * The invitation must be supplied by the caller (persisted at invite time,
   * keyed by exchange id).
   */
  acceptKeyResponseFromPayload(input: {
    invitation: SharingInvitationV1;
    response: SharingPublicKeyResponseV1;
    recipientEmailAddress: string;
  }): Promise<AcceptedDatasetResult[]> {
    return this.serialized(async () => {
      this.requireConfiguredAccountBindingVerifier();
      const identity = await this.options.identity();
      const binding = input.response.accountBinding;
      if (this.options.requireAccountBinding && !binding) {
        throw new SyncKitError(
          "authorization",
          "The key response has no required account binding.",
        );
      }
      const verifiedAccount =
        binding && this.options.verifyAccountBinding
          ? await this.options.verifyAccountBinding(binding, {
              appId: this.options.appId,
              exchangeId: input.invitation.exchangeId,
              sharingKeyId: input.response.keyId,
              credentialId: binding.passkey.credentialId,
            })
          : undefined;
      const accepted = await acceptSharingPublicKeyResponseV1(
        input.invitation,
        input.response,
        {
          acceptedByKeyId: identity.publicKey.keyId,
          drivePermissionId: input.invitation.recipientDrivePermissionId,
          ...(verifiedAccount ? { googleSubject: verifiedAccount.subject } : {}),
        },
        this.cryptoOptions(),
      );
      return this.applyAcceptedGrants(
        accepted,
        identity,
        input.recipientEmailAddress,
      );
    });
  }

  private requireConfiguredAccountBindingVerifier(): void {
    if (
      this.options.requireAccountBinding &&
      !this.options.verifyAccountBinding
    ) {
      throw new SyncKitError(
        "configuration",
        "Account binding is required but no verifier is configured.",
      );
    }
  }

  /**
   * Grant a dataset to a participant whose sharing public key this identity
   * already holds — no invitation/response exchange. This is how a topology
   * migration "shares each target with its intended recipients"
   * (docs/sharing-control-datasets.md, hard-cutover step 2), and how an
   * owner adds a dataset to someone who joined before that dataset existed:
   * the content key is wrapped to the participant's existing public key and
   * the file is per-email shared on the transport.
   *
   * Upsert semantics: re-running with the same participant updates their
   * role instead of failing, so interrupted migrations can simply run the
   * grant phase again.
   */
  addDatasetParticipant(input: {
    datasetId: string;
    participant: {
      publicKey: SharedBackupParticipantInput["publicKey"];
      role: Exclude<SharingRole, "owner">;
    };
    emailAddress: string;
  }): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      requireNonEmpty(input.datasetId, "datasetId");
      requireNonEmpty(input.emailAddress, "emailAddress");
      requireNonEmpty(input.participant.publicKey.keyId, "participant keyId");
      const stored = await this.readDatasetById(input.datasetId);
      const record = await this.requiredRegistry(input.datasetId);
      await this.verifyHead(stored, record);
      const identity = await this.options.identity();
      const actor = sharedBackupParticipant(
        stored.envelope,
        identity.publicKey.keyId,
      );
      if (!actor || !canAdministerSharedBackup(actor.role)) {
        throw new SyncKitError(
          "authorization",
          "Only a current owner or admin can grant dataset access.",
        );
      }
      const { updated, value } = await this.upsertDatasetParticipant({
        datasetId: input.datasetId,
        participant: input.participant,
        emailAddress: input.emailAddress,
        identity,
        stored,
        record,
      });
      return result(updated, value as T, "updated");
    });
  }

  setDatasetRole(input: {
    datasetId: string;
    keyId: string;
    role: Exclude<SharingRole, "owner">;
    emailAddress: string;
  }): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      requireNonEmpty(input.datasetId, "datasetId");
      requireNonEmpty(input.keyId, "keyId");
      requireNonEmpty(input.emailAddress, "emailAddress");
      const stored = await this.readDatasetById(input.datasetId);
      const record = await this.requiredRegistry(input.datasetId);
      await this.verifyHead(stored, record);
      const identity = await this.options.identity();
      const actor = sharedBackupParticipant(
        stored.envelope,
        identity.publicKey.keyId,
      );
      if (!actor || !canAdministerSharedBackup(actor.role)) {
        throw new SyncKitError(
          "authorization",
          "Only a current owner or admin can change dataset access.",
        );
      }
      const codec = this.codecForDataset(input.datasetId);
      const value = await decryptSharedBackupEnvelopeV1(
        stored.envelope,
        codec,
        identity,
        this.crypto(),
        { trustedOwnerKeyId: record.trustedOwnerKeyId },
      );
      const participants = participantInputs(stored.envelope);
      const participant = participants.find(
        (candidate) => candidate.publicKey.keyId === input.keyId,
      );
      if (!participant) {
        throw new SyncKitError(
          "not-found",
          `Participant ${input.keyId} is not in this dataset.`,
        );
      }
      participant.role = input.role;
      const existingPermission = await this.findDirectDatasetPermission(
        stored.fileId,
        record.participantPermissionIds?.[input.keyId],
        input.emailAddress,
      );
      const permission = await this.options.transport.setDatasetPermission(
        stored.fileId,
        input.emailAddress,
        input.role,
        {
          ...(existingPermission
            ? { existingDirectPermissionId: existingPermission.permissionId }
            : {}),
          ...(input.role === "viewer"
            ? { hasInheritedReadAccess: true }
            : {}),
        },
      );
      const participantPermissionIds = permission.permissionId
        ? {
            ...record.participantPermissionIds,
            [input.keyId]: permission.permissionId,
          }
        : Object.fromEntries(
            Object.entries(record.participantPermissionIds ?? {}).filter(
              ([keyId]) => keyId !== input.keyId,
            ),
          );
      const next = await createSharedBackupEnvelopeV1(
        value,
        codec,
        identity,
        {
          appId: this.options.appId,
          backupId: input.datasetId,
          participants,
          previous: stored.envelope,
        },
        this.cryptoOptions(),
      );
      const updated = await this.options.transport.writeDataset(stored, next);
      await this.persistHead(updated, record.trustedOwnerKeyId, {
        ...record,
        participantPermissionIds,
      });
      return result(updated, value, "updated");
    });
  }

  revokeDatasetKey(input: {
    datasetId: string;
    keyId: string;
    emailAddress?: string;
  }): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      const stored = await this.readDatasetById(input.datasetId);
      const record = await this.requiredRegistry(input.datasetId);
      await this.verifyHead(stored, record);
      const identity = await this.options.identity();
      const actor = sharedBackupParticipant(
        stored.envelope,
        identity.publicKey.keyId,
      );
      if (!actor || !canAdministerSharedBackup(actor.role)) {
        throw new SyncKitError(
          "authorization",
          "Only a current owner or admin can change dataset access.",
        );
      }
      const codec = this.codecForDataset(input.datasetId);
      const value = await decryptSharedBackupEnvelopeV1(
        stored.envelope,
        codec,
        identity,
        this.crypto(),
        { trustedOwnerKeyId: record.trustedOwnerKeyId },
      );
      const participant = sharedBackupParticipant(stored.envelope, input.keyId);
      if (!participant) {
        const permission = await this.findDirectDatasetPermission(
          stored.fileId,
          record.participantPermissionIds?.[input.keyId],
          input.emailAddress,
        );
        if (permission) {
          await this.options.transport.removeDatasetPermission(
            stored.fileId,
            permission.permissionId,
          );
        }
        await this.options.registry.set({
          ...record,
          participantPermissionIds: Object.fromEntries(
            Object.entries(record.participantPermissionIds ?? {}).filter(
              ([keyId]) => keyId !== input.keyId,
            ),
          ),
        });
        return result(stored, value, "unchanged");
      }
      if (participant.role === "owner") {
        throw new SyncKitError(
          "authorization",
          "Owner transfer or removal is not supported by sharing v1.",
        );
      }
      const permission = await this.findDirectDatasetPermission(
        stored.fileId,
        record.participantPermissionIds?.[input.keyId],
        input.emailAddress,
      );
      if (permission) {
        await this.options.transport.removeDatasetPermission(
          stored.fileId,
          permission.permissionId,
        );
      }
      const participants = participantInputs(stored.envelope).filter(
        (candidate) => candidate.publicKey.keyId !== input.keyId,
      );
      const next = await createSharedBackupEnvelopeV1(
        value,
        codec,
        identity,
        {
          appId: this.options.appId,
          backupId: input.datasetId,
          participants,
          previous: stored.envelope,
        },
        this.cryptoOptions(),
      );
      const updated = await this.options.transport.writeDataset(stored, next);
      await this.persistHead(
        updated,
        record.trustedOwnerKeyId,
        {
          ...record,
          participantPermissionIds: Object.fromEntries(
            Object.entries(record.participantPermissionIds ?? {}).filter(
              ([keyId]) => keyId !== input.keyId,
            ),
          ),
        },
      );
      return result(updated, value, "updated");
    });
  }

  private async findDirectDatasetPermission(
    fileId: string,
    permissionId?: string,
    emailAddress?: string,
  ): Promise<SharedDatasetDrivePermission | undefined> {
    const directPermissions = (
      await this.options.transport.listDatasetPermissions(fileId)
    ).filter((permission) => !permission.inherited);
    if (permissionId) {
      const byId = directPermissions.find(
        (permission) => permission.permissionId === permissionId,
      );
      if (byId) return byId;
    }
    const normalizedEmail = emailAddress?.trim().toLowerCase();
    if (!normalizedEmail) return undefined;
    return directPermissions.find(
      (permission) =>
        permission.emailAddress?.toLowerCase() === normalizedEmail,
    );
  }

  /**
   * Common participant upsert used by both verified invitation acceptance and
   * direct grants to already-known keys. Build and publish the signed envelope
   * before changing the provider ACL so a failed crypto/write step cannot
   * leave an untracked writer permission behind.
   */
  private async upsertDatasetParticipant(input: {
    datasetId: string;
    participant: SharedBackupParticipantInput;
    emailAddress: string;
    identity: WebCryptoSharingIdentity;
    stored: VersionedSharedDataset;
    record: SharedDatasetRegistryRecord;
  }): Promise<{
    updated: VersionedSharedDataset;
    value: unknown;
    permissionId?: string;
  }> {
    const codec = this.codecForDataset(input.datasetId);
    const value = await decryptSharedBackupEnvelopeV1(
      input.stored.envelope,
      codec,
      input.identity,
      this.crypto(),
      { trustedOwnerKeyId: input.record.trustedOwnerKeyId },
    );
    const participants = participantInputs(input.stored.envelope).filter(
      (candidate) =>
        candidate.publicKey.keyId !== input.participant.publicKey.keyId,
    );
    participants.push(input.participant);
    const next = await createSharedBackupEnvelopeV1(
      value,
      codec,
      input.identity,
      {
        appId: this.options.appId,
        backupId: input.datasetId,
        participants,
        previous: input.stored.envelope,
      },
      this.cryptoOptions(),
    );
    const updated = await this.options.transport.writeDataset(
      input.stored,
      next,
    );
    const existingPermission = await this.findDirectDatasetPermission(
      input.stored.fileId,
      input.record.participantPermissionIds?.[
        input.participant.publicKey.keyId
      ],
      input.emailAddress,
    );
    const driveRole =
      input.participant.role === "owner" ? "admin" : input.participant.role;
    const permission = await this.options.transport.setDatasetPermission(
      input.stored.fileId,
      input.emailAddress,
      driveRole,
      {
        ...(existingPermission
          ? { existingDirectPermissionId: existingPermission.permissionId }
          : {}),
        ...(driveRole === "viewer"
          ? { hasInheritedReadAccess: true }
          : {}),
      },
    );
    const participantPermissionIds = permission.permissionId
      ? {
          ...input.record.participantPermissionIds,
          [input.participant.publicKey.keyId]: permission.permissionId,
        }
      : Object.fromEntries(
          Object.entries(input.record.participantPermissionIds ?? {}).filter(
            ([keyId]) => keyId !== input.participant.publicKey.keyId,
          ),
        );
    await this.persistHead(updated, input.record.trustedOwnerKeyId, {
      ...input.record,
      participantPermissionIds,
    });
    return {
      updated,
      value,
      ...(permission.permissionId
        ? { permissionId: permission.permissionId }
        : {}),
    };
  }

  rotateLocalKey(
    replacementIdentity: WebCryptoSharingIdentity,
    datasetIds: string[],
  ): Promise<RotatedDatasetResult[]> {
    return this.serialized(async () => {
      const currentIdentity = await this.options.identity();
      const results: RotatedDatasetResult[] = [];
      for (const datasetId of datasetIds) {
        try {
          const stored = await this.readDatasetById(datasetId);
          const record = await this.requiredRegistry(datasetId);
          await this.verifyHead(stored, record);
          const current = sharedBackupParticipant(
            stored.envelope,
            currentIdentity.publicKey.keyId,
          );
          if (!current || current.role === "viewer") {
            throw new SyncKitError(
              "authorization",
              "Only a current owner, admin, or writer can rotate its own key.",
            );
          }
          const codec = this.codecForDataset(datasetId);
          const value = await decryptSharedBackupEnvelopeV1(
            stored.envelope,
            codec,
            currentIdentity,
            this.crypto(),
            { trustedOwnerKeyId: record.trustedOwnerKeyId },
          );
          const participants = participantInputs(stored.envelope).map(
            (participant) =>
              participant.publicKey.keyId === currentIdentity.publicKey.keyId
                ? {
                    publicKey: replacementIdentity.publicKey,
                    role: participant.role,
                    ...(participant.accepted
                      ? { accepted: participant.accepted }
                      : {}),
                  }
                : participant,
          );
          const next = await createSharedBackupEnvelopeV1(
            value,
            codec,
            replacementIdentity,
            {
              appId: this.options.appId,
              backupId: datasetId,
              participants,
              previous: stored.envelope,
              keyRotation: { previousIdentity: currentIdentity },
            },
            this.cryptoOptions(),
          );
          const updated = await this.options.transport.writeDataset(
            stored,
            next,
          );
          const permission =
            record.participantPermissionIds?.[
              currentIdentity.publicKey.keyId
            ];
          const permissions = Object.fromEntries(
            Object.entries(record.participantPermissionIds ?? {}).filter(
              ([keyId]) => keyId !== currentIdentity.publicKey.keyId,
            ),
          );
          if (permission) {
            permissions[replacementIdentity.publicKey.keyId] = permission;
          }
          await this.persistHead(
            updated,
            record.trustedOwnerKeyId,
            {
              ...record,
              participantPermissionIds: permissions,
            },
          );
          results.push({
            datasetId,
            status: "rotated",
            revisionId: updated.envelope.revisionId,
          });
        } catch (error) {
          results.push({ datasetId, status: "failed", error });
        }
      }
      return results;
    });
  }

  reconcileDrivePermissions(input: {
    datasetId: string;
    participantEmails: Record<string, string>;
  }): Promise<DrivePermissionReconciliationResult> {
    return this.serialized(async () => {
      const stored = await this.readDatasetById(input.datasetId);
      const record = await this.requiredRegistry(input.datasetId);
      await this.verifyHead(stored, record);
      const identity = await this.options.identity();
      const actor = sharedBackupParticipant(
        stored.envelope,
        identity.publicKey.keyId,
      );
      if (!actor || !canAdministerSharedBackup(actor.role)) {
        throw new SyncKitError(
          "authorization",
          "Only a current owner or admin can reconcile Drive permissions.",
        );
      }
      const livePermissions = await this.options.transport.listDatasetPermissions(
        stored.fileId,
      );
      const directPermissions = livePermissions.filter(
        (permission) => !permission.inherited,
      );
      const actions: DrivePermissionReconciliationAction[] = [];
      const expectedPermissionIds = new Set<string>();
      let participantPermissionIds = {
        ...record.participantPermissionIds,
      };
      const participants = sharedBackupParticipants(stored.envelope).filter(
        (participant): participant is typeof participant & {
          role: Exclude<SharingRole, "owner">;
        } => participant.role !== "owner",
      );
      for (const participant of participants) {
        const emailAddress = input.participantEmails[participant.keyId]?.trim();
        const expectedRole = sharingRoleToDriveRole(participant.role);
        const permissionId = participantPermissionIds[participant.keyId];
        const live = permissionId
          ? directPermissions.find(
              (permission) => permission.permissionId === permissionId,
            )
          : emailAddress
            ? directPermissions.find(
                (permission) =>
                  permission.emailAddress?.toLowerCase() ===
                  emailAddress.toLowerCase(),
              )
            : undefined;
        if (
          participant.role === "viewer" &&
          !permissionId &&
          !emailAddress &&
          livePermissions.some(
            (permission) =>
              permission.inherited && permission.role === "reader",
          )
        ) {
          actions.push({
            kind: "unchanged",
            keyId: participant.keyId,
          });
          continue;
        }
        if (!emailAddress) {
          if (live?.role === expectedRole) {
            expectedPermissionIds.add(live.permissionId);
            actions.push({ kind: "unchanged", keyId: participant.keyId });
          } else {
            actions.push({
              kind: "skipped",
              keyId: participant.keyId,
              reason: "No email address was provided for reconciliation.",
            });
            if (live) {
              expectedPermissionIds.add(live.permissionId);
            }
          }
          continue;
        }
        if (live?.role === expectedRole) {
          expectedPermissionIds.add(live.permissionId);
          if (permissionId !== live.permissionId) {
            participantPermissionIds = {
              ...participantPermissionIds,
              [participant.keyId]: live.permissionId,
            };
          }
          actions.push({ kind: "unchanged", keyId: participant.keyId });
          continue;
        }
        const permission = await this.options.transport.setDatasetPermission(
          stored.fileId,
          emailAddress,
          participant.role,
          {
            ...(live?.permissionId
              ? { existingDirectPermissionId: live.permissionId }
              : {}),
            ...(participant.role === "viewer"
              ? { hasInheritedReadAccess: true }
              : {}),
          },
        );
        if (!permission.permissionId) {
          actions.push({
            kind: "unchanged",
            keyId: participant.keyId,
          });
          continue;
        }
        expectedPermissionIds.add(permission.permissionId);
        participantPermissionIds = {
          ...participantPermissionIds,
          [participant.keyId]: permission.permissionId,
        };
        actions.push({
          kind: live ? "updated" : "granted",
          keyId: participant.keyId,
          permissionId: permission.permissionId,
          role: permission.role,
        });
      }
      if (
        JSON.stringify(participantPermissionIds) !==
        JSON.stringify(record.participantPermissionIds ?? {})
      ) {
        await this.options.registry.set({
          ...record,
          participantPermissionIds,
        });
      }
      const removedPermissionIds = new Set<string>();
      for (const permission of directPermissions) {
        const tracked = Object.values(participantPermissionIds).includes(
          permission.permissionId,
        );
        if (
          tracked &&
          !expectedPermissionIds.has(permission.permissionId)
        ) {
          await this.options.transport.removeDatasetPermission(
            stored.fileId,
            permission.permissionId,
          );
          removedPermissionIds.add(permission.permissionId);
          actions.push({
            kind: "removed",
            permissionId: permission.permissionId,
          });
        }
      }
      if (removedPermissionIds.size > 0) {
        participantPermissionIds = Object.fromEntries(
          Object.entries(participantPermissionIds).filter(
            ([, permissionId]) => !removedPermissionIds.has(permissionId),
          ),
        );
        await this.options.registry.set({
          ...record,
          participantPermissionIds,
        });
      }
      return { datasetId: input.datasetId, actions };
    });
  }

  private async readDatasetById(
    datasetId: string,
  ): Promise<VersionedSharedDataset> {
    requireNonEmpty(datasetId, "datasetId");
    const record = await this.options.registry.get(datasetId);
    const file =
      record?.fileId ??
      (await this.options.transport.listDatasets()).find(
        (candidate) => candidate.datasetId === datasetId,
      )?.fileId;
    if (!file) {
      throw new SyncKitError(
        "not-found",
        `Dataset ${datasetId} was not found.`,
      );
    }
    return this.options.transport.readDataset(file);
  }

  private async requiredRegistry(
    datasetId: string,
  ): Promise<SharedDatasetRegistryRecord> {
    const record = await this.options.registry.get(datasetId);
    if (!record) {
      throw new SyncKitError(
        "state",
        `Dataset ${datasetId} has no pinned owner key. Open it from a verified invitation first.`,
      );
    }
    return record;
  }

  private async verifyHead(
    stored: VersionedSharedDataset,
    record: SharedDatasetRegistryRecord,
    allowFork = false,
  ): Promise<boolean> {
    await verifySharedBackupEnvelopeV1(stored.envelope, this.crypto(), {
      trustedOwnerKeyId: record.trustedOwnerKeyId,
    });
    if (!record.lastRevisionId) return false;
    if (
      stored.envelope.revisionId !== record.lastRevisionId &&
      record.seenRevisionIds?.includes(stored.envelope.revisionId)
    ) {
      throw new SyncKitError(
        "conflict",
        `Dataset ${stored.datasetId} rolled back to a previously verified revision.`,
      );
    }
    if (
      stored.envelope.revisionId === record.lastRevisionId ||
      stored.envelope.parentRevisionId === record.lastRevisionId ||
      stored.envelope.revisionAncestors?.includes(record.lastRevisionId)
    ) {
      return false;
    }
    if (allowFork) return true;
    throw new SyncKitError(
      "conflict",
      `Dataset ${stored.datasetId} has a divergent signed head.`,
    );
  }

  private initialOwnerRecord(
    stored: VersionedSharedDataset,
  ): SharedDatasetRegistryRecord {
    const owner = sharedBackupParticipants(stored.envelope).find(
      (participant) => participant.role === "owner",
    );
    if (!owner) {
      throw new SyncKitError(
        "compatibility",
        "The dataset has no owner.",
      );
    }
    return {
      datasetId: stored.datasetId,
      fileId: stored.fileId,
      trustedOwnerKeyId: owner.keyId,
    };
  }

  private async persistHead(
    stored: VersionedSharedDataset,
    trustedOwnerKeyId: string,
    previous?: SharedDatasetRegistryRecord,
  ): Promise<SharedDatasetRegistryRecord> {
    const record: SharedDatasetRegistryRecord = {
      datasetId: stored.datasetId,
      fileId: stored.fileId,
      trustedOwnerKeyId,
      lastRevisionId: stored.envelope.revisionId,
      seenRevisionIds: [
        ...new Set([
          ...(previous?.seenRevisionIds ?? []),
          ...(previous?.lastRevisionId ? [previous.lastRevisionId] : []),
          stored.envelope.revisionId,
        ]),
      ].slice(-256),
      ...(previous?.participantPermissionIds
        ? { participantPermissionIds: previous.participantPermissionIds }
        : {}),
    };
    await this.options.registry.set(record);
    return record;
  }

  private crypto(): Crypto {
    const implementation = this.options.crypto ?? globalThis.crypto;
    if (!implementation?.subtle) {
      throw new SyncKitError(
        "configuration",
        "WebCrypto is required by the sharing controller.",
      );
    }
    return implementation;
  }

  private codecForDataset(datasetId: string): SharedBackupControllerCodec<T> {
    return (this.options.codecForDataset?.(datasetId) ??
      this.options.codec) as SharedBackupControllerCodec<T>;
  }

  private cryptoOptions(): WebCryptoSharingOptions {
    return {
      crypto: this.crypto(),
      ...(this.options.now ? { now: this.options.now } : {}),
      ...(this.options.randomUUID
        ? { randomUUID: this.options.randomUUID }
        : {}),
    };
  }

  private serialized<R>(operation: () => Promise<R>): Promise<R> {
    const run = this.queue.then(operation, operation);
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

export function createSharedBackupController<T>(
  options: SharedBackupControllerOptions<T>,
): SharedBackupController<T> {
  return new SharedBackupController(options);
}

function sharingRoleToDriveRole(
  role: Exclude<SharingRole, "owner">,
): "reader" | "writer" {
  return role === "viewer" ? "reader" : "writer";
}

function participantInputs(
  envelope: SharedBackupEnvelopeV1,
): SharedBackupParticipantInput[] {
  return sharedBackupParticipants(envelope).map((participant) => ({
    publicKey: {
      keyId: participant.keyId,
      encryptionAlgorithm: participant.encryptionAlgorithm,
      encryptionPublicKey: participant.encryptionPublicKey,
      signatureAlgorithm: participant.signatureAlgorithm,
      signingPublicKey: participant.signingPublicKey,
    },
    role: participant.role,
    ...(participant.accepted ? { accepted: participant.accepted } : {}),
  }));
}

function result<T>(
  stored: VersionedSharedDataset,
  value: T,
  outcome: SharedDatasetResult<T>["outcome"],
): SharedDatasetResult<T> {
  const envelope = parseSharedBackupEnvelopeV1(stored.envelope);
  return {
    datasetId: stored.datasetId,
    fileId: stored.fileId,
    revisionId: envelope.revisionId,
    value,
    outcome,
  };
}

function requireNonEmpty(value: string, name: string): void {
  if (!value.trim()) throw new TypeError(`${name} must not be empty.`);
}
