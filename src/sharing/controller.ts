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
  type SharingRole,
} from "./index.js";
import type {
  SharedBackupStorage,
  SharedBackupTransport,
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
  outcome: "created" | "loaded" | "updated" | "unchanged";
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

export type SharedBackupControllerOptions<T> = {
  appId: string;
  codec: SharedBackupControllerCodec<T>;
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
      const identity = await this.options.identity();
      const envelope = await createSharedBackupEnvelopeV1(
        value,
        this.options.codec,
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

  loadDataset(datasetId: string): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      const stored = await this.readDatasetById(datasetId);
      const record = await this.requiredRegistry(datasetId);
      await this.verifyHead(stored, record);
      const value = await decryptSharedBackupEnvelopeV1(
        stored.envelope,
        this.options.codec,
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
      const remoteValue = await decryptSharedBackupEnvelopeV1(
        stored.envelope,
        this.options.codec,
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
      const merged = this.options.codec.merge(localValue, remoteValue);
      if (
        this.options.codec.fingerprint(merged) ===
        this.options.codec.fingerprint(remoteValue)
      ) {
        await this.persistHead(stored, record.trustedOwnerKeyId, record);
        return result(stored, merged, "unchanged");
      }
      const next = await createSharedBackupEnvelopeV1(
        merged,
        this.options.codec,
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
      const access = await this.options.transport.grantExchangeAccess(
        input.emailAddress,
        {
          ...(input.sendNotificationEmail === undefined
            ? {}
            : { sendNotificationEmail: input.sendNotificationEmail }),
          ...(input.emailMessage ? { emailMessage: input.emailMessage } : {}),
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
      if (
        binding &&
        this.options.requireAccountBinding &&
        !this.options.verifyAccountBinding
      ) {
        throw new SyncKitError(
          "configuration",
          "Account binding is required but no verifier is configured.",
        );
      }
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
      const results: AcceptedDatasetResult[] = [];
      for (const grant of accepted) {
        try {
          const stored = await this.readDatasetById(grant.datasetId);
          const record =
            (await this.options.registry.get(grant.datasetId)) ??
            this.initialOwnerRecord(stored);
          await this.verifyHead(stored, record);
          const value = await decryptSharedBackupEnvelopeV1(
            stored.envelope,
            this.options.codec,
            identity,
            this.crypto(),
            { trustedOwnerKeyId: record.trustedOwnerKeyId },
          );
          const participants = participantInputs(stored.envelope).filter(
            (participant) =>
              participant.publicKey.keyId !==
              grant.participant.publicKey.keyId,
          );
          participants.push(grant.participant);
          const next = await createSharedBackupEnvelopeV1(
            value,
            this.options.codec,
            identity,
            {
              appId: this.options.appId,
              backupId: grant.datasetId,
              participants,
              previous: stored.envelope,
            },
            this.cryptoOptions(),
          );
          const updated = await this.options.transport.writeDataset(
            stored,
            next,
          );
          const permission =
            await this.options.transport.setDatasetPermission(
              stored.fileId,
              input.recipientEmailAddress,
              grant.participant.role === "owner"
                ? "admin"
                : grant.participant.role,
              {
                hasInheritedReadAccess: true,
              },
            );
          const participantPermissionIds = {
            ...record.participantPermissionIds,
            ...(permission.permissionId
              ? {
                  [grant.participant.publicKey.keyId]:
                    permission.permissionId,
                }
              : {}),
          };
          const nextRecord: SharedDatasetRegistryRecord = {
            ...record,
            fileId: updated.fileId,
            lastRevisionId: updated.envelope.revisionId,
            participantPermissionIds,
          };
          await this.options.registry.set(nextRecord);
          results.push({
            datasetId: grant.datasetId,
            fileId: updated.fileId,
            revisionId: updated.envelope.revisionId,
            ...(permission.permissionId
              ? { permissionId: permission.permissionId }
              : {}),
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
    });
  }

  setDatasetRole(input: {
    datasetId: string;
    keyId: string;
    role: Exclude<SharingRole, "owner">;
    emailAddress: string;
  }): Promise<SharedDatasetResult<T>> {
    return this.changeParticipants(input.datasetId, (stored, value) => {
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
      return Promise.resolve({
        participants,
        value,
        afterWrite: async (updated, record) => {
          const permission =
            await this.options.transport.setDatasetPermission(
              updated.fileId,
              input.emailAddress,
              input.role,
              {
                ...(record.participantPermissionIds?.[input.keyId]
                  ? {
                      existingDirectPermissionId:
                        record.participantPermissionIds[input.keyId],
                    }
                  : {}),
                ...(input.role === "viewer"
                  ? { hasInheritedReadAccess: true }
                  : {}),
              },
            );
          const participantPermissionIds = {
            ...record.participantPermissionIds,
            ...(permission.permissionId
              ? { [input.keyId]: permission.permissionId }
              : {}),
          };
          await this.options.registry.set({
            ...record,
            participantPermissionIds,
          });
        },
      });
    });
  }

  revokeDatasetKey(input: {
    datasetId: string;
    keyId: string;
  }): Promise<SharedDatasetResult<T>> {
    return this.changeParticipants(input.datasetId, (stored, value) => {
      const participant = sharedBackupParticipant(stored.envelope, input.keyId);
      if (!participant) {
        throw new SyncKitError(
          "not-found",
          `Participant ${input.keyId} is not in this dataset.`,
        );
      }
      if (participant.role === "owner") {
        throw new SyncKitError(
          "authorization",
          "Owner transfer or removal is not supported by sharing v1.",
        );
      }
      const participants = participantInputs(stored.envelope).filter(
        (candidate) => candidate.publicKey.keyId !== input.keyId,
      );
      return Promise.resolve({
        participants,
        value,
        afterWrite: async (_updated, record) => {
          const permissionId = record.participantPermissionIds?.[input.keyId];
          if (permissionId) {
            await this.options.transport.removeDatasetPermission(
              stored.fileId,
              permissionId,
            );
          }
          const participantPermissionIds = Object.fromEntries(
            Object.entries(record.participantPermissionIds ?? {}).filter(
              ([keyId]) => keyId !== input.keyId,
            ),
          );
          await this.options.registry.set({
            ...record,
            participantPermissionIds,
          });
        },
      });
    });
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
          const value = await decryptSharedBackupEnvelopeV1(
            stored.envelope,
            this.options.codec,
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
            this.options.codec,
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

  private changeParticipants(
    datasetId: string,
    change: (
      stored: VersionedSharedDataset,
      value: T,
    ) => Promise<{
      participants: SharedBackupParticipantInput[];
      value: T;
      afterWrite?: (
        updated: VersionedSharedDataset,
        record: SharedDatasetRegistryRecord,
      ) => Promise<void>;
    }>,
  ): Promise<SharedDatasetResult<T>> {
    return this.serialized(async () => {
      const stored = await this.readDatasetById(datasetId);
      const record = await this.requiredRegistry(datasetId);
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
      const value = await decryptSharedBackupEnvelopeV1(
        stored.envelope,
        this.options.codec,
        identity,
        this.crypto(),
        { trustedOwnerKeyId: record.trustedOwnerKeyId },
      );
      const changed = await change(stored, value);
      const next = await createSharedBackupEnvelopeV1(
        changed.value,
        this.options.codec,
        identity,
        {
          appId: this.options.appId,
          backupId: datasetId,
          participants: changed.participants,
          previous: stored.envelope,
        },
        this.cryptoOptions(),
      );
      const updated = await this.options.transport.writeDataset(stored, next);
      const nextRecord = await this.persistHead(
        updated,
        record.trustedOwnerKeyId,
        record,
      );
      await changed.afterWrite?.(updated, nextRecord);
      return result(updated, changed.value, "updated");
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
