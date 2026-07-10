import { SyncKitError } from "../core/errors.js";
import { base64UrlToBytes, bytesToBase64Url } from "../crypto/base64url.js";
import { canonicalAad, canonicalJson, compareUtf16CodeUnits } from "../crypto/canonical.js";
import { copyBuffer } from "../crypto/runtime.js";
import type { SharingPublicKeyV1 } from "./index.js";
import {
  createSharingPublicKeyV1,
  type WebCryptoSharingIdentity,
} from "./web-crypto.js";
import type {
  SharedBackupController,
  SharedBackupControllerCodec,
  SharedDatasetResult,
} from "./controller.js";

/**
 * An encrypted, merge-safe coordination dataset. It is intentionally separate
 * from application data so every profile participant may acknowledge a
 * migration without being allowed to modify the data being migrated.
 */
export const SHARING_CONTROL_KIND = "sync-kit-sharing-control" as const;
export const SHARING_CONTROL_EVENT_KIND = "sync-kit-sharing-control-event" as const;

export type SharingControlMemberV1 = {
  publicKey: SharingPublicKeyV1;
  email?: string;
  googleSubject?: string;
  drivePermissionId?: string;
};

export type SharingControlMigrationTargetV1 = {
  datasetId: string;
  fileId: string;
  revisionId?: string;
};

export type SharingControlMigrationRequirementV1 = {
  keyId: string;
  targetFileIds: string[];
};

export type SharingControlMigrationV1 = {
  migrationId: string;
  sourceDatasetIds: string[];
  targets: SharingControlMigrationTargetV1[];
  requiredAcks: SharingControlMigrationRequirementV1[];
  mode: "hard-cutover";
};

type SharingControlEventBaseV1 = {
  schemaVersion: 1;
  kind: typeof SHARING_CONTROL_EVENT_KIND;
  eventId: string;
  profileId: string;
  actorKeyId: string;
  sequence: number;
  createdAt: string;
  signature: string;
};

export type SharingControlMemberUpsertEventV1 = SharingControlEventBaseV1 & {
  type: "member-upsert";
  member: SharingControlMemberV1;
};

export type SharingControlMigrationAnnouncedEventV1 =
  SharingControlEventBaseV1 & {
    type: "migration-announced";
    migration: SharingControlMigrationV1;
  };

export type SharingControlMigrationAcknowledgedEventV1 =
  SharingControlEventBaseV1 & {
    type: "migration-acknowledged";
    migrationId: string;
    openedFileIds: string[];
  };

export type SharingControlMigrationClosedEventV1 = SharingControlEventBaseV1 & {
  type: "migration-closed";
  migrationId: string;
  forced?: boolean;
};

export type SharingControlEventV1 =
  | SharingControlMemberUpsertEventV1
  | SharingControlMigrationAnnouncedEventV1
  | SharingControlMigrationAcknowledgedEventV1
  | SharingControlMigrationClosedEventV1;

type UnsignedSharingControlEventV1 =
  | Omit<SharingControlMemberUpsertEventV1, keyof SharingControlEventBaseV1>
  | Omit<SharingControlMigrationAnnouncedEventV1, keyof SharingControlEventBaseV1>
  | Omit<SharingControlMigrationAcknowledgedEventV1, keyof SharingControlEventBaseV1>
  | Omit<SharingControlMigrationClosedEventV1, keyof SharingControlEventBaseV1>;

export type SharingControlStateV1 = {
  schemaVersion: 1;
  kind: typeof SHARING_CONTROL_KIND;
  profileId: string;
  events: SharingControlEventV1[];
};

export type VerifiedSharingControlStateV1 = {
  state: SharingControlStateV1;
  ownerKeyId: string;
  members: Map<string, SharingControlMemberV1>;
  migrations: Map<string, SharingControlMigrationV1>;
  acknowledgements: Map<string, Map<string, SharingControlMigrationAcknowledgedEventV1>>;
  closedMigrations: Set<string>;
};

export type SharingControlMigrationStatusV1 = {
  migration: SharingControlMigrationV1;
  acknowledgedKeyIds: string[];
  pendingKeyIds: string[];
  closed: boolean;
};

export type SharingControlDatasetOptions = {
  controller: SharedBackupController<SharingControlStateV1>;
  datasetId: string;
  profileId: string;
  identity(): Promise<WebCryptoSharingIdentity>;
  crypto?: Crypto;
  now?: () => Date;
  randomUUID?: () => string;
  maxPublishAttempts?: number;
};

/**
 * Creates a codec whose merge is an event-id union. Signature and authority
 * validation is intentionally asynchronous and is performed by
 * `verifySharingControlStateV1` before callers act on the state.
 */
export function createSharingControlCodec(): SharedBackupControllerCodec<SharingControlStateV1> {
  return {
    serialize: (value) => parseSharingControlStateV1(value),
    parse: parseSharingControlStateV1,
    merge: mergeSharingControlStates,
    fingerprint: canonicalJson,
  };
}

export function parseSharingControlStateV1(value: unknown): SharingControlStateV1 {
  const state = object(value, "control state");
  exact(state.schemaVersion, 1, "control state schemaVersion");
  exact(state.kind, SHARING_CONTROL_KIND, "control state kind");
  nonEmpty(state.profileId, "control state profileId");
  if (!Array.isArray(state.events)) {
    throw new SyncKitError("compatibility", "Control state events must be an array.");
  }
  const events = state.events.map(parseSharingControlEventV1);
  const eventIds = new Set<string>();
  for (const event of events) {
    if (event.profileId !== state.profileId) {
      throw new SyncKitError("compatibility", "A control event belongs to another profile.");
    }
    if (eventIds.has(event.eventId)) {
      throw new SyncKitError("compatibility", `Duplicate control event ${event.eventId}.`);
    }
    eventIds.add(event.eventId);
  }
  return { schemaVersion: 1, kind: SHARING_CONTROL_KIND, profileId: state.profileId, events: sortEvents(events) };
}

export function parseSharingControlEventV1(value: unknown): SharingControlEventV1 {
  const event = object(value, "control event");
  exact(event.schemaVersion, 1, "control event schemaVersion");
  exact(event.kind, SHARING_CONTROL_EVENT_KIND, "control event kind");
  for (const key of ["eventId", "profileId", "actorKeyId", "createdAt", "signature"] as const) {
    nonEmpty(event[key], `control event ${key}`);
  }
  if (!Number.isSafeInteger(event.sequence) || (event.sequence as number) < 0) {
    throw new SyncKitError("compatibility", "control event sequence must be a non-negative integer.");
  }
  validTime(event.createdAt as string, "control event createdAt");
  const base = {
    schemaVersion: 1 as const,
    kind: SHARING_CONTROL_EVENT_KIND,
    eventId: event.eventId as string,
    profileId: event.profileId as string,
    actorKeyId: event.actorKeyId as string,
    sequence: event.sequence as number,
    createdAt: event.createdAt as string,
    signature: event.signature as string,
  };
  switch (event.type) {
    case "member-upsert":
      return { ...base, type: "member-upsert", member: parseMember(event.member) };
    case "migration-announced":
      return { ...base, type: "migration-announced", migration: parseMigration(event.migration) };
    case "migration-acknowledged":
      nonEmpty(event.migrationId, "control acknowledgement migrationId");
      return {
        ...base,
        type: "migration-acknowledged",
        migrationId: event.migrationId,
        openedFileIds: stringArray(event.openedFileIds, "control acknowledgement openedFileIds"),
      };
    case "migration-closed":
      nonEmpty(event.migrationId, "control close migrationId");
      if (event.forced !== undefined && typeof event.forced !== "boolean") {
        throw new SyncKitError("compatibility", "control close forced must be a boolean.");
      }
      return {
        ...base,
        type: "migration-closed",
        migrationId: event.migrationId,
        ...(event.forced === undefined ? {} : { forced: event.forced }),
      };
    default:
      throw new SyncKitError("compatibility", "Unsupported control event type.");
  }
}

export function mergeSharingControlStates(
  local: SharingControlStateV1,
  remote: SharingControlStateV1,
): SharingControlStateV1 {
  const left = parseSharingControlStateV1(local);
  const right = parseSharingControlStateV1(remote);
  if (left.profileId !== right.profileId) {
    throw new SyncKitError("compatibility", "Cannot merge control states for different profiles.");
  }
  const events = new Map<string, SharingControlEventV1>();
  for (const event of [...left.events, ...right.events]) {
    const existing = events.get(event.eventId);
    if (existing && canonicalJson(existing) !== canonicalJson(event)) {
      throw new SyncKitError("conflict", `Control event ${event.eventId} has conflicting contents.`);
    }
    events.set(event.eventId, event);
  }
  return { schemaVersion: 1, kind: SHARING_CONTROL_KIND, profileId: left.profileId, events: sortEvents([...events.values()]) };
}

export async function verifySharingControlStateV1(
  input: SharingControlStateV1,
  cryptoImplementation: Crypto = globalThis.crypto,
  options: { trustedOwnerKeyId?: string } = {},
): Promise<VerifiedSharingControlStateV1> {
  const state = parseSharingControlStateV1(input);
  const members = new Map<string, SharingControlMemberV1>();
  const migrations = new Map<string, SharingControlMigrationV1>();
  const acknowledgements = new Map<string, Map<string, SharingControlMigrationAcknowledgedEventV1>>();
  const closedMigrations = new Set<string>();
  const events = sortEvents(state.events);
  const genesis = events[0];
  if (genesis?.sequence !== 0 || genesis.type !== "member-upsert" || genesis.actorKeyId !== genesis.member.publicKey.keyId) {
    throw new SyncKitError("authorization", "The first control event must be a self-signed owner member record.");
  }
  const ownerKeyId = genesis.actorKeyId;
  if (options.trustedOwnerKeyId && ownerKeyId !== options.trustedOwnerKeyId) {
    throw new SyncKitError("authorization", "The control ledger owner does not match the pinned dataset owner.");
  }
  for (const event of events) {
    const actor = members.get(event.actorKeyId) ??
      (event === genesis ? genesis.member : undefined);
    if (!actor) {
      throw new SyncKitError("authorization", `Control event ${event.eventId} has an unknown actor.`);
    }
    await verifyEvent(event, actor.publicKey, cryptoImplementation);
    if (event.type === "member-upsert") {
      if (event.actorKeyId !== ownerKeyId) {
        throw new SyncKitError("authorization", "Only the control owner may publish membership records.");
      }
      members.set(event.member.publicKey.keyId, event.member);
      continue;
    }
    if (event.type === "migration-announced") {
      if (event.actorKeyId !== ownerKeyId) {
        throw new SyncKitError("authorization", "Only the control owner may announce a migration.");
      }
      if (migrations.has(event.migration.migrationId)) {
        throw new SyncKitError("conflict", `Migration ${event.migration.migrationId} was announced twice.`);
      }
      for (const requirement of event.migration.requiredAcks) {
        if (!members.has(requirement.keyId)) {
          throw new SyncKitError("authorization", `Migration ${event.migration.migrationId} requires an unknown member.`);
        }
      }
      migrations.set(event.migration.migrationId, event.migration);
      continue;
    }
    if (event.type === "migration-acknowledged") {
      const migration = migrations.get(event.migrationId);
      if (!migration) {
        throw new SyncKitError("state", `Acknowledgement references unknown migration ${event.migrationId}.`);
      }
      const requirement = migration.requiredAcks.find((candidate) => candidate.keyId === event.actorKeyId);
      if (!requirement) {
        throw new SyncKitError("authorization", "This member is not required to acknowledge the migration.");
      }
      if (closedMigrations.has(event.migrationId)) {
        throw new SyncKitError("state", "A closed migration cannot receive another acknowledgement.");
      }
      if (missingSharingControlPickerFiles(requirement, event.openedFileIds).length > 0) {
        throw new SyncKitError("state", "Migration acknowledgement omits one or more required Picker files.");
      }
      if (unexpectedPickerFiles(requirement, event.openedFileIds).length > 0) {
        throw new SyncKitError("state", "Migration acknowledgement includes an unexpected Picker file.");
      }
      const acknowledgementsForMigration = acknowledgements.get(event.migrationId) ??
        new Map<string, SharingControlMigrationAcknowledgedEventV1>();
      acknowledgementsForMigration.set(event.actorKeyId, event);
      acknowledgements.set(event.migrationId, acknowledgementsForMigration);
      continue;
    }
    const migration = migrations.get(event.migrationId);
    if (!migration) {
      throw new SyncKitError("state", `Close references unknown migration ${event.migrationId}.`);
    }
    if (event.actorKeyId !== ownerKeyId) {
      throw new SyncKitError("authorization", "Only the control owner may close a migration.");
    }
    const pending = migration.requiredAcks.filter(
      (requirement) => !acknowledgements.get(event.migrationId)?.has(requirement.keyId),
    );
    if (pending.length > 0 && !event.forced) {
      throw new SyncKitError("state", "A migration cannot close before every required acknowledgement arrives.");
    }
    closedMigrations.add(event.migrationId);
  }
  return { state, ownerKeyId, members, migrations, acknowledgements, closedMigrations };
}

export function missingSharingControlPickerFiles(
  requirement: SharingControlMigrationRequirementV1,
  openedFileIds: readonly string[],
): string[] {
  const opened = new Set(openedFileIds);
  return requirement.targetFileIds.filter((fileId) => !opened.has(fileId));
}

export class SharingControlDataset {
  constructor(private readonly options: SharingControlDatasetOptions) {
    nonEmpty(options.datasetId, "control datasetId");
    nonEmpty(options.profileId, "control profileId");
  }

  async create(owner: Omit<SharingControlMemberV1, "publicKey"> = {}): Promise<SharedDatasetResult<SharingControlStateV1>> {
    const identity = await this.options.identity();
    const event = await this.sign({
      type: "member-upsert",
      member: { publicKey: identity.publicKey, ...owner },
    }, identity, 0);
    return this.options.controller.createDataset(this.options.datasetId, {
      schemaVersion: 1,
      kind: SHARING_CONTROL_KIND,
      profileId: this.options.profileId,
      events: [event],
    });
  }

  async read(): Promise<VerifiedSharingControlStateV1> {
    const trust = await this.options.controller.getDatasetTrust(this.options.datasetId);
    const loaded = await this.options.controller.loadDataset(this.options.datasetId);
    return verifySharingControlStateV1(loaded.value, this.crypto(), trust);
  }

  addMember(member: SharingControlMemberV1): Promise<SharedDatasetResult<SharingControlStateV1>> {
    return this.publish(() => ({ type: "member-upsert", member }), identityMustBeOwner);
  }

  /**
   * Mirrors cryptographically accepted control-file participants into the
   * signed directory. Call this after accepting a join response; `metadata`
   * supplies the application-visible email/Drive details that envelopes do
   * not contain.
   */
  async synchronizeMembers(
    metadata: Record<string, Omit<SharingControlMemberV1, "publicKey">> = {},
  ): Promise<SharedDatasetResult<SharingControlStateV1> | null> {
    const verified = await this.read();
    const identity = await this.options.identity();
    identityMustBeOwner(verified, identity);
    const participants = await this.options.controller.getDatasetParticipants(this.options.datasetId);
    let last: SharedDatasetResult<SharingControlStateV1> | null = null;
    for (const participant of participants.participants) {
      const current = verified.members.get(participant.keyId);
      const details = metadata[participant.keyId] ?? {};
      const member: SharingControlMemberV1 = {
        publicKey: {
          keyId: participant.keyId,
          encryptionAlgorithm: participant.encryptionAlgorithm,
          encryptionPublicKey: participant.encryptionPublicKey,
          signatureAlgorithm: participant.signatureAlgorithm,
          signingPublicKey: participant.signingPublicKey,
        },
        ...details,
      };
      if (!current || canonicalJson(current) !== canonicalJson(member)) {
        last = await this.addMember(member);
      }
    }
    return last;
  }

  announceMigration(migration: SharingControlMigrationV1): Promise<SharedDatasetResult<SharingControlStateV1>> {
    return this.publish(() => ({ type: "migration-announced", migration }), identityMustBeOwner);
  }

  acknowledgeMigration(input: {
    migrationId: string;
    openedFileIds: string[];
  }): Promise<SharedDatasetResult<SharingControlStateV1>> {
    return this.publish(
      () => ({
        type: "migration-acknowledged",
        migrationId: input.migrationId,
        openedFileIds: [...new Set(input.openedFileIds)].sort(compareUtf16CodeUnits),
      }),
      (verified, identity) => {
        const migration = verified.migrations.get(input.migrationId);
        const requirement = migration?.requiredAcks.find((candidate) => candidate.keyId === identity.publicKey.keyId);
        if (!requirement) {
          throw new SyncKitError("authorization", "This identity is not required to acknowledge this migration.");
        }
        const missing = missingSharingControlPickerFiles(requirement, input.openedFileIds);
        if (missing.length > 0) {
          throw new SyncKitError("state", `Select every required migration file before acknowledging: ${missing.join(", ")}.`);
        }
        const unexpected = unexpectedPickerFiles(requirement, input.openedFileIds);
        if (unexpected.length > 0) {
          throw new SyncKitError("state", `Do not acknowledge unexpected Picker files: ${unexpected.join(", ")}.`);
        }
      },
    );
  }

  closeMigration(input: {
    migrationId: string;
    force?: boolean;
  }): Promise<SharedDatasetResult<SharingControlStateV1>> {
    return this.publish(
      () => ({ type: "migration-closed", migrationId: input.migrationId, ...(input.force ? { forced: true } : {}) }),
      (verified, identity) => {
        identityMustBeOwner(verified, identity);
        const migration = verified.migrations.get(input.migrationId);
        if (!migration) throw new SyncKitError("not-found", `Migration ${input.migrationId} was not found.`);
        if (!input.force) {
          const pending = migration.requiredAcks.filter(
            (requirement) => !verified.acknowledgements.get(input.migrationId)?.has(requirement.keyId),
          );
          if (pending.length > 0) {
            throw new SyncKitError("state", `Migration still awaits: ${pending.map((entry) => entry.keyId).join(", ")}.`);
          }
        }
      },
    );
  }

  async migrationStatus(migrationId: string): Promise<SharingControlMigrationStatusV1> {
    const verified = await this.read();
    const migration = verified.migrations.get(migrationId);
    if (!migration) throw new SyncKitError("not-found", `Migration ${migrationId} was not found.`);
    const acknowledgements = verified.acknowledgements.get(migrationId) ??
      new Map<string, SharingControlMigrationAcknowledgedEventV1>();
    const pendingKeyIds = migration.requiredAcks
      .filter((requirement) => !acknowledgements.has(requirement.keyId))
      .map((requirement) => requirement.keyId);
    return {
      migration,
      acknowledgedKeyIds: [...acknowledgements.keys()].sort(compareUtf16CodeUnits),
      pendingKeyIds,
      closed: verified.closedMigrations.has(migrationId),
    };
  }

  private async publish(
    build: (identity: WebCryptoSharingIdentity) => UnsignedSharingControlEventV1,
    authorize: (verified: VerifiedSharingControlStateV1, identity: WebCryptoSharingIdentity) => Promise<void> | void,
  ): Promise<SharedDatasetResult<SharingControlStateV1>> {
    const attempts = this.options.maxPublishAttempts ?? 3;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        const trust = await this.options.controller.getDatasetTrust(this.options.datasetId);
        const loaded = await this.options.controller.loadDataset(this.options.datasetId);
        const verified = await verifySharingControlStateV1(loaded.value, this.crypto(), trust);
        const identity = await this.options.identity();
        await authorize(verified, identity);
        const sequence = Math.max(...loaded.value.events.map((event) => event.sequence), -1) + 1;
        const event = await this.sign(build(identity), identity, sequence);
        return await this.options.controller.syncDataset(this.options.datasetId, {
          ...loaded.value,
          events: [...loaded.value.events, event],
        });
      } catch (error) {
        lastError = error;
        if (!(error instanceof SyncKitError) || error.code !== "conflict" || attempt + 1 >= attempts) throw error;
      }
    }
    throw lastError;
  }

  private async sign(
    event: UnsignedSharingControlEventV1,
    identity: WebCryptoSharingIdentity,
    sequence: number,
  ): Promise<SharingControlEventV1> {
    const unsigned = {
      schemaVersion: 1 as const,
      kind: SHARING_CONTROL_EVENT_KIND,
      eventId: this.randomUUID(),
      profileId: this.options.profileId,
      actorKeyId: identity.publicKey.keyId,
      sequence,
      createdAt: this.now().toISOString(),
      ...event,
    };
    const signature = new Uint8Array(
      await this.crypto().subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        identity.signingPrivateKey,
        copyBuffer(canonicalAad(unsigned)),
      ),
    );
    return parseSharingControlEventV1({ ...unsigned, signature: bytesToBase64Url(signature) });
  }

  private now(): Date {
    return (this.options.now ?? (() => new Date()))();
  }

  private randomUUID(): string {
    const value = this.options.randomUUID ?? globalThis.crypto?.randomUUID?.bind(globalThis.crypto);
    if (!value) throw new SyncKitError("configuration", "Secure UUID generation is unavailable.");
    return value();
  }

  private crypto(): Crypto {
    const value = this.options.crypto ?? globalThis.crypto;
    if (!value?.subtle) throw new SyncKitError("configuration", "WebCrypto is required for sharing control.");
    return value;
  }
}

export function createSharingControlDataset(options: SharingControlDatasetOptions): SharingControlDataset {
  return new SharingControlDataset(options);
}

function identityMustBeOwner(
  verified: VerifiedSharingControlStateV1,
  identity: WebCryptoSharingIdentity,
): void {
  if (verified.ownerKeyId !== identity.publicKey.keyId) {
    throw new SyncKitError("authorization", "Only the control owner may perform this operation.");
  }
}

async function verifyEvent(
  event: SharingControlEventV1,
  publicKey: SharingPublicKeyV1,
  cryptoImplementation: Crypto,
): Promise<void> {
  const expected = await createSharingPublicKeyV1(
    publicKey.encryptionPublicKey,
    publicKey.signingPublicKey,
    cryptoImplementation,
  );
  if (expected.keyId !== publicKey.keyId) {
    throw new SyncKitError("key", `Control member ${publicKey.keyId} has an invalid fingerprint.`);
  }
  const { signature, ...unsigned } = event;
  const signingKey = await cryptoImplementation.subtle.importKey(
    "raw",
    copyBuffer(base64UrlToBytes(publicKey.signingPublicKey)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const valid = await cryptoImplementation.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    signingKey,
    copyBuffer(base64UrlToBytes(signature)),
    copyBuffer(canonicalAad(unsigned)),
  );
  if (!valid) throw new SyncKitError("crypto", `Control event ${event.eventId} has an invalid signature.`);
}

function parseMember(value: unknown): SharingControlMemberV1 {
  const member = object(value, "control member");
  const publicKey = object(member.publicKey, "control member publicKey");
  for (const key of ["keyId", "encryptionAlgorithm", "encryptionPublicKey", "signatureAlgorithm", "signingPublicKey"] as const) {
    nonEmpty(publicKey[key], `control member publicKey ${key}`);
  }
  if (member.email !== undefined) nonEmpty(member.email, "control member email");
  if (member.googleSubject !== undefined) nonEmpty(member.googleSubject, "control member googleSubject");
  if (member.drivePermissionId !== undefined) nonEmpty(member.drivePermissionId, "control member drivePermissionId");
  return {
    publicKey: {
      keyId: publicKey.keyId as string,
      encryptionAlgorithm: publicKey.encryptionAlgorithm as SharingPublicKeyV1["encryptionAlgorithm"],
      encryptionPublicKey: publicKey.encryptionPublicKey as string,
      signatureAlgorithm: publicKey.signatureAlgorithm as SharingPublicKeyV1["signatureAlgorithm"],
      signingPublicKey: publicKey.signingPublicKey as string,
    },
    ...(member.email === undefined ? {} : { email: member.email }),
    ...(member.googleSubject === undefined ? {} : { googleSubject: member.googleSubject }),
    ...(member.drivePermissionId === undefined ? {} : { drivePermissionId: member.drivePermissionId }),
  };
}

function parseMigration(value: unknown): SharingControlMigrationV1 {
  const migration = object(value, "control migration");
  nonEmpty(migration.migrationId, "control migrationId");
  exact(migration.mode, "hard-cutover", "control migration mode");
  const sourceDatasetIds = stringArray(migration.sourceDatasetIds, "control sourceDatasetIds");
  const targets = array(migration.targets, "control targets").map((value) => {
    const target = object(value, "control migration target");
    nonEmpty(target.datasetId, "control target datasetId");
    nonEmpty(target.fileId, "control target fileId");
    if (target.revisionId !== undefined) nonEmpty(target.revisionId, "control target revisionId");
    return {
      datasetId: target.datasetId,
      fileId: target.fileId,
      ...(target.revisionId === undefined ? {} : { revisionId: target.revisionId }),
    };
  });
  const requiredAcks = array(migration.requiredAcks, "control requiredAcks").map((value) => {
    const requirement = object(value, "control acknowledgement requirement");
    nonEmpty(requirement.keyId, "control acknowledgement keyId");
    return { keyId: requirement.keyId, targetFileIds: stringArray(requirement.targetFileIds, "control acknowledgement targetFileIds") };
  });
  unique(sourceDatasetIds, "control source dataset");
  unique(targets.map((target) => target.fileId), "control target file");
  unique(requiredAcks.map((requirement) => requirement.keyId), "control acknowledgement member");
  return { migrationId: migration.migrationId, sourceDatasetIds, targets, requiredAcks, mode: "hard-cutover" };
}

function sortEvents(events: SharingControlEventV1[]): SharingControlEventV1[] {
  return [...events].sort((left, right) =>
    left.sequence === right.sequence
      ? compareUtf16CodeUnits(left.eventId, right.eventId)
      : left.sequence - right.sequence,
  );
}

function unexpectedPickerFiles(
  requirement: SharingControlMigrationRequirementV1,
  openedFileIds: readonly string[],
): string[] {
  const expected = new Set(requirement.targetFileIds);
  return openedFileIds.filter((fileId) => !expected.has(fileId));
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new SyncKitError("compatibility", `${name} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new SyncKitError("compatibility", `${name} must be an array.`);
  return value;
}

function stringArray(value: unknown, name: string): string[] {
  const values = array(value, name);
  const result = values.map((entry) => {
    nonEmpty(entry, name);
    return entry;
  });
  unique(result, name);
  return result.sort(compareUtf16CodeUnits);
}

function unique(values: string[], name: string): void {
  if (new Set(values).size !== values.length) {
    throw new SyncKitError("compatibility", `${name} contains duplicates.`);
  }
}

function nonEmpty(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !value.trim()) {
    throw new SyncKitError("compatibility", `${name} must be a non-empty string.`);
  }
}

function exact(value: unknown, expected: unknown, name: string): void {
  if (value !== expected) throw new SyncKitError("compatibility", `${name} is unsupported.`);
}

function validTime(value: string, name: string): void {
  if (Number.isNaN(Date.parse(value))) throw new SyncKitError("compatibility", `${name} must be an ISO timestamp.`);
}
