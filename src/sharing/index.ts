import { SyncKitError } from "../core/errors.js";
import { base64UrlToBytes } from "../crypto/base64url.js";

export const SHARING_KEY_KIND = "sync-kit-public-key" as const;
export const SHARING_INVITATION_KIND = "sync-kit-share-invitation" as const;
export const SHARED_BACKUP_KIND = "sync-kit-shared-backup" as const;
export const SHARING_ENCRYPTION_ALGORITHM = "ECDH-P256" as const;
export const SHARING_SIGNATURE_ALGORITHM =
  "ECDSA-P256-SHA256-P1363" as const;
export const SHARING_CONTENT_ALGORITHM =
  "AES-256-GCM+ECDH-P256+HKDF-SHA256" as const;
export const SHARED_BACKUP_MAX_REVISION_ANCESTORS = 256;

export type SharingRole = "owner" | "admin" | "writer" | "viewer";

export type SharingPublicKeyV1 = {
  keyId: string;
  encryptionAlgorithm: typeof SHARING_ENCRYPTION_ALGORITHM;
  encryptionPublicKey: string;
  signatureAlgorithm: typeof SHARING_SIGNATURE_ALGORITHM;
  signingPublicKey: string;
};

export type SharingPasskeyAssertionV1 = {
  credentialId: string;
  credentialPublicKey: JsonWebKey;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
};

export type SharingAccountBindingV1 = {
  schemaVersion: 1;
  kind: "sync-kit-sharing-account-binding";
  challenge: string;
  googleIdToken: string;
  passkey: SharingPasskeyAssertionV1;
};

export type SharingPublicKeyResponseV1 = SharingPublicKeyV1 & {
  schemaVersion: 1;
  kind: typeof SHARING_KEY_KIND;
  appId: string;
  exchangeId: string;
  createdAt: string;
  accountBinding?: SharingAccountBindingV1;
  proof: string;
};

export type SharingDatasetGrantV1 = {
  datasetId: string;
  role: Exclude<SharingRole, "owner">;
};

export type SharingInvitationV1 = {
  schemaVersion: 1;
  kind: typeof SHARING_INVITATION_KIND;
  appId: string;
  appFolderId: string;
  exchangeId: string;
  recipientDrivePermissionId: string;
  requestedGrants: SharingDatasetGrantV1[];
  trustedOwnerKeyId: string;
  createdAt: string;
  expiresAt?: string;
  owner: SharingPublicKeyV1;
  signature: string;
};

export type SharingAcceptanceProvenanceV1 = {
  exchangeId: string;
  drivePermissionId: string;
  acceptedAt: string;
  acceptedByKeyId: string;
  googleSubject?: string;
};

export type SharedBackupParticipantV1 = SharingPublicKeyV1 & {
  role: SharingRole;
  accepted?: SharingAcceptanceProvenanceV1;
};

export type SharedBackupAccessV1 = {
  sequence: number;
  appId?: string;
  backupId?: string;
  previousHash?: string;
  authorKeyId: string;
  participants: SharedBackupParticipantV1[];
  keyRotation?: {
    fromKeyId: string;
    toKeyId: string;
    newKeyProof: string;
  };
  signature: string;
};

export type SharedBackupKeyGrantV1 = {
  recipientKeyId: string;
  ephemeralPublicKey: string;
  kdfSalt: string;
  nonce: string;
  wrappedContentKey: string;
};

export type SharedBackupEnvelopeV1 = {
  schemaVersion: 1;
  kind: typeof SHARED_BACKUP_KIND;
  algorithm: typeof SHARING_CONTENT_ALGORITHM;
  appId: string;
  backupId: string;
  revisionId: string;
  parentRevisionId?: string;
  revisionAncestors?: string[];
  createdAt: string;
  authorKeyId: string;
  accessControl: SharedBackupAccessV1[];
  keyGrants: SharedBackupKeyGrantV1[];
  payloadNonce: string;
  ciphertext: string;
  signature: string;
};

export type SharedBackupCodec<T> = {
  serialize(value: T): unknown;
  parse(value: unknown): T;
};

export function canReadSharedBackup(role: SharingRole): boolean {
  return role === "owner" || role === "admin" || role === "writer" || role === "viewer";
}

export function canWriteSharedBackup(role: SharingRole): boolean {
  return role === "owner" || role === "admin" || role === "writer";
}

export function canAdministerSharedBackup(role: SharingRole): boolean {
  return role === "owner" || role === "admin";
}

export function parseSharingPublicKeyResponseV1(
  value: unknown,
): SharingPublicKeyResponseV1 {
  const parsed = parseObject(value, "public-key response");
  assertExact(parsed.schemaVersion, 1, "schemaVersion");
  assertExact(parsed.kind, SHARING_KEY_KIND, "kind");
  assertNonEmptyStrings(parsed, [
    "appId",
    "exchangeId",
    "createdAt",
    "keyId",
    "encryptionPublicKey",
    "signingPublicKey",
    "proof",
  ]);
  assertExact(
    parsed.encryptionAlgorithm,
    SHARING_ENCRYPTION_ALGORITHM,
    "encryptionAlgorithm",
  );
  assertExact(
    parsed.signatureAlgorithm,
    SHARING_SIGNATURE_ALGORITHM,
    "signatureAlgorithm",
  );
  validatePublicKey(parsed.encryptionPublicKey as string, "encryptionPublicKey");
  validatePublicKey(parsed.signingPublicKey as string, "signingPublicKey");
  validateBytes(parsed.keyId as string, 32, "keyId");
  validateBytes(parsed.proof as string, 64, "proof");
  validateTimestamp(parsed.createdAt as string, "createdAt");
  if (parsed.accountBinding !== undefined) {
    parseSharingAccountBinding(parsed.accountBinding);
  }
  return parsed as SharingPublicKeyResponseV1;
}

export function parseSharingInvitationV1(value: unknown): SharingInvitationV1 {
  const parsed = parseObject(value, "sharing invitation");
  assertExact(parsed.schemaVersion, 1, "schemaVersion");
  assertExact(parsed.kind, SHARING_INVITATION_KIND, "kind");
  assertNonEmptyStrings(parsed, [
    "appId",
    "appFolderId",
    "exchangeId",
    "recipientDrivePermissionId",
    "trustedOwnerKeyId",
    "createdAt",
    "signature",
  ]);
  validateBytes(
    parsed.trustedOwnerKeyId as string,
    32,
    "trustedOwnerKeyId",
  );
  if (parsed.expiresAt !== undefined && !nonEmpty(parsed.expiresAt)) {
    throw compatibility("expiresAt must be a non-empty string.");
  }
  if (
    !Array.isArray(parsed.requestedGrants) ||
    parsed.requestedGrants.length === 0
  ) {
    throw compatibility("requestedGrants must not be empty.");
  }
  const datasetIds = new Set<string>();
  for (const input of parsed.requestedGrants) {
    const grant = parseObject(input, "requested dataset grant");
    assertNonEmptyStrings(grant, ["datasetId", "role"]);
    if (!isRole(grant.role) || grant.role === "owner") {
      throw compatibility("An invitation has an unsupported requested role.");
    }
    const datasetId = grant.datasetId as string;
    if (datasetIds.has(datasetId)) {
      throw compatibility(`Duplicate requested dataset ${datasetId}.`);
    }
    datasetIds.add(datasetId);
  }
  const owner = parseObject(parsed.owner, "invitation owner");
  assertNonEmptyStrings(owner, [
    "keyId",
    "encryptionPublicKey",
    "signingPublicKey",
  ]);
  assertExact(
    owner.encryptionAlgorithm,
    SHARING_ENCRYPTION_ALGORITHM,
    "encryptionAlgorithm",
  );
  assertExact(
    owner.signatureAlgorithm,
    SHARING_SIGNATURE_ALGORITHM,
    "signatureAlgorithm",
  );
  validatePublicKey(owner.encryptionPublicKey as string, "encryptionPublicKey");
  validatePublicKey(owner.signingPublicKey as string, "signingPublicKey");
  validateBytes(owner.keyId as string, 32, "owner keyId");
  validateBytes(parsed.signature as string, 64, "signature");
  validateTimestamp(parsed.createdAt as string, "createdAt");
  if (parsed.expiresAt) {
    validateTimestamp(parsed.expiresAt, "expiresAt");
  }
  return parsed as SharingInvitationV1;
}

export function parseSharedBackupEnvelopeV1(
  value: unknown,
): SharedBackupEnvelopeV1 {
  const parsed = parseObject(value, "shared-backup envelope");
  assertExact(parsed.schemaVersion, 1, "schemaVersion");
  assertExact(parsed.kind, SHARED_BACKUP_KIND, "kind");
  assertExact(parsed.algorithm, SHARING_CONTENT_ALGORITHM, "algorithm");
  assertNonEmptyStrings(parsed, [
    "appId",
    "backupId",
    "revisionId",
    "createdAt",
    "authorKeyId",
    "payloadNonce",
    "ciphertext",
    "signature",
  ]);
  if (
    parsed.parentRevisionId !== undefined &&
    !nonEmpty(parsed.parentRevisionId)
  ) {
    throw compatibility("parentRevisionId must be a non-empty string.");
  }
  if (parsed.revisionAncestors !== undefined) {
    if (
      !Array.isArray(parsed.revisionAncestors) ||
      !parsed.revisionAncestors.every(nonEmpty)
    ) {
      throw compatibility("revisionAncestors must contain revision IDs.");
    }
    const ancestors = parsed.revisionAncestors;
    if (ancestors.length > SHARED_BACKUP_MAX_REVISION_ANCESTORS) {
      throw compatibility(
        `revisionAncestors must contain at most ${SHARED_BACKUP_MAX_REVISION_ANCESTORS} revision IDs.`,
      );
    }
    if (
      new Set(ancestors).size !== ancestors.length ||
      ancestors.includes(parsed.revisionId as string)
    ) {
      throw compatibility("revisionAncestors contains a duplicate or cycle.");
    }
    if (
      parsed.parentRevisionId &&
      ancestors.at(-1) !== parsed.parentRevisionId
    ) {
      throw compatibility(
        "parentRevisionId must be the last revision ancestor.",
      );
    }
    if (!parsed.parentRevisionId && ancestors.length > 0) {
      throw compatibility("A genesis revision cannot have ancestors.");
    }
  }
  if (!Array.isArray(parsed.accessControl) || parsed.accessControl.length === 0) {
    throw compatibility("accessControl must not be empty.");
  }
  if (!Array.isArray(parsed.keyGrants) || parsed.keyGrants.length === 0) {
    throw compatibility("keyGrants must not be empty.");
  }

  for (const [index, input] of parsed.accessControl.entries()) {
    parseAccessEntry(input, index);
  }
  const accessControl = parsed.accessControl as SharedBackupAccessV1[];
  const participants = accessControl.at(-1)?.participants;
  if (!participants) throw compatibility("accessControl must not be empty.");
  const participantIds = new Set(
    participants.map((participant) => participant.keyId),
  );
  if (!participantIds.has(parsed.authorKeyId as string)) {
    throw compatibility("The revision author is not a participant.");
  }

  const grantIds = new Set<string>();
  for (const input of parsed.keyGrants) {
    const grant = parseObject(input, "key grant");
    assertNonEmptyStrings(grant, [
      "recipientKeyId",
      "ephemeralPublicKey",
      "kdfSalt",
      "nonce",
      "wrappedContentKey",
    ]);
    const recipientKeyId = grant.recipientKeyId as string;
    if (!participantIds.has(recipientKeyId)) {
      throw compatibility("A key grant references a non-participant.");
    }
    if (grantIds.has(recipientKeyId)) {
      throw compatibility(`Duplicate key grant for ${recipientKeyId}.`);
    }
    grantIds.add(recipientKeyId);
    validatePublicKey(
      grant.ephemeralPublicKey as string,
      "ephemeralPublicKey",
    );
    validateBytes(grant.kdfSalt as string, 32, "kdfSalt");
    validateBytes(grant.nonce as string, 12, "key-grant nonce");
    base64UrlToBytes(grant.wrappedContentKey as string);
  }
  if (grantIds.size !== participantIds.size) {
    throw compatibility("Every participant must have exactly one key grant.");
  }
  validateBytes(parsed.payloadNonce as string, 12, "payload nonce");
  base64UrlToBytes(parsed.ciphertext as string);
  validateBytes(parsed.signature as string, 64, "signature");
  validateTimestamp(parsed.createdAt as string, "createdAt");
  return parsed as SharedBackupEnvelopeV1;
}

export function sharedBackupParticipants(
  envelope: SharedBackupEnvelopeV1,
): SharedBackupParticipantV1[] {
  const participants = envelope.accessControl.at(-1)?.participants;
  if (!participants) {
    throw compatibility("accessControl must not be empty.");
  }
  return participants;
}

export function sharedBackupParticipant(
  envelope: SharedBackupEnvelopeV1,
  keyId: string,
): SharedBackupParticipantV1 | null {
  return sharedBackupParticipants(envelope).find(
    (participant) => participant.keyId === keyId,
  ) ?? null;
}

function parseAccessEntry(input: unknown, index: number): void {
  const entry = parseObject(input, "access-control entry");
  if (!Number.isSafeInteger(entry.sequence) || entry.sequence !== index) {
    throw compatibility("Access-control sequence is invalid.");
  }
  assertNonEmptyStrings(entry, ["authorKeyId", "signature"]);
  if (entry.appId !== undefined || entry.backupId !== undefined) {
    assertNonEmptyStrings(entry, ["appId", "backupId"]);
  }
  validateBytes(entry.authorKeyId as string, 32, "access author keyId");
  validateBytes(entry.signature as string, 64, "access signature");
  if (index === 0) {
    if (entry.previousHash !== undefined) {
      throw compatibility("The first access-control entry cannot have a previousHash.");
    }
  } else {
    if (!nonEmpty(entry.previousHash)) {
      throw compatibility("An access-control entry is missing previousHash.");
    }
    validateBytes(entry.previousHash, 32, "access previousHash");
  }
  if (!Array.isArray(entry.participants) || entry.participants.length === 0) {
    throw compatibility("Access-control participants must not be empty.");
  }
  const participantIds = new Set<string>();
  let ownerCount = 0;
  for (const inputParticipant of entry.participants) {
    const participant = parseObject(inputParticipant, "participant");
    assertNonEmptyStrings(participant, [
      "keyId",
      "encryptionPublicKey",
      "signingPublicKey",
      "role",
    ]);
    assertExact(
      participant.encryptionAlgorithm,
      SHARING_ENCRYPTION_ALGORITHM,
      "encryptionAlgorithm",
    );
    assertExact(
      participant.signatureAlgorithm,
      SHARING_SIGNATURE_ALGORITHM,
      "signatureAlgorithm",
    );
    if (!isRole(participant.role)) {
      throw compatibility("A participant has an unsupported role.");
    }
    if (participant.accepted !== undefined) {
      parseAcceptanceProvenance(participant.accepted);
    }
    validatePublicKey(
      participant.encryptionPublicKey as string,
      "encryptionPublicKey",
    );
    validatePublicKey(
      participant.signingPublicKey as string,
      "signingPublicKey",
    );
    const keyId = participant.keyId as string;
    validateBytes(keyId, 32, "participant keyId");
    if (participantIds.has(keyId)) {
      throw compatibility(`Duplicate participant ${keyId}.`);
    }
    participantIds.add(keyId);
    if (participant.role === "owner") ownerCount += 1;
  }
  if (ownerCount !== 1) {
    throw compatibility("An access-control entry must have exactly one owner.");
  }
  if (entry.keyRotation !== undefined) {
    const rotation = parseObject(entry.keyRotation, "key rotation");
    assertNonEmptyStrings(rotation, [
      "fromKeyId",
      "toKeyId",
      "newKeyProof",
    ]);
    validateBytes(rotation.fromKeyId as string, 32, "rotation fromKeyId");
    validateBytes(rotation.toKeyId as string, 32, "rotation toKeyId");
    validateBytes(rotation.newKeyProof as string, 64, "rotation proof");
    if (rotation.fromKeyId === rotation.toKeyId) {
      throw compatibility("A key rotation must change the key ID.");
    }
  }
}

function parseAcceptanceProvenance(input: unknown): void {
  const accepted = parseObject(input, "participant acceptance provenance");
  assertNonEmptyStrings(accepted, [
    "exchangeId",
    "drivePermissionId",
    "acceptedAt",
    "acceptedByKeyId",
  ]);
  if (
    accepted.googleSubject !== undefined &&
    !nonEmpty(accepted.googleSubject)
  ) {
    throw compatibility("googleSubject must be a non-empty string.");
  }
  validateBytes(
    accepted.acceptedByKeyId as string,
    32,
    "acceptedByKeyId",
  );
  validateTimestamp(accepted.acceptedAt as string, "acceptedAt");
}

function parseSharingAccountBinding(input: unknown): void {
  const binding = parseObject(input, "sharing account binding");
  assertExact(binding.schemaVersion, 1, "account binding schemaVersion");
  assertExact(
    binding.kind,
    "sync-kit-sharing-account-binding",
    "account binding kind",
  );
  assertNonEmptyStrings(binding, ["challenge", "googleIdToken"]);
  validateBytes(binding.challenge as string, 32, "account binding challenge");
  const passkey = parseObject(binding.passkey, "passkey assertion");
  assertNonEmptyStrings(passkey, [
    "credentialId",
    "authenticatorData",
    "clientDataJSON",
    "signature",
  ]);
  base64UrlToBytes(passkey.credentialId as string);
  base64UrlToBytes(passkey.authenticatorData as string);
  base64UrlToBytes(passkey.clientDataJSON as string);
  base64UrlToBytes(passkey.signature as string);
  if (
    !passkey.credentialPublicKey ||
    typeof passkey.credentialPublicKey !== "object" ||
    Array.isArray(passkey.credentialPublicKey)
  ) {
    throw compatibility("credentialPublicKey must be a JWK object.");
  }
}

function parseObject(value: unknown, label: string): Record<string, unknown> {
  let parsed = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value) as unknown;
    } catch (error) {
      throw new SyncKitError(
        "compatibility",
        `The ${label} is not valid JSON.`,
        { cause: error },
      );
    }
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw compatibility(`The ${label} must be an object.`);
  }
  return parsed as Record<string, unknown>;
}

function assertNonEmptyStrings(
  value: Record<string, unknown>,
  fields: string[],
): void {
  for (const field of fields) {
    if (!nonEmpty(value[field])) {
      throw compatibility(`${field} must be a non-empty string.`);
    }
  }
}

function assertExact(value: unknown, expected: unknown, field: string): void {
  if (value !== expected) {
    throw compatibility(`${field} is not supported.`);
  }
}

function validatePublicKey(value: string, field: string): void {
  validateBytes(value, 65, field);
  if (base64UrlToBytes(value)[0] !== 4) {
    throw compatibility(`${field} is not an uncompressed P-256 public key.`);
  }
}

function validateBytes(value: string, length: number, field: string): void {
  if (base64UrlToBytes(value).length !== length) {
    throw compatibility(`${field} has an invalid length.`);
  }
}

function validateTimestamp(value: string, field: string): void {
  if (!Number.isFinite(Date.parse(value))) {
    throw compatibility(`${field} is not a valid timestamp.`);
  }
}

function isRole(value: unknown): value is SharingRole {
  return (
    value === "owner" ||
    value === "admin" ||
    value === "writer" ||
    value === "viewer"
  );
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function compatibility(message: string): SyncKitError {
  return new SyncKitError("compatibility", message);
}

export type {
  SharedDatasetHead,
  SharingChangeDetectionResult,
  SharingNotificationEvent,
  SharingSyncCheckpoint,
} from "./checkpoint.js";
export {
  SharingChangeDetector,
  createSharingChangeDetectorFromTransport,
  detectSharingChanges,
} from "./change-detector.js";
export type {
  SharedBackupStorage,
  SharedBackupTransport,
  SharedDatasetFile,
  SharedDatasetDrivePermission,
  SharedDatasetPermission,
  SharedExchangeFile,
  SharedKeyResponseFile,
  VersionedSharedDataset,
} from "./transport.js";
export {
  appendSharingJoinParams,
  buildSharingJoinSearchParams,
  findSharingJoinInvitation,
  formatSharingInviteEmailMessage,
  parseSharingJoinParams,
  resolveSharingJoinInvitation,
  SHARING_JOIN_EXCHANGE_PARAM,
  SHARING_JOIN_FOLDER_PARAM,
  SHARING_JOIN_MARKER_PARAM,
  SHARING_JOIN_SHORT_EXCHANGE_PARAM,
  SHARING_JOIN_SHORT_FOLDER_PARAM,
  SHARING_JOIN_SHORT_MARKER_PARAM,
  SHARING_JOIN_SHORT_MARKER_VALUE,
  type SharingJoinInvitationMatch,
  type SharingJoinParamStyle,
  type SharingJoinParams,
} from "./join.js";
