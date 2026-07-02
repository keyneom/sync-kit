import { SyncKitError, asSyncKitError } from "../core/errors.js";
import { base64UrlToBytes, bytesToBase64Url } from "../crypto/base64url.js";
import { canonicalAad, canonicalJson } from "../crypto/canonical.js";
import { copyBuffer } from "../crypto/runtime.js";
import {
  SHARED_BACKUP_KIND,
  SHARING_CONTENT_ALGORITHM,
  SHARING_ENCRYPTION_ALGORITHM,
  SHARING_INVITATION_KIND,
  SHARING_KEY_KIND,
  SHARING_SIGNATURE_ALGORITHM,
  canAdministerSharedBackup,
  canWriteSharedBackup,
  parseSharedBackupEnvelopeV1,
  parseSharingInvitationV1,
  parseSharingPublicKeyResponseV1,
  sharedBackupParticipant,
  sharedBackupParticipants,
  type SharedBackupCodec,
  type SharedBackupAccessV1,
  type SharedBackupEnvelopeV1,
  type SharedBackupParticipantV1,
  type SharingAcceptanceProvenanceV1,
  type SharingAccountBindingV1,
  type SharingDatasetGrantV1,
  type SharingPublicKeyResponseV1,
  type SharingPublicKeyV1,
  type SharingInvitationV1,
  type SharingRole,
} from "./index.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type WebCryptoSharingIdentity = {
  publicKey: SharingPublicKeyV1;
  encryptionPrivateKey: CryptoKey;
  signingPrivateKey: CryptoKey;
};

export type SharedBackupParticipantInput = {
  publicKey: SharingPublicKeyV1;
  role: SharingRole;
  accepted?: SharingAcceptanceProvenanceV1;
};

export type AcceptedSharingGrantV1 = {
  datasetId: string;
  participant: SharedBackupParticipantInput;
};

export type WebCryptoSharingOptions = {
  crypto?: Crypto;
  now?: () => Date;
  randomUUID?: () => string;
};

export async function createWebCryptoSharingIdentity(
  cryptoImplementation: Crypto = globalThis.crypto,
): Promise<WebCryptoSharingIdentity> {
  assertWebCrypto(cryptoImplementation);
  const encryption = await cryptoImplementation.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const signing = await cryptoImplementation.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  const encryptionPublicKey = bytesToBase64Url(
    new Uint8Array(
      await cryptoImplementation.subtle.exportKey("raw", encryption.publicKey),
    ),
  );
  const signingPublicKey = bytesToBase64Url(
    new Uint8Array(
      await cryptoImplementation.subtle.exportKey("raw", signing.publicKey),
    ),
  );
  const publicKey = await createSharingPublicKeyV1(
    encryptionPublicKey,
    signingPublicKey,
    cryptoImplementation,
  );
  return {
    publicKey,
    encryptionPrivateKey: encryption.privateKey,
    signingPrivateKey: signing.privateKey,
  };
}

export async function createSharingPublicKeyResponseV1(
  identity: WebCryptoSharingIdentity,
  input: {
    appId: string;
    exchangeId: string;
    createdAt?: string;
    accountBinding?: SharingAccountBindingV1;
  },
  options: WebCryptoSharingOptions = {},
): Promise<SharingPublicKeyResponseV1> {
  requireNonEmpty(input.appId, "appId");
  requireNonEmpty(input.exchangeId, "exchangeId");
  const cryptoImplementation = options.crypto ?? globalThis.crypto;
  assertWebCrypto(cryptoImplementation);
  await assertIdentity(identity, cryptoImplementation);
  const unsigned = {
    schemaVersion: 1 as const,
    kind: SHARING_KEY_KIND,
    appId: input.appId,
    exchangeId: input.exchangeId,
    createdAt: input.createdAt ?? now(options).toISOString(),
    ...(input.accountBinding ? { accountBinding: input.accountBinding } : {}),
    ...identity.publicKey,
  };
  return parseSharingPublicKeyResponseV1({
    ...unsigned,
    proof: bytesToBase64Url(
      new Uint8Array(
        await cryptoImplementation.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          identity.signingPrivateKey,
          copyBuffer(canonicalAad(unsigned)),
        ),
      ),
    ),
  });
}

export async function createSharingInvitationV1(
  identity: WebCryptoSharingIdentity,
  input: {
    appId: string;
    appFolderId: string;
    exchangeId?: string;
    recipientDrivePermissionId: string;
    requestedGrants: SharingDatasetGrantV1[];
    trustedOwnerKeyId?: string;
    createdAt?: string;
    expiresAt?: string;
  },
  options: WebCryptoSharingOptions = {},
): Promise<SharingInvitationV1> {
  for (const [name, value] of Object.entries({
    appId: input.appId,
    appFolderId: input.appFolderId,
    recipientDrivePermissionId: input.recipientDrivePermissionId,
  })) {
    requireNonEmpty(value, name);
  }
  const requestedGrants = normalizedRequestedGrants(input.requestedGrants);
  const cryptoImplementation = options.crypto ?? globalThis.crypto;
  assertWebCrypto(cryptoImplementation);
  await assertIdentity(identity, cryptoImplementation);
  const unsigned = {
    schemaVersion: 1 as const,
    kind: SHARING_INVITATION_KIND,
    appId: input.appId,
    appFolderId: input.appFolderId,
    exchangeId: input.exchangeId ?? randomUUID(options),
    recipientDrivePermissionId: input.recipientDrivePermissionId,
    requestedGrants,
    trustedOwnerKeyId:
      input.trustedOwnerKeyId ?? identity.publicKey.keyId,
    createdAt: input.createdAt ?? now(options).toISOString(),
    ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
    owner: identity.publicKey,
  };
  return parseSharingInvitationV1({
    ...unsigned,
    signature: bytesToBase64Url(
      new Uint8Array(
        await cryptoImplementation.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          identity.signingPrivateKey,
          copyBuffer(canonicalAad(unsigned)),
        ),
      ),
    ),
  });
}

export async function acceptSharingPublicKeyResponseV1(
  invitationInput: unknown,
  responseInput: unknown,
  input: {
    acceptedByKeyId: string;
    drivePermissionId: string;
    acceptedAt?: string;
    googleSubject?: string;
  },
  options: WebCryptoSharingOptions = {},
): Promise<AcceptedSharingGrantV1[]> {
  requireNonEmpty(input.acceptedByKeyId, "acceptedByKeyId");
  requireNonEmpty(input.drivePermissionId, "drivePermissionId");
  const cryptoImplementation = options.crypto ?? globalThis.crypto;
  const invitation = await verifySharingInvitationV1(invitationInput, {
    crypto: cryptoImplementation,
    ...(options.now ? { now: options.now } : {}),
  });
  const response = await verifySharingPublicKeyResponseV1(
    responseInput,
    cryptoImplementation,
  );
  if (
    response.appId !== invitation.appId ||
    response.exchangeId !== invitation.exchangeId
  ) {
    throw new SyncKitError(
      "authorization",
      "The public-key response does not match this invitation.",
    );
  }
  if (
    input.drivePermissionId !== invitation.recipientDrivePermissionId
  ) {
    throw new SyncKitError(
      "authorization",
      "The response Drive account does not match the invited account.",
    );
  }
  const accepted: SharingAcceptanceProvenanceV1 = {
    exchangeId: invitation.exchangeId,
    drivePermissionId: input.drivePermissionId,
    acceptedAt: input.acceptedAt ?? now(options).toISOString(),
    acceptedByKeyId: input.acceptedByKeyId,
    ...(input.googleSubject ? { googleSubject: input.googleSubject } : {}),
  };
  return invitation.requestedGrants.map((grant) => ({
    datasetId: grant.datasetId,
    participant: {
      publicKey: publicKeyFromResponse(response),
      role: grant.role,
      accepted,
    },
  }));
}

export async function verifySharingInvitationV1(
  input: unknown,
  options: {
    crypto?: Crypto;
    now?: () => Date;
  } = {},
): Promise<SharingInvitationV1> {
  const cryptoImplementation = options.crypto ?? globalThis.crypto;
  assertWebCrypto(cryptoImplementation);
  const invitation = parseSharingInvitationV1(input);
  const expectedOwner = await createSharingPublicKeyV1(
    invitation.owner.encryptionPublicKey,
    invitation.owner.signingPublicKey,
    cryptoImplementation,
  );
  if (expectedOwner.keyId !== invitation.owner.keyId) {
    throw new SyncKitError(
      "key",
      "The invitation owner fingerprint does not match its keys.",
    );
  }
  const { signature, ...unsigned } = invitation;
  const valid = await cryptoImplementation.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    await importSigningPublicKey(invitation.owner, cryptoImplementation),
    copyBuffer(base64UrlToBytes(signature)),
    copyBuffer(canonicalAad(unsigned)),
  );
  if (!valid) {
    throw new SyncKitError("crypto", "The sharing invitation signature is invalid.");
  }
  if (
    invitation.expiresAt &&
    Date.parse(invitation.expiresAt) <=
      (options.now?.() ?? new Date()).getTime()
  ) {
    throw new SyncKitError("authorization", "The sharing invitation has expired.");
  }
  return invitation;
}

export async function verifySharingPublicKeyResponseV1(
  input: unknown,
  cryptoImplementation: Crypto = globalThis.crypto,
): Promise<SharingPublicKeyResponseV1> {
  assertWebCrypto(cryptoImplementation);
  const response = parseSharingPublicKeyResponseV1(input);
  const expectedKey = await createSharingPublicKeyV1(
    response.encryptionPublicKey,
    response.signingPublicKey,
    cryptoImplementation,
  );
  if (expectedKey.keyId !== response.keyId) {
    throw new SyncKitError(
      "key",
      "The public-key response fingerprint does not match its keys.",
    );
  }
  const { proof, ...unsigned } = response;
  const valid = await cryptoImplementation.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    await importSigningPublicKey(response, cryptoImplementation),
    copyBuffer(base64UrlToBytes(proof)),
    copyBuffer(canonicalAad(unsigned)),
  );
  if (!valid) {
    throw new SyncKitError(
      "key",
      "The public-key response does not prove possession of its signing key.",
    );
  }
  return response;
}

export async function createSharedBackupEnvelopeV1<T>(
  value: T,
  codec: SharedBackupCodec<T>,
  identity: WebCryptoSharingIdentity,
  input: {
    appId: string;
    backupId: string;
    participants: SharedBackupParticipantInput[];
    previous?: SharedBackupEnvelopeV1;
    keyRotation?: {
      previousIdentity: WebCryptoSharingIdentity;
    };
    revisionId?: string;
    createdAt?: string;
  },
  options: WebCryptoSharingOptions = {},
): Promise<SharedBackupEnvelopeV1> {
  requireNonEmpty(input.appId, "appId");
  requireNonEmpty(input.backupId, "backupId");
  const cryptoImplementation = options.crypto ?? globalThis.crypto;
  assertWebCrypto(cryptoImplementation);
  await assertIdentity(identity, cryptoImplementation);
  if (input.keyRotation) {
    await assertIdentity(
      input.keyRotation.previousIdentity,
      cryptoImplementation,
    );
  }
  const participants = normalizedParticipants(input.participants);
  const author = participants.find(
    (participant) => participant.keyId === identity.publicKey.keyId,
  );
  if (!author || !canWriteSharedBackup(author.role)) {
    throw new SyncKitError(
      "authorization",
      "The author is not allowed to write this shared backup.",
    );
  }
  const previous = input.previous
    ? await verifySharedBackupEnvelopeV1(input.previous, cryptoImplementation)
    : undefined;
  await assertParticipantKeys(participants, cryptoImplementation);
  assertRevisionAuthority(
    input.appId,
    input.backupId,
    participants,
    identity.publicKey.keyId,
    previous,
    input.keyRotation?.previousIdentity.publicKey.keyId,
  );
  const accessControl = await createAccessControl(
    input.appId,
    input.backupId,
    participants,
    identity,
    previous,
    cryptoImplementation,
    input.keyRotation?.previousIdentity,
  );

  const revisionId = input.revisionId ?? randomUUID(options);
  const createdAt = input.createdAt ?? now(options).toISOString();
  requireNonEmpty(revisionId, "revisionId");
  const header = {
    schemaVersion: 1 as const,
    kind: SHARED_BACKUP_KIND,
    algorithm: SHARING_CONTENT_ALGORITHM,
    appId: input.appId,
    backupId: input.backupId,
    revisionId,
    ...(previous ? { parentRevisionId: previous.revisionId } : {}),
    ...(previous
      ? {
          revisionAncestors: [
            ...(previous.revisionAncestors ?? []),
            previous.revisionId,
          ],
        }
      : {}),
    createdAt,
    authorKeyId: identity.publicKey.keyId,
  };

  const rawContentKey = randomBytes(32, cryptoImplementation);
  try {
    const contentKey = await cryptoImplementation.subtle.importKey(
      "raw",
      copyBuffer(rawContentKey),
      "AES-GCM",
      false,
      ["encrypt", "decrypt"],
    );
    const payloadNonce = randomBytes(12, cryptoImplementation);
    let serialized: unknown;
    try {
      serialized = codec.serialize(value);
    } catch (error) {
      throw new SyncKitError(
        "serialization",
        "Shared-backup serialization failed.",
        { cause: error },
      );
    }
    const ciphertext = new Uint8Array(
      await cryptoImplementation.subtle.encrypt(
        aesGcm(payloadNonce, canonicalAad(header)),
        contentKey,
        copyBuffer(encoder.encode(JSON.stringify(serialized))),
      ),
    );
    const keyGrants = await Promise.all(
      participants.map((participant) =>
        createKeyGrant(
          rawContentKey,
          header,
          participant,
          cryptoImplementation,
        ),
      ),
    );
    const unsigned = {
      ...header,
      accessControl,
      keyGrants,
      payloadNonce: bytesToBase64Url(payloadNonce),
      ciphertext: bytesToBase64Url(ciphertext),
    };
    const signature = new Uint8Array(
      await cryptoImplementation.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        identity.signingPrivateKey,
        copyBuffer(canonicalAad(unsigned)),
      ),
    );
    return parseSharedBackupEnvelopeV1({
      ...unsigned,
      signature: bytesToBase64Url(signature),
    });
  } catch (error) {
    throw asSyncKitError(
      error,
      "crypto",
      "The shared backup could not be encrypted.",
    );
  } finally {
    rawContentKey.fill(0);
  }
}

export async function verifySharedBackupEnvelopeV1(
  input: unknown,
  cryptoImplementation: Crypto = globalThis.crypto,
  options: { trustedOwnerKeyId?: string } = {},
): Promise<SharedBackupEnvelopeV1> {
  assertWebCrypto(cryptoImplementation);
  const envelope = parseSharedBackupEnvelopeV1(input);
  const participants = await verifyAccessControl(
    envelope.accessControl,
    cryptoImplementation,
    options.trustedOwnerKeyId,
    envelope.appId,
    envelope.backupId,
  );
  const author = sharedBackupParticipant(envelope, envelope.authorKeyId);
  if (!author || !canWriteSharedBackup(author.role)) {
    throw new SyncKitError(
      "authorization",
      "The shared-backup author is not an authorized writer.",
    );
  }
  await assertParticipantKeys(participants, cryptoImplementation);
  const { signature, ...unsigned } = envelope;
  const valid = await cryptoImplementation.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    await importSigningPublicKey(author, cryptoImplementation),
    copyBuffer(base64UrlToBytes(signature)),
    copyBuffer(canonicalAad(unsigned)),
  );
  if (!valid) {
    throw new SyncKitError(
      "crypto",
      "The shared-backup signature is invalid.",
    );
  }
  return envelope;
}

export async function decryptSharedBackupEnvelopeV1<T>(
  input: unknown,
  codec: Pick<SharedBackupCodec<T>, "parse">,
  identity: WebCryptoSharingIdentity,
  cryptoImplementation: Crypto = globalThis.crypto,
  options: { trustedOwnerKeyId?: string } = {},
): Promise<T> {
  assertWebCrypto(cryptoImplementation);
  await assertIdentity(identity, cryptoImplementation);
  const envelope = await verifySharedBackupEnvelopeV1(
    input,
    cryptoImplementation,
    options,
  );
  const participant = sharedBackupParticipant(
    envelope,
    identity.publicKey.keyId,
  );
  if (!participant) {
    throw new SyncKitError(
      "authorization",
      "This identity is not a participant in the shared backup.",
    );
  }
  const grant = envelope.keyGrants.find(
    (candidate) => candidate.recipientKeyId === identity.publicKey.keyId,
  );
  if (!grant) {
    throw new SyncKitError("key", "No content-key grant exists for this identity.");
  }
  const header = sharedBackupHeader(envelope);
  let rawContentKey: Uint8Array;
  try {
    rawContentKey = await unwrapContentKey(
      grant,
      header,
      identity.encryptionPrivateKey,
      cryptoImplementation,
    );
  } catch (error) {
    throw asSyncKitError(
      error,
      "key",
      "This identity could not unwrap the shared-backup content key.",
    );
  }
  try {
    const contentKey = await cryptoImplementation.subtle.importKey(
      "raw",
      copyBuffer(rawContentKey),
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const plaintext = await cryptoImplementation.subtle.decrypt(
      aesGcm(
        base64UrlToBytes(envelope.payloadNonce),
        canonicalAad(header),
      ),
      contentKey,
      copyBuffer(base64UrlToBytes(envelope.ciphertext)),
    );
    try {
      return codec.parse(JSON.parse(decoder.decode(plaintext)));
    } catch (error) {
      throw new SyncKitError(
        "serialization",
        "The decrypted shared-backup payload is invalid.",
        { cause: error },
      );
    }
  } catch (error) {
    throw asSyncKitError(
      error,
      "crypto",
      "This identity could not decrypt the shared backup.",
    );
  } finally {
    rawContentKey.fill(0);
  }
}

export function sharingKeyFingerprint(keyId: string): string {
  const bytes = base64UrlToBytes(keyId);
  return Array.from(bytes.slice(0, 12), (byte) =>
    byte.toString(16).padStart(2, "0"),
  )
    .join("")
    .match(/.{1,4}/gu)
    ?.join("-") ?? "";
}

async function createKeyGrant(
  rawContentKey: Uint8Array,
  header: ReturnType<typeof sharedBackupHeader>,
  participant: SharedBackupParticipantV1,
  cryptoImplementation: Crypto,
) {
  const ephemeral = await cryptoImplementation.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const ephemeralPublicKey = bytesToBase64Url(
    new Uint8Array(
      await cryptoImplementation.subtle.exportKey("raw", ephemeral.publicKey),
    ),
  );
  const kdfSalt = randomBytes(32, cryptoImplementation);
  const nonce = randomBytes(12, cryptoImplementation);
  const grantHeader = {
    appId: header.appId,
    backupId: header.backupId,
    revisionId: header.revisionId,
    recipientKeyId: participant.keyId,
    ephemeralPublicKey,
    kdfSalt: bytesToBase64Url(kdfSalt),
    nonce: bytesToBase64Url(nonce),
  };
  const wrappingKey = await deriveWrappingKey(
    ephemeral.privateKey,
    await importEncryptionPublicKey(participant, cryptoImplementation),
    kdfSalt,
    grantHeader,
    cryptoImplementation,
  );
  const wrappedContentKey = await cryptoImplementation.subtle.encrypt(
    aesGcm(nonce, canonicalAad(grantHeader)),
    wrappingKey,
    copyBuffer(rawContentKey),
  );
  return {
    recipientKeyId: participant.keyId,
    ephemeralPublicKey,
    kdfSalt: bytesToBase64Url(kdfSalt),
    nonce: bytesToBase64Url(nonce),
    wrappedContentKey: bytesToBase64Url(new Uint8Array(wrappedContentKey)),
  };
}

async function unwrapContentKey(
  grant: SharedBackupEnvelopeV1["keyGrants"][number],
  header: ReturnType<typeof sharedBackupHeader>,
  privateKey: CryptoKey,
  cryptoImplementation: Crypto,
): Promise<Uint8Array> {
  const grantHeader = {
    appId: header.appId,
    backupId: header.backupId,
    revisionId: header.revisionId,
    recipientKeyId: grant.recipientKeyId,
    ephemeralPublicKey: grant.ephemeralPublicKey,
    kdfSalt: grant.kdfSalt,
    nonce: grant.nonce,
  };
  const wrappingKey = await deriveWrappingKey(
    privateKey,
    await importEcdhPublicKey(grant.ephemeralPublicKey, cryptoImplementation),
    base64UrlToBytes(grant.kdfSalt),
    grantHeader,
    cryptoImplementation,
  );
  return new Uint8Array(
    await cryptoImplementation.subtle.decrypt(
      aesGcm(
        base64UrlToBytes(grant.nonce),
        canonicalAad(grantHeader),
      ),
      wrappingKey,
      copyBuffer(base64UrlToBytes(grant.wrappedContentKey)),
    ),
  );
}

async function deriveWrappingKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  salt: Uint8Array,
  context: unknown,
  cryptoImplementation: Crypto,
): Promise<CryptoKey> {
  const secret = new Uint8Array(
    await cryptoImplementation.subtle.deriveBits(
      { name: "ECDH", public: publicKey },
      privateKey,
      256,
    ),
  );
  try {
    const material = await cryptoImplementation.subtle.importKey(
      "raw",
      copyBuffer(secret),
      "HKDF",
      false,
      ["deriveKey"],
    );
    return await cryptoImplementation.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: copyBuffer(salt),
        info: copyBuffer(
          encoder.encode(`sync-kit-sharing-v1:${canonicalJson(context)}`),
        ),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    secret.fill(0);
  }
}

export async function createSharingPublicKeyV1(
  encryptionPublicKey: string,
  signingPublicKey: string,
  cryptoImplementation: Crypto,
): Promise<SharingPublicKeyV1> {
  const digest = await cryptoImplementation.subtle.digest(
    "SHA-256",
    copyBuffer(
      canonicalAad({
        encryptionAlgorithm: SHARING_ENCRYPTION_ALGORITHM,
        encryptionPublicKey,
        signatureAlgorithm: SHARING_SIGNATURE_ALGORITHM,
        signingPublicKey,
      }),
    ),
  );
  return {
    keyId: bytesToBase64Url(new Uint8Array(digest)),
    encryptionAlgorithm: SHARING_ENCRYPTION_ALGORITHM,
    encryptionPublicKey,
    signatureAlgorithm: SHARING_SIGNATURE_ALGORITHM,
    signingPublicKey,
  };
}

async function assertIdentity(
  identity: WebCryptoSharingIdentity,
  cryptoImplementation: Crypto,
): Promise<void> {
  const expected = await createSharingPublicKeyV1(
    identity.publicKey.encryptionPublicKey,
    identity.publicKey.signingPublicKey,
    cryptoImplementation,
  );
  if (expected.keyId !== identity.publicKey.keyId) {
    throw new SyncKitError("key", "The sharing identity fingerprint is invalid.");
  }
}

async function assertParticipantKeys(
  participants: SharedBackupParticipantV1[],
  cryptoImplementation: Crypto,
): Promise<void> {
  for (const participant of participants) {
    const expected = await createSharingPublicKeyV1(
      participant.encryptionPublicKey,
      participant.signingPublicKey,
      cryptoImplementation,
    );
    if (expected.keyId !== participant.keyId) {
      throw new SyncKitError(
        "key",
        `Participant fingerprint ${participant.keyId} is invalid.`,
      );
    }
  }
}

async function createAccessControl(
  appId: string,
  backupId: string,
  participants: SharedBackupParticipantV1[],
  identity: WebCryptoSharingIdentity,
  previous: SharedBackupEnvelopeV1 | undefined,
  cryptoImplementation: Crypto,
  previousIdentity?: WebCryptoSharingIdentity,
): Promise<SharedBackupAccessV1[]> {
  if (
    previous &&
    canonicalJson(sharedBackupParticipants(previous)) ===
      canonicalJson(participants)
  ) {
    return previous.accessControl;
  }
  const priorEntry = previous?.accessControl.at(-1);
  const sequence = previous?.accessControl.length ?? 0;
  const previousHash = priorEntry
    ? await accessControlHash(priorEntry, cryptoImplementation)
    : undefined;
  const rotationUnsigned = previousIdentity
    ? {
        appId,
        backupId,
        sequence,
        ...(previousHash ? { previousHash } : {}),
        fromKeyId: previousIdentity.publicKey.keyId,
        toKeyId: identity.publicKey.keyId,
        participants,
      }
    : undefined;
  const keyRotation =
    previousIdentity && rotationUnsigned
      ? {
          fromKeyId: previousIdentity.publicKey.keyId,
          toKeyId: identity.publicKey.keyId,
          newKeyProof: bytesToBase64Url(
            new Uint8Array(
              await cryptoImplementation.subtle.sign(
                { name: "ECDSA", hash: "SHA-256" },
                identity.signingPrivateKey,
                copyBuffer(canonicalAad(rotationUnsigned)),
              ),
            ),
          ),
        }
      : undefined;
  const accessSigner = previousIdentity ?? identity;
  const unsigned = {
    appId,
    backupId,
    sequence,
    ...(previousHash ? { previousHash } : {}),
    authorKeyId: accessSigner.publicKey.keyId,
    participants,
    ...(keyRotation ? { keyRotation } : {}),
  };
  const entry: SharedBackupAccessV1 = {
    ...unsigned,
    signature: bytesToBase64Url(
      new Uint8Array(
        await cryptoImplementation.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          accessSigner.signingPrivateKey,
          copyBuffer(canonicalAad(unsigned)),
        ),
      ),
    ),
  };
  return [...(previous?.accessControl ?? []), entry];
}

async function verifyAccessControl(
  accessControl: SharedBackupAccessV1[],
  cryptoImplementation: Crypto,
  trustedOwnerKeyId?: string,
  appId?: string,
  backupId?: string,
): Promise<SharedBackupParticipantV1[]> {
  let previous: SharedBackupAccessV1 | undefined;
  let ownerKeyId: string | undefined;
  for (const entry of accessControl) {
    if (
      (entry.appId !== undefined || entry.backupId !== undefined) &&
      (entry.appId !== appId || entry.backupId !== backupId)
    ) {
      throw new SyncKitError(
        "authorization",
        "An access-control entry belongs to another dataset.",
      );
    }
    await assertParticipantKeys(entry.participants, cryptoImplementation);
    const owner = entry.participants.find(
      (participant) => participant.role === "owner",
    );
    if (!owner) {
      throw new SyncKitError(
        "authorization",
        "An access-control entry has no owner.",
      );
    }
    if (ownerKeyId === undefined) {
      ownerKeyId = owner.keyId;
      if (trustedOwnerKeyId && trustedOwnerKeyId !== ownerKeyId) {
        throw new SyncKitError(
          "authorization",
          "The shared backup does not match the trusted owner key.",
        );
      }
    }

    let author: SharedBackupParticipantV1 | undefined;
    let validRotation = false;
    if (previous) {
      const expectedHash = await accessControlHash(
        previous,
        cryptoImplementation,
      );
      if (entry.previousHash !== expectedHash) {
        throw new SyncKitError(
          "crypto",
          "The access-control history hash is invalid.",
        );
      }
      author = previous.participants.find(
        (participant) => participant.keyId === entry.authorKeyId,
      );
      validRotation = entry.keyRotation
        ? await verifyAccessKeyRotation(
            entry,
            previous,
            cryptoImplementation,
          )
        : false;
      if (
        !author ||
        (!canAdministerSharedBackup(author.role) && !validRotation)
      ) {
        throw new SyncKitError(
          "authorization",
          "An access-control change was not signed by a prior owner or admin.",
        );
      }
      if (owner.keyId !== ownerKeyId) {
        if (
          !validRotation ||
          entry.keyRotation?.fromKeyId !== ownerKeyId ||
          entry.keyRotation.toKeyId !== owner.keyId
        ) {
          throw new SyncKitError(
            "authorization",
            "Owner transfer is not supported by sharing v1.",
          );
        }
        ownerKeyId = owner.keyId;
      }
    } else {
      if (entry.keyRotation) {
        throw new SyncKitError(
          "authorization",
          "A genesis access entry cannot rotate a key.",
        );
      }
      author = entry.participants.find(
        (participant) => participant.keyId === entry.authorKeyId,
      );
      if (author?.role !== "owner") {
        throw new SyncKitError(
          "authorization",
          "The first access-control entry was not signed by its owner.",
        );
      }
    }
    const { signature, ...unsigned } = entry;
    const valid = await cryptoImplementation.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      await importSigningPublicKey(author, cryptoImplementation),
      copyBuffer(base64UrlToBytes(signature)),
      copyBuffer(canonicalAad(unsigned)),
    );
    if (!valid) {
      throw new SyncKitError(
        "crypto",
        "An access-control signature is invalid.",
      );
    }
    previous = entry;
  }
  const participants = previous?.participants;
  if (!participants) {
    throw new SyncKitError("compatibility", "Access-control history is empty.");
  }
  return participants;
}

async function verifyAccessKeyRotation(
  entry: SharedBackupAccessV1,
  previous: SharedBackupAccessV1,
  cryptoImplementation: Crypto,
): Promise<boolean> {
  const rotation = entry.keyRotation;
  if (
    !rotation ||
    !entry.appId ||
    !entry.backupId ||
    entry.authorKeyId !== rotation.fromKeyId
  ) {
    return false;
  }
  const from = previous.participants.find(
    (participant) => participant.keyId === rotation.fromKeyId,
  );
  const to = entry.participants.find(
    (participant) => participant.keyId === rotation.toKeyId,
  );
  if (
    !from ||
    !to ||
    !canWriteSharedBackup(from.role) ||
    from.role !== to.role ||
    canonicalJson(from.accepted ?? null) !== canonicalJson(to.accepted ?? null)
  ) {
    return false;
  }
  const expectedParticipants = previous.participants
    .map((participant) => (participant.keyId === from.keyId ? to : participant))
    .sort((left, right) => left.keyId.localeCompare(right.keyId));
  if (canonicalJson(expectedParticipants) !== canonicalJson(entry.participants)) {
    return false;
  }
  const proof = {
    appId: entry.appId,
    backupId: entry.backupId,
    sequence: entry.sequence,
    ...(entry.previousHash ? { previousHash: entry.previousHash } : {}),
    fromKeyId: rotation.fromKeyId,
    toKeyId: rotation.toKeyId,
    participants: entry.participants,
  };
  return cryptoImplementation.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    await importSigningPublicKey(to, cryptoImplementation),
    copyBuffer(base64UrlToBytes(rotation.newKeyProof)),
    copyBuffer(canonicalAad(proof)),
  );
}

async function accessControlHash(
  entry: SharedBackupAccessV1,
  cryptoImplementation: Crypto,
): Promise<string> {
  return bytesToBase64Url(
    new Uint8Array(
      await cryptoImplementation.subtle.digest(
        "SHA-256",
        copyBuffer(canonicalAad(entry)),
      ),
    ),
  );
}

function normalizedParticipants(
  input: SharedBackupParticipantInput[],
): SharedBackupParticipantV1[] {
  if (input.length === 0) {
    throw new SyncKitError("configuration", "participants must not be empty.");
  }
  const participants = input
    .map(({ publicKey, role, accepted }) => ({
      ...publicKey,
      role,
      ...(accepted ? { accepted } : {}),
    }))
    .sort((left, right) => left.keyId.localeCompare(right.keyId));
  const duplicate = participants.find(
    (participant, index) =>
      index > 0 && participants[index - 1]?.keyId === participant.keyId,
  );
  if (duplicate) {
    throw new SyncKitError(
      "configuration",
      `Duplicate participant ${duplicate.keyId}.`,
    );
  }
  if (participants.filter((participant) => participant.role === "owner").length !== 1) {
    throw new SyncKitError(
      "configuration",
      "A shared backup must have exactly one owner.",
    );
  }
  return participants;
}

function normalizedRequestedGrants(
  input: SharingDatasetGrantV1[],
): SharingDatasetGrantV1[] {
  if (input.length === 0) {
    throw new SyncKitError(
      "configuration",
      "requestedGrants must not be empty.",
    );
  }
  const grants = [...input].sort((left, right) =>
    left.datasetId.localeCompare(right.datasetId),
  );
  for (const [index, grant] of grants.entries()) {
    requireNonEmpty(grant.datasetId, "datasetId");
    if (index > 0 && grants[index - 1]?.datasetId === grant.datasetId) {
      throw new SyncKitError(
        "configuration",
        `Duplicate requested dataset ${grant.datasetId}.`,
      );
    }
  }
  return grants;
}

function publicKeyFromResponse(
  response: SharingPublicKeyResponseV1,
): SharingPublicKeyV1 {
  return {
    keyId: response.keyId,
    encryptionAlgorithm: response.encryptionAlgorithm,
    encryptionPublicKey: response.encryptionPublicKey,
    signatureAlgorithm: response.signatureAlgorithm,
    signingPublicKey: response.signingPublicKey,
  };
}

function assertRevisionAuthority(
  appId: string,
  backupId: string,
  participants: SharedBackupParticipantV1[],
  authorKeyId: string,
  previous: SharedBackupEnvelopeV1 | undefined,
  rotationFromKeyId?: string,
): void {
  if (!previous) {
    const owner = participants.find((participant) => participant.role === "owner");
    if (owner?.keyId !== authorKeyId) {
      throw new SyncKitError(
        "authorization",
        "Only the owner can create the first shared-backup revision.",
      );
    }
    return;
  }
  if (previous.appId !== appId || previous.backupId !== backupId) {
    throw new SyncKitError(
      "compatibility",
      "The previous revision belongs to a different shared backup.",
    );
  }
  const priorAuthor = sharedBackupParticipant(
    previous,
    rotationFromKeyId ?? authorKeyId,
  );
  if (!priorAuthor || !canWriteSharedBackup(priorAuthor.role)) {
    throw new SyncKitError(
      "authorization",
      "The previous revision does not authorize this writer.",
    );
  }
  const participantsChanged =
    canonicalJson(sharedBackupParticipants(previous)) !==
    canonicalJson(participants);
  if (
    participantsChanged &&
    !rotationFromKeyId &&
    !canAdministerSharedBackup(priorAuthor.role)
  ) {
    throw new SyncKitError(
      "authorization",
      "Only an owner or admin can change shared-backup participants.",
    );
  }
  const priorOwner = sharedBackupParticipants(previous).find(
    (participant) => participant.role === "owner",
  );
  const nextOwner = participants.find(
    (participant) => participant.role === "owner",
  );
  if (
    priorOwner?.keyId !== nextOwner?.keyId &&
    (rotationFromKeyId !== priorOwner?.keyId ||
      authorKeyId !== nextOwner?.keyId)
  ) {
    throw new SyncKitError(
      "authorization",
      "Owner transfer is not supported by sharing v1.",
    );
  }
  if (rotationFromKeyId) {
    const replacement = participants.find(
      (participant) => participant.keyId === authorKeyId,
    );
    const expected = sharedBackupParticipants(previous)
      .map((participant) =>
        participant.keyId === rotationFromKeyId
          ? replacement
          : participant,
      )
      .filter(
        (participant): participant is SharedBackupParticipantV1 =>
          participant !== undefined,
      )
      .sort((left, right) => left.keyId.localeCompare(right.keyId));
    if (
      replacement?.role !== priorAuthor.role ||
      canonicalJson(replacement?.accepted ?? null) !==
        canonicalJson(priorAuthor.accepted ?? null) ||
      canonicalJson(expected) !== canonicalJson(participants)
    ) {
      throw new SyncKitError(
        "authorization",
        "A key rotation may only replace the current writer's key.",
      );
    }
  }
}

function sharedBackupHeader(
  envelope: Pick<
    SharedBackupEnvelopeV1,
    | "schemaVersion"
    | "kind"
    | "algorithm"
    | "appId"
    | "backupId"
    | "revisionId"
    | "parentRevisionId"
    | "revisionAncestors"
    | "createdAt"
    | "authorKeyId"
  >,
) {
  return {
    schemaVersion: envelope.schemaVersion,
    kind: envelope.kind,
    algorithm: envelope.algorithm,
    appId: envelope.appId,
    backupId: envelope.backupId,
    revisionId: envelope.revisionId,
    ...(envelope.parentRevisionId
      ? { parentRevisionId: envelope.parentRevisionId }
      : {}),
    ...(envelope.revisionAncestors
      ? { revisionAncestors: envelope.revisionAncestors }
      : {}),
    createdAt: envelope.createdAt,
    authorKeyId: envelope.authorKeyId,
  };
}

function importEncryptionPublicKey(
  publicKey: Pick<SharingPublicKeyV1, "encryptionPublicKey">,
  cryptoImplementation: Crypto,
): Promise<CryptoKey> {
  return importEcdhPublicKey(publicKey.encryptionPublicKey, cryptoImplementation);
}

function importEcdhPublicKey(
  value: string,
  cryptoImplementation: Crypto,
): Promise<CryptoKey> {
  return cryptoImplementation.subtle.importKey(
    "raw",
    copyBuffer(base64UrlToBytes(value)),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

function importSigningPublicKey(
  publicKey: Pick<SharingPublicKeyV1, "signingPublicKey">,
  cryptoImplementation: Crypto,
): Promise<CryptoKey> {
  return cryptoImplementation.subtle.importKey(
    "raw",
    copyBuffer(base64UrlToBytes(publicKey.signingPublicKey)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

function aesGcm(nonce: Uint8Array, additionalData: Uint8Array): AesGcmParams {
  return {
    name: "AES-GCM",
    iv: copyBuffer(nonce),
    additionalData: copyBuffer(additionalData),
    tagLength: 128,
  };
}

function randomBytes(length: number, cryptoImplementation: Crypto): Uint8Array {
  return cryptoImplementation.getRandomValues(new Uint8Array(length));
}

function randomUUID(options: WebCryptoSharingOptions): string {
  const implementation =
    options.randomUUID ??
    (options.crypto ?? globalThis.crypto).randomUUID?.bind(
      options.crypto ?? globalThis.crypto,
    );
  if (!implementation) {
    throw new SyncKitError(
      "configuration",
      "Secure UUID generation is unavailable.",
    );
  }
  return implementation();
}

function now(options: WebCryptoSharingOptions): Date {
  return options.now?.() ?? new Date();
}

function requireNonEmpty(value: string, name: string): void {
  if (!value.trim()) throw new TypeError(`${name} must not be empty.`);
}

function assertWebCrypto(value: Crypto): void {
  if (!value?.subtle || !value.getRandomValues) {
    throw new SyncKitError(
      "configuration",
      "A WebCrypto implementation with P-256 support is required.",
    );
  }
}
