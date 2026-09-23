import type {
  CreatedKey,
  EnvelopeCrypto,
  SnapshotRecoveryCrypto,
  SyncCodec,
} from "../core/types.js";
import { SyncKitError, asSyncKitError } from "../core/errors.js";
import { base64UrlToBytes, bytesToBase64Url } from "./base64url.js";
import {
  newSnapshotMaterialV2,
  openPasskeyLockV2,
  openSnapshotMaterialV2,
  parseSyncEnvelopeV2,
  passkeyFields,
  passkeyLockV2,
  recoveryLockV2,
  sealSnapshotV2,
  snapshotLocksV2,
  unsealSnapshotV2,
  type SnapshotLocksV2,
  type SnapshotWrappedKeyV2,
  type SyncEnvelopeV2,
} from "./envelope-v2.js";
import type { CryptoBackend } from "./runtime.js";
import type { V1CompatibilityProfile } from "./profiles.js";
import { V1_ALGORITHM } from "./profiles.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * An encrypted private snapshot. `schemaVersion` 1 is the original format and
 * is unchanged. `schemaVersion` 2 adds an explicit `appId`, an authenticated
 * header, and a content key held by locks — the passkey and optionally a
 * recovery code — in the fields marked v2 below. It is read only by profiles
 * listing 2 in `readVersions`. The passkey fields sit in the same place in
 * both, so existing key providers unlock either. See docs/snapshot-recovery.md.
 */
export type SyncEnvelopeV1 = {
  schemaVersion: 1 | 2;
  algorithm: typeof V1_ALGORITHM;
  compression?: "gzip";
  credentialId: string;
  rpId: string;
  prfInput: string;
  kdfSalt: string;
  nonce: string;
  ciphertext: string;
  updatedAt: string;
  /** v2 only. */
  appId?: string;
  /** v2 only. */
  contentSalt?: string;
  /** v2 only: the content key, wrapped under the passkey's derived key. */
  passkeyKey?: SnapshotWrappedKeyV2;
  /** v2 only: the content key, wrapped under a recovery code. */
  recoveryKey?: SnapshotWrappedKeyV2 & { kdfSalt: string };
};

export type V1KeyMetadata = {
  credentialId: string;
  rpId: string;
  prfInput: Uint8Array;
  kdfSalt: Uint8Array;
  /** Present for a v2 snapshot, so ordinary sync keeps its locks unchanged. */
  locks?: SnapshotLocksV2;
};

export function parseSyncEnvelopeV1(
  value: unknown,
  profile: V1CompatibilityProfile,
): SyncEnvelopeV1 {
  let parsed: Partial<SyncEnvelopeV1>;
  try {
    parsed =
      typeof value === "string"
        ? (JSON.parse(value) as Partial<SyncEnvelopeV1>)
        : (value as Partial<SyncEnvelopeV1>);
  } catch (error) {
    throw new SyncKitError(
      "compatibility",
      `The ${profile.appId} snapshot is not valid JSON.`,
      { cause: error },
    );
  }
  if ((parsed as { schemaVersion?: unknown }).schemaVersion === 2) {
    return parseSyncEnvelopeV2(parsed, profile);
  }
  if (
    parsed?.schemaVersion !== 1 ||
    parsed.algorithm !== V1_ALGORITHM ||
    (parsed.compression !== undefined && parsed.compression !== "gzip") ||
    (profile.compression === "none" && parsed.compression !== undefined) ||
    !nonEmpty(parsed.credentialId) ||
    !nonEmpty(parsed.rpId) ||
    !nonEmpty(parsed.prfInput) ||
    !nonEmpty(parsed.kdfSalt) ||
    !nonEmpty(parsed.nonce) ||
    !nonEmpty(parsed.ciphertext) ||
    !nonEmpty(parsed.updatedAt)
  ) {
    throw new SyncKitError(
      "compatibility",
      `The file is not a supported ${profile.appId} v1 encrypted snapshot.`,
    );
  }
  validateEncodedLength(parsed.nonce, profile.nonceBytes, "nonce");
  validateEncodedLength(parsed.kdfSalt, profile.kdfSaltBytes, "KDF salt");
  validateEncodedLength(parsed.prfInput, profile.prfInputBytes, "PRF input");
  return parsed as SyncEnvelopeV1;
}

export async function deriveContentKey<K>(
  profile: V1CompatibilityProfile,
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  backend: CryptoBackend<K>,
): Promise<K> {
  return backend.deriveAesGcmKey(
    inputKeyMaterial,
    salt,
    encoder.encode(profile.hkdfInfo),
  );
}

/**
 * Encrypts `value`. An existing v2 snapshot (its locks in `metadata`) stays
 * v2 with the same locks; otherwise a new snapshot takes the profile's
 * `writeVersion`. An existing v1 snapshot is never upgraded here — only by
 * an explicit `setRecoveryCode` or `migrate`.
 */
export async function encryptSyncEnvelopeV1<T, K>(
  value: T,
  key: K,
  metadata: V1KeyMetadata,
  profile: V1CompatibilityProfile,
  codec: Pick<SyncCodec<T>, "serialize" | "updatedAt">,
  backend: CryptoBackend<K>,
  options: { nonce?: Uint8Array; now?: () => Date; version?: 1 | 2 } = {},
): Promise<SyncEnvelopeV1> {
  if (metadata.locks) {
    const material = await openPasskeyLockV2(metadata.locks, metadata, key, backend);
    try {
      return await sealSnapshotV2(value, material, metadata.locks, metadata, profile, codec, backend);
    } finally {
      material.fill(0);
    }
  }
  if ((options.version ?? profile.writeVersion) === 2) {
    const { material, contentSalt } = newSnapshotMaterialV2(backend);
    try {
      const locks: SnapshotLocksV2 = {
        appId: profile.appId,
        contentSalt,
        passkeyKey: await passkeyLockV2(profile.appId, key, metadata, contentSalt, material, backend),
      };
      return await sealSnapshotV2(value, material, locks, metadata, profile, codec, backend);
    } finally {
      material.fill(0);
    }
  }
  return encryptV1(value, key, metadata, profile, codec, backend, options);
}

async function encryptV1<T, K>(
  value: T,
  key: K,
  metadata: V1KeyMetadata,
  profile: V1CompatibilityProfile,
  codec: Pick<SyncCodec<T>, "serialize" | "updatedAt">,
  backend: CryptoBackend<K>,
  options: { nonce?: Uint8Array; now?: () => Date },
): Promise<SyncEnvelopeV1> {
  const nonce = options.nonce ?? backend.randomBytes(profile.nonceBytes);
  if (nonce.length !== profile.nonceBytes) {
    throw new SyncKitError("crypto", "AES-GCM nonce must be 12 bytes.");
  }
  let plaintext: Uint8Array;
  try {
    plaintext = encoder.encode(JSON.stringify(codec.serialize(value)));
  } catch (error) {
    throw new SyncKitError("serialization", "Snapshot serialization failed.", {
      cause: error,
    });
  }
  let compression: "gzip" | undefined;
  if (profile.compression === "gzip-if-smaller") {
    const compressed = await backend.gzip(plaintext);
    if (compressed.length < plaintext.length) {
      plaintext = compressed;
      compression = "gzip";
    }
  }
  const ciphertext = await backend.encryptAesGcm(
    key,
    nonce,
    encoder.encode(profile.aad),
    plaintext,
  );
  const updatedAt =
    codec.updatedAt?.(value) ??
    options.now?.().toISOString() ??
    new Date().toISOString();
  return {
    schemaVersion: 1,
    algorithm: V1_ALGORITHM,
    ...(compression ? { compression } : {}),
    credentialId: metadata.credentialId,
    rpId: metadata.rpId,
    prfInput: bytesToBase64Url(metadata.prfInput),
    kdfSalt: bytesToBase64Url(metadata.kdfSalt),
    nonce: bytesToBase64Url(nonce),
    ciphertext: bytesToBase64Url(ciphertext),
    updatedAt,
  };
}

export async function decryptSyncEnvelopeV1<T, K>(
  input: SyncEnvelopeV1,
  key: K,
  profile: V1CompatibilityProfile,
  codec: Pick<SyncCodec<T>, "parse">,
  backend: CryptoBackend<K>,
): Promise<T> {
  const envelope = parseSyncEnvelopeV1(input, profile);
  if (envelope.schemaVersion === 2) {
    const v2 = envelope as SyncEnvelopeV2;
    const material = await openSnapshotMaterialV2(v2, { key }, backend);
    try {
      return await unsealSnapshotV2(v2, material, profile, codec, backend);
    } finally {
      material.fill(0);
    }
  }
  try {
    let plaintext = await backend.decryptAesGcm(
      key,
      base64UrlToBytes(envelope.nonce),
      encoder.encode(profile.aad),
      base64UrlToBytes(envelope.ciphertext),
    );
    if (envelope.compression === "gzip") {
      plaintext = await backend.gunzip(plaintext);
    }
    return codec.parse(JSON.parse(decoder.decode(plaintext)));
  } catch (error) {
    throw asSyncKitError(
      error,
      "crypto",
      `The key could not decrypt the ${profile.appId} snapshot.`,
    );
  }
}

export function createV1EnvelopeCrypto<T, K>(
  profile: V1CompatibilityProfile,
  codec: SyncCodec<T>,
  backend: CryptoBackend<K>,
): EnvelopeCrypto<T, SyncEnvelopeV1, K, V1KeyMetadata> &
  SnapshotRecoveryCrypto<T, SyncEnvelopeV1, K, V1KeyMetadata> {
  const decrypt = (envelope: SyncEnvelopeV1, key: K): Promise<T> =>
    decryptSyncEnvelopeV1(envelope, key, profile, codec, backend);
  const requireV2Reads = (): void => {
    if (!profile.readVersions.includes(2)) {
      throw new SyncKitError(
        "configuration",
        `Snapshot recovery and v2 need 2 in the ${profile.appId} profile's readVersions.`,
      );
    }
  };
  const requireV2 = (envelope: SyncEnvelopeV1): SyncEnvelopeV2 => {
    const parsed = parseSyncEnvelopeV1(envelope, profile);
    if (parsed.schemaVersion !== 2) {
      throw new SyncKitError("key", `This ${profile.appId} snapshot has no recovery code.`);
    }
    return parsed as SyncEnvelopeV2;
  };
  /** Opens the snapshot's content key with the passkey, creating one for a v1 snapshot. */
  const materialAndLocks = async (
    envelope: SyncEnvelopeV1,
    key: K,
  ): Promise<{ material: Uint8Array; locks: SnapshotLocksV2 }> => {
    const parsed = parseSyncEnvelopeV1(envelope, profile);
    if (parsed.schemaVersion === 2) {
      const v2 = parsed as SyncEnvelopeV2;
      return {
        material: await openSnapshotMaterialV2(v2, { key }, backend),
        locks: snapshotLocksV2(v2),
      };
    }
    const { material, contentSalt } = newSnapshotMaterialV2(backend);
    return {
      material,
      locks: {
        appId: profile.appId,
        contentSalt,
        passkeyKey: await passkeyLockV2(
          profile.appId,
          key,
          passkeyFields(parsed),
          contentSalt,
          material,
          backend,
        ),
      },
    };
  };
  return {
    encrypt: (value, key, metadata) =>
      encryptSyncEnvelopeV1(value, key, metadata, profile, codec, backend),
    decrypt,
    metadataFromEnvelope: (envelope) => ({
      credentialId: envelope.credentialId,
      rpId: envelope.rpId,
      prfInput: base64UrlToBytes(envelope.prfInput),
      kdfSalt: base64UrlToBytes(envelope.kdfSalt),
      ...(envelope.schemaVersion === 2
        ? { locks: snapshotLocksV2(parseSyncEnvelopeV1(envelope, profile) as SyncEnvelopeV2) }
        : {}),
    }),
    async setRecoveryCode(envelope, key, recoveryCode) {
      requireV2Reads();
      const value = await decrypt(envelope, key);
      const { material, locks } = await materialAndLocks(envelope, key);
      try {
        const base: SnapshotLocksV2 = {
          appId: locks.appId,
          contentSalt: locks.contentSalt,
          passkeyKey: locks.passkeyKey,
        };
        const next: SnapshotLocksV2 = recoveryCode === null
          ? base
          : {
              ...base,
              recoveryKey: await recoveryLockV2(
                locks.appId,
                recoveryCode,
                locks.contentSalt,
                material,
                backend,
              ),
            };
        return await sealSnapshotV2(value, material, next, passkeyFields(envelope), profile, codec, backend);
      } finally {
        material.fill(0);
      }
    },
    async decryptWithRecoveryCode(envelope, recoveryCode) {
      requireV2Reads();
      const v2 = requireV2(envelope);
      const material = await openSnapshotMaterialV2(v2, { recoveryCode }, backend);
      try {
        return await unsealSnapshotV2(v2, material, profile, codec, backend);
      } finally {
        material.fill(0);
      }
    },
    async relockWithRecoveryCode(
      envelope,
      recoveryCode,
      replacement: CreatedKey<V1KeyMetadata, K>,
      value,
    ) {
      requireV2Reads();
      const v2 = requireV2(envelope);
      const material = await openSnapshotMaterialV2(v2, { recoveryCode }, backend);
      try {
        const locks: SnapshotLocksV2 = {
          ...snapshotLocksV2(v2),
          passkeyKey: await passkeyLockV2(
            v2.appId,
            replacement.key,
            replacement.metadata,
            v2.contentSalt,
            material,
            backend,
          ),
        };
        return await sealSnapshotV2(value, material, locks, replacement.metadata, profile, codec, backend);
      } finally {
        material.fill(0);
      }
    },
    async migrate(envelope, key, version) {
      const parsed = parseSyncEnvelopeV1(envelope, profile);
      if (parsed.schemaVersion === version) return parsed;
      const value = await decrypt(parsed, key);
      if (version === 1) {
        // The passkey-derived key is exactly the v1 content key.
        return encryptV1(value, key, passkeyFields(parsed), profile, codec, backend, {});
      }
      requireV2Reads();
      return encryptSyncEnvelopeV1(value, key, passkeyFields(parsed), profile, codec, backend, {
        version: 2,
      });
    },
  };
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function validateEncodedLength(
  value: string,
  expected: number,
  label: string,
): void {
  if (base64UrlToBytes(value).length !== expected) {
    throw new SyncKitError(
      "compatibility",
      `The v1 envelope ${label} has an invalid length.`,
    );
  }
}
