// Snapshot envelope v2: an explicit appId, a canonical authenticated header,
// and a random content key held by one or more locks — the passkey, and
// optionally a recovery code. See docs/snapshot-recovery.md.
//
// v1 is untouched. v2 is written only when a profile opts in (writeVersion 2,
// or an explicit recovery / migration call) and read only when a profile lists
// 2 in readVersions; ordinary sync keeps whichever version a snapshot has.
import { SyncKitError, asSyncKitError } from "../core/errors.js";
import type { SyncCodec } from "../core/types.js";
import { base64UrlToBytes, bytesToBase64Url } from "./base64url.js";
import { canonicalAad } from "./canonical.js";
import type { V1CompatibilityProfile } from "./profiles.js";
import { V1_ALGORITHM } from "./profiles.js";
import { parseRecoveryCode } from "./recovery-code.js";
import type { CryptoBackend } from "./runtime.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const CONTENT_KEY_INFO = encoder.encode("sync-kit snapshot content key v2");
const RECOVERY_KEY_INFO = encoder.encode("sync-kit snapshot recovery key v2");
const MATERIAL_BYTES = 32;

/** The content key, wrapped under one lock. */
export type SnapshotWrappedKeyV2 = { nonce: string; wrappedKey: string };

/** The locks a v2 snapshot carries, preserved unchanged by ordinary sync. */
export type SnapshotLocksV2 = {
  appId: string;
  contentSalt: string;
  passkeyKey: SnapshotWrappedKeyV2;
  recoveryKey?: SnapshotWrappedKeyV2 & { kdfSalt: string };
};

/** The passkey fields every snapshot carries, v1 or v2. */
export type SnapshotPasskeyFields = {
  credentialId: string;
  rpId: string;
  prfInput: Uint8Array;
  kdfSalt: Uint8Array;
};

export type SyncEnvelopeV2 = {
  schemaVersion: 2;
  appId: string;
  algorithm: typeof V1_ALGORITHM;
  compression?: "gzip";
  credentialId: string;
  rpId: string;
  prfInput: string;
  kdfSalt: string;
  contentSalt: string;
  passkeyKey: SnapshotWrappedKeyV2;
  recoveryKey?: SnapshotWrappedKeyV2 & { kdfSalt: string };
  nonce: string;
  ciphertext: string;
  updatedAt: string;
};

/** How to open a v2 snapshot: the passkey's derived key, or a recovery code. */
export type SnapshotOpener<K> = { key: K } | { recoveryCode: string };

export function parseSyncEnvelopeV2(
  value: Record<string, unknown>,
  profile: V1CompatibilityProfile,
): SyncEnvelopeV2 {
  if (!profile.readVersions.includes(2)) {
    throw new SyncKitError(
      "compatibility",
      `This ${profile.appId} snapshot is version 2; add 2 to the profile's readVersions to read it.`,
    );
  }
  const fail = (): never => {
    throw new SyncKitError(
      "compatibility",
      `The file is not a supported ${profile.appId} v2 encrypted snapshot.`,
    );
  };
  const strings = [
    "appId", "credentialId", "rpId", "prfInput", "kdfSalt", "contentSalt",
    "nonce", "ciphertext", "updatedAt",
  ];
  if (
    value.algorithm !== V1_ALGORITHM ||
    strings.some((field) => !nonEmpty(value[field])) ||
    (value.compression !== undefined && value.compression !== "gzip") ||
    (profile.compression === "none" && value.compression !== undefined) ||
    !wrappedKey(value.passkeyKey) ||
    (value.recoveryKey !== undefined &&
      (!wrappedKey(value.recoveryKey) ||
        !nonEmpty((value.recoveryKey as Record<string, unknown>).kdfSalt)))
  ) {
    fail();
  }
  if (value.appId !== profile.appId) {
    throw new SyncKitError(
      "compatibility",
      `This snapshot belongs to ${String(value.appId)}, not ${profile.appId}.`,
    );
  }
  const envelope = value as SyncEnvelopeV2;
  length(envelope.nonce, profile.nonceBytes, "nonce");
  length(envelope.kdfSalt, profile.kdfSaltBytes, "KDF salt");
  length(envelope.prfInput, profile.prfInputBytes, "PRF input");
  length(envelope.contentSalt, 32, "content salt");
  length(envelope.passkeyKey.nonce, 12, "passkey-lock nonce");
  if (envelope.recoveryKey) {
    length(envelope.recoveryKey.nonce, 12, "recovery-lock nonce");
    length(envelope.recoveryKey.kdfSalt, 32, "recovery-lock salt");
  }
  return envelope;
}

export function snapshotLocksV2(envelope: SyncEnvelopeV2): SnapshotLocksV2 {
  return {
    appId: envelope.appId,
    contentSalt: envelope.contentSalt,
    passkeyKey: envelope.passkeyKey,
    ...(envelope.recoveryKey ? { recoveryKey: envelope.recoveryKey } : {}),
  };
}

/** Recovers the content-key material from a v2 snapshot with either lock. */
export async function openSnapshotMaterialV2<K>(
  envelope: SyncEnvelopeV2,
  opener: SnapshotOpener<K>,
  backend: CryptoBackend<K>,
): Promise<Uint8Array> {
  if ("key" in opener) {
    return openPasskeyLockV2(snapshotLocksV2(envelope), passkeyFields(envelope), opener.key, backend);
  }
  const lock = envelope.recoveryKey;
  if (!lock) {
    throw new SyncKitError("key", "This snapshot has no recovery code.");
  }
  const secret = await parseRecoveryCode(opener.recoveryCode, requireSha256(backend));
  try {
    const recoveryKey = await backend.deriveAesGcmKey(
      secret,
      base64UrlToBytes(lock.kdfSalt),
      RECOVERY_KEY_INFO,
    );
    return await backend.decryptAesGcm(
      recoveryKey,
      base64UrlToBytes(lock.nonce),
      recoveryLockAad(envelope.appId, lock.kdfSalt, envelope.contentSalt),
      base64UrlToBytes(lock.wrappedKey),
    );
  } catch (error) {
    throw asSyncKitError(error, "key", "This recovery code does not unlock this snapshot.");
  } finally {
    secret.fill(0);
  }
}

/** Recovers the content-key material through the passkey lock. */
export async function openPasskeyLockV2<K>(
  locks: SnapshotLocksV2,
  passkey: SnapshotPasskeyFields,
  key: K,
  backend: CryptoBackend<K>,
): Promise<Uint8Array> {
  try {
    return await backend.decryptAesGcm(
      key,
      base64UrlToBytes(locks.passkeyKey.nonce),
      passkeyLockAad(locks.appId, passkey, locks.contentSalt),
      base64UrlToBytes(locks.passkeyKey.wrappedKey),
    );
  } catch (error) {
    throw asSyncKitError(error, "crypto", `This passkey could not open the ${locks.appId} snapshot.`);
  }
}

/** Fresh content-key material and its salt, for a new v2 snapshot. */
export function newSnapshotMaterialV2<K>(backend: CryptoBackend<K>): {
  material: Uint8Array;
  contentSalt: string;
} {
  return {
    material: backend.randomBytes(MATERIAL_BYTES),
    contentSalt: bytesToBase64Url(backend.randomBytes(32)),
  };
}

/** Wraps the content key under the passkey's derived key. */
export async function passkeyLockV2<K>(
  appId: string,
  key: K,
  passkey: SnapshotPasskeyFields,
  contentSalt: string,
  material: Uint8Array,
  backend: CryptoBackend<K>,
): Promise<SnapshotWrappedKeyV2> {
  const nonce = backend.randomBytes(12);
  return {
    nonce: bytesToBase64Url(nonce),
    wrappedKey: bytesToBase64Url(
      await backend.encryptAesGcm(key, nonce, passkeyLockAad(appId, passkey, contentSalt), material),
    ),
  };
}

/** Wraps the content key under a key derived from a recovery code. */
export async function recoveryLockV2<K>(
  appId: string,
  recoveryCode: string,
  contentSalt: string,
  material: Uint8Array,
  backend: CryptoBackend<K>,
): Promise<SnapshotWrappedKeyV2 & { kdfSalt: string }> {
  const secret = await parseRecoveryCode(recoveryCode, requireSha256(backend));
  try {
    const kdfSalt = bytesToBase64Url(backend.randomBytes(32));
    const recoveryKey = await backend.deriveAesGcmKey(secret, base64UrlToBytes(kdfSalt), RECOVERY_KEY_INFO);
    const nonce = backend.randomBytes(12);
    return {
      kdfSalt,
      nonce: bytesToBase64Url(nonce),
      wrappedKey: bytesToBase64Url(
        await backend.encryptAesGcm(
          recoveryKey,
          nonce,
          recoveryLockAad(appId, kdfSalt, contentSalt),
          material,
        ),
      ),
    };
  } finally {
    secret.fill(0);
  }
}

/** Encrypts `value` into a v2 snapshot holding `locks`. */
export async function sealSnapshotV2<T, K>(
  value: T,
  material: Uint8Array,
  locks: SnapshotLocksV2,
  passkey: SnapshotPasskeyFields,
  profile: V1CompatibilityProfile,
  codec: Pick<SyncCodec<T>, "serialize" | "updatedAt">,
  backend: CryptoBackend<K>,
): Promise<SyncEnvelopeV2> {
  let plaintext: Uint8Array;
  try {
    plaintext = encoder.encode(JSON.stringify(codec.serialize(value)));
  } catch (error) {
    throw new SyncKitError("serialization", "Snapshot serialization failed.", { cause: error });
  }
  let compression: "gzip" | undefined;
  if (profile.compression === "gzip-if-smaller") {
    const compressed = await backend.gzip(plaintext);
    if (compressed.length < plaintext.length) {
      plaintext = compressed;
      compression = "gzip";
    }
  }
  const header = headerOf({
    schemaVersion: 2,
    appId: locks.appId,
    algorithm: V1_ALGORITHM,
    ...(compression ? { compression } : {}),
    credentialId: passkey.credentialId,
    rpId: passkey.rpId,
    prfInput: bytesToBase64Url(passkey.prfInput),
    kdfSalt: bytesToBase64Url(passkey.kdfSalt),
    contentSalt: locks.contentSalt,
    passkeyKey: locks.passkeyKey,
    ...(locks.recoveryKey ? { recoveryKey: locks.recoveryKey } : {}),
    updatedAt: codec.updatedAt?.(value) ?? new Date().toISOString(),
  });
  const nonce = backend.randomBytes(profile.nonceBytes);
  const ciphertext = await backend.encryptAesGcm(
    await contentKey(material, locks.contentSalt, backend),
    nonce,
    payloadAad(profile, header),
    plaintext,
  );
  return { ...header, nonce: bytesToBase64Url(nonce), ciphertext: bytesToBase64Url(ciphertext) };
}

/** Decrypts a v2 snapshot's payload once its content-key material is open. */
export async function unsealSnapshotV2<T, K>(
  envelope: SyncEnvelopeV2,
  material: Uint8Array,
  profile: V1CompatibilityProfile,
  codec: Pick<SyncCodec<T>, "parse">,
  backend: CryptoBackend<K>,
): Promise<T> {
  try {
    let plaintext = await backend.decryptAesGcm(
      await contentKey(material, envelope.contentSalt, backend),
      base64UrlToBytes(envelope.nonce),
      payloadAad(profile, headerOf(envelope)),
      base64UrlToBytes(envelope.ciphertext),
    );
    if (envelope.compression === "gzip") plaintext = await backend.gunzip(plaintext);
    return codec.parse(JSON.parse(decoder.decode(plaintext)));
  } catch (error) {
    throw asSyncKitError(error, "crypto", `The ${profile.appId} snapshot could not be decrypted.`);
  }
}

export function passkeyFields(envelope: {
  credentialId: string;
  rpId: string;
  prfInput: string;
  kdfSalt: string;
}): SnapshotPasskeyFields {
  return {
    credentialId: envelope.credentialId,
    rpId: envelope.rpId,
    prfInput: base64UrlToBytes(envelope.prfInput),
    kdfSalt: base64UrlToBytes(envelope.kdfSalt),
  };
}

/**
 * The authenticated header, built from the known fields only — never "every
 * field but the nonce and ciphertext" — so a reader that drops unknown fields
 * (Android does) authenticates exactly what the writer did.
 */
function headerOf(envelope: Omit<SyncEnvelopeV2, "nonce" | "ciphertext">): Omit<SyncEnvelopeV2, "nonce" | "ciphertext"> {
  return {
    schemaVersion: 2,
    appId: envelope.appId,
    algorithm: envelope.algorithm,
    ...(envelope.compression ? { compression: envelope.compression } : {}),
    credentialId: envelope.credentialId,
    rpId: envelope.rpId,
    prfInput: envelope.prfInput,
    kdfSalt: envelope.kdfSalt,
    contentSalt: envelope.contentSalt,
    passkeyKey: { nonce: envelope.passkeyKey.nonce, wrappedKey: envelope.passkeyKey.wrappedKey },
    ...(envelope.recoveryKey
      ? {
          recoveryKey: {
            kdfSalt: envelope.recoveryKey.kdfSalt,
            nonce: envelope.recoveryKey.nonce,
            wrappedKey: envelope.recoveryKey.wrappedKey,
          },
        }
      : {}),
    updatedAt: envelope.updatedAt,
  };
}

function contentKey<K>(material: Uint8Array, contentSalt: string, backend: CryptoBackend<K>): Promise<K> {
  return backend.deriveAesGcmKey(material, base64UrlToBytes(contentSalt), CONTENT_KEY_INFO);
}

/** The whole header — every field but the nonce and ciphertext — is authenticated. */
function payloadAad(profile: V1CompatibilityProfile, header: object): Uint8Array {
  return canonicalAad({ aad: profile.aad, header });
}

function passkeyLockAad(appId: string, passkey: SnapshotPasskeyFields, contentSalt: string): Uint8Array {
  return canonicalAad({
    kind: "sync-kit-snapshot-passkey-lock",
    appId,
    credentialId: passkey.credentialId,
    rpId: passkey.rpId,
    prfInput: bytesToBase64Url(passkey.prfInput),
    kdfSalt: bytesToBase64Url(passkey.kdfSalt),
    contentSalt,
  });
}

function recoveryLockAad(appId: string, kdfSalt: string, contentSalt: string): Uint8Array {
  return canonicalAad({ kind: "sync-kit-snapshot-recovery-lock", appId, kdfSalt, contentSalt });
}

function requireSha256<K>(backend: CryptoBackend<K>): { sha256(data: Uint8Array): Promise<Uint8Array> } {
  const sha256 = backend.sha256?.bind(backend);
  if (!sha256) {
    throw new SyncKitError("configuration", "Recovery codes need a CryptoBackend with sha256.");
  }
  return { sha256 };
}

function wrappedKey(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return nonEmpty(record.nonce) && nonEmpty(record.wrappedKey);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function length(value: string, expected: number, label: string): void {
  if (base64UrlToBytes(value).length !== expected) {
    throw new SyncKitError("compatibility", `The v2 envelope ${label} has an invalid length.`);
  }
}
