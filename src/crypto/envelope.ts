import type { EnvelopeCrypto, SyncCodec } from "../core/types.js";
import { SyncKitError, asSyncKitError } from "../core/errors.js";
import { base64UrlToBytes, bytesToBase64Url } from "./base64url.js";
import type { CryptoBackend } from "./runtime.js";
import type { V1CompatibilityProfile } from "./profiles.js";
import { V1_ALGORITHM } from "./profiles.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type SyncEnvelopeV1 = {
  schemaVersion: 1;
  algorithm: typeof V1_ALGORITHM;
  compression?: "gzip";
  credentialId: string;
  rpId: string;
  prfInput: string;
  kdfSalt: string;
  nonce: string;
  ciphertext: string;
  updatedAt: string;
};

export type V1KeyMetadata = {
  credentialId: string;
  rpId: string;
  prfInput: Uint8Array;
  kdfSalt: Uint8Array;
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

export async function encryptSyncEnvelopeV1<T, K>(
  value: T,
  key: K,
  metadata: V1KeyMetadata,
  profile: V1CompatibilityProfile,
  codec: Pick<SyncCodec<T>, "serialize" | "updatedAt">,
  backend: CryptoBackend<K>,
  options: { nonce?: Uint8Array; now?: () => Date } = {},
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
): EnvelopeCrypto<T, SyncEnvelopeV1, K, V1KeyMetadata> {
  return {
    encrypt: (value, key, metadata) =>
      encryptSyncEnvelopeV1(value, key, metadata, profile, codec, backend),
    decrypt: (envelope, key) =>
      decryptSyncEnvelopeV1(envelope, key, profile, codec, backend),
    metadataFromEnvelope: (envelope) => ({
      credentialId: envelope.credentialId,
      rpId: envelope.rpId,
      prfInput: base64UrlToBytes(envelope.prfInput),
      kdfSalt: base64UrlToBytes(envelope.kdfSalt),
    }),
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
