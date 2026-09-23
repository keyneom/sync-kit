/**
 * Additional participant keys and recovery codes. See docs/participant-keys.md.
 *
 * Every operation here is signed by the participant it concerns, so any
 * participant who can write a dataset may carry it in. Apply them with
 * `SharedBackupController.addParticipantKeys`, `removeParticipantKeys`, and
 * `rotateWithAdditionalKey`.
 */
import { SyncKitError, asSyncKitError } from "../core/errors.js";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalAad,
  generateRecoveryCode,
  isRecoveryCodeWellFormed,
  parseRecoveryCode,
  type RecoveryCodeCrypto,
} from "../crypto/index.js";
import { copyBuffer } from "../crypto/runtime.js";
import {
  sharedBackupAdditionalKeys,
  type SharedBackupAdditionalKeyPurpose,
  type SharedBackupAdditionalKeyV1,
  type SharedBackupAuthorizedKeyRotationV1,
  type SharedBackupEnvelopeV1,
  type SharedBackupKeyRemovalV1,
  type SharedBackupSealedKeyV1,
} from "./index.js";
import {
  generateSharingIdentityMaterial,
  importSharingIdentity,
} from "./identity-material.js";
import {
  additionStatement,
  publicKeyFields,
  removalStatement,
  rotationStatement,
  signStatement,
} from "./participant-key-statements.js";
import type { WebCryptoSharingIdentity } from "./web-crypto.js";

export type ParticipantKeyOptions = { crypto?: Crypto };

/**
 * Signs a request to add `key` to the participant `principalKeyId`. The
 * `authorizer` must be that participant's primary key or one of its existing
 * additional keys; `key` signs too, proving its holder has it.
 */
export async function createParticipantKeyAdditionV1(
  input: {
    appId: string;
    principalKeyId: string;
    authorizer: WebCryptoSharingIdentity;
    key: WebCryptoSharingIdentity;
    purpose: SharedBackupAdditionalKeyPurpose;
    sealedPrivateKeys?: SharedBackupSealedKeyV1;
  },
  options: ParticipantKeyOptions = {},
): Promise<SharedBackupAdditionalKeyV1> {
  const cryptoImplementation = webCrypto(options);
  requireNonEmpty(input.appId, "appId");
  if (input.key.publicKey.keyId === input.principalKeyId) {
    throw new SyncKitError(
      "configuration",
      "A participant's primary key cannot also be one of its additional keys.",
    );
  }
  const statement = additionStatement({
    appId: input.appId,
    principalKeyId: input.principalKeyId,
    addedByKeyId: input.authorizer.publicKey.keyId,
    key: input.key.publicKey,
    purpose: input.purpose,
    ...(input.sealedPrivateKeys ? { sealedPrivateKeys: input.sealedPrivateKeys } : {}),
  });
  return {
    ...publicKeyFields(input.key.publicKey),
    principalKeyId: input.principalKeyId,
    purpose: input.purpose,
    addedByKeyId: input.authorizer.publicKey.keyId,
    addition: await signStatement(
      input.authorizer.signingPrivateKey,
      statement,
      cryptoImplementation,
    ),
    possession: await signStatement(
      input.key.signingPrivateKey,
      statement,
      cryptoImplementation,
    ),
    ...(input.sealedPrivateKeys ? { sealedPrivateKeys: input.sealedPrivateKeys } : {}),
  };
}

/**
 * Signs a participant's removal of one of its own additional keys. The
 * `authorizer` must be a key of the same participant — its primary key or any
 * of its additional keys, including the one being removed.
 */
export async function createParticipantKeyRemovalV1(
  input: {
    appId: string;
    authorizer: WebCryptoSharingIdentity;
    key: SharedBackupAdditionalKeyV1;
  },
  options: ParticipantKeyOptions = {},
): Promise<SharedBackupKeyRemovalV1> {
  const cryptoImplementation = webCrypto(options);
  requireNonEmpty(input.appId, "appId");
  return {
    keyId: input.key.keyId,
    removedByKeyId: input.authorizer.publicKey.keyId,
    removal: await signStatement(
      input.authorizer.signingPrivateKey,
      removalStatement({
        appId: input.appId,
        keyId: input.key.keyId,
        addition: input.key.addition,
      }),
      cryptoImplementation,
    ),
  };
}

/**
 * Signs "replace my primary key `fromKeyId` with `replacement`", authorized by
 * one of that participant's additional keys — how a lost passkey is replaced.
 * One signed rotation applies to every dataset in the app.
 */
export async function createAuthorizedKeyRotationV1(
  input: {
    appId: string;
    fromKeyId: string;
    authorizer: WebCryptoSharingIdentity;
    replacement: WebCryptoSharingIdentity;
  },
  options: ParticipantKeyOptions = {},
): Promise<SharedBackupAuthorizedKeyRotationV1> {
  const cryptoImplementation = webCrypto(options);
  requireNonEmpty(input.appId, "appId");
  const statement = rotationStatement({
    appId: input.appId,
    fromKeyId: input.fromKeyId,
    to: input.replacement.publicKey,
  });
  return {
    fromKeyId: input.fromKeyId,
    to: publicKeyFields(input.replacement.publicKey),
    newKeyProof: await signStatement(
      input.replacement.signingPrivateKey,
      statement,
      cryptoImplementation,
    ),
    authorizedByKeyId: input.authorizer.publicKey.keyId,
    authorization: await signStatement(
      input.authorizer.signingPrivateKey,
      statement,
      cryptoImplementation,
    ),
  };
}

// --- Recovery codes -------------------------------------------------------

const RECOVERY_KDF_INFO = "sync-kit participant recovery key v1";
const SEALED_KEY_KIND = "sync-kit-sealed-participant-key";

/**
 * Generates a recovery code: 128 random bits as 26 Crockford base32
 * characters plus 2 check characters, in seven groups of four. Show it once;
 * whoever holds it can act as the participant until the key is removed.
 */
export async function generateSharingRecoveryCode(
  options: ParticipantKeyOptions = {},
): Promise<string> {
  return generateRecoveryCode(codeCrypto(options));
}

/**
 * Whether `code` is a well-formed recovery code, for live input validation.
 * Tolerates case, spaces, and hyphens, and reads I and L as 1 and O as 0.
 */
export async function isSharingRecoveryCodeWellFormed(
  code: string,
  options: ParticipantKeyOptions = {},
): Promise<boolean> {
  return isRecoveryCodeWellFormed(code, codeCrypto(options));
}

/**
 * Returns the 16-byte secret in a recovery code. Rejects anything that is not
 * a generated code, so a user-chosen passphrase can never be used. The caller
 * zeroes the result.
 */
export async function parseSharingRecoveryCode(
  code: string,
  options: ParticipantKeyOptions = {},
): Promise<Uint8Array> {
  return parseRecoveryCode(code, codeCrypto(options));
}

/**
 * Creates a recovery key for `code`: a fresh sharing identity whose private
 * keys are sealed under the code. Add it to each dataset with
 * `createParticipantKeyAdditionV1({ purpose: "recovery", sealedPrivateKeys })`;
 * the sealed keys travel inside every data file that grants the recovery key,
 * so the code and any one file are enough to recover.
 */
export async function createSharingRecoveryKeyV1(
  input: { appId: string; code: string },
  options: ParticipantKeyOptions = {},
): Promise<{
  identity: WebCryptoSharingIdentity;
  sealedPrivateKeys: SharedBackupSealedKeyV1;
}> {
  const cryptoImplementation = webCrypto(options);
  requireNonEmpty(input.appId, "appId");
  const secret = await parseSharingRecoveryCode(input.code, options);
  const { publicKey, packed } = await generateSharingIdentityMaterial(cryptoImplementation);
  try {
    const kdfSalt = cryptoImplementation.getRandomValues(new Uint8Array(32));
    const nonce = cryptoImplementation.getRandomValues(new Uint8Array(12));
    const header = sealedKeyHeader(input.appId, publicKey.keyId, kdfSalt, nonce);
    const encrypted = await cryptoImplementation.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: copyBuffer(nonce),
        additionalData: copyBuffer(canonicalAad(header)),
        tagLength: 128,
      },
      await recoveryWrappingKey(secret, kdfSalt, cryptoImplementation),
      copyBuffer(packed),
    );
    return {
      identity: await importSharingIdentity(publicKey, packed, cryptoImplementation),
      sealedPrivateKeys: {
        kdf: "HKDF-SHA256",
        kdfSalt: bytesToBase64Url(kdfSalt),
        nonce: bytesToBase64Url(nonce),
        encryptedPrivateKeys: bytesToBase64Url(new Uint8Array(encrypted)),
      },
    };
  } finally {
    secret.fill(0);
    packed.fill(0);
  }
}

/** Unseals one recovery key with its code. */
export async function openSharingRecoveryKeyV1(
  input: { appId: string; code: string; key: SharedBackupAdditionalKeyV1 },
  options: ParticipantKeyOptions = {},
): Promise<WebCryptoSharingIdentity> {
  const cryptoImplementation = webCrypto(options);
  const sealed = input.key.sealedPrivateKeys;
  if (!sealed) {
    throw new SyncKitError("key", "This additional key is not sealed under a recovery code.");
  }
  const secret = await parseSharingRecoveryCode(input.code, options);
  let packed: Uint8Array;
  try {
    const kdfSalt = base64UrlToBytes(sealed.kdfSalt);
    const nonce = base64UrlToBytes(sealed.nonce);
    packed = new Uint8Array(
      await cryptoImplementation.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: copyBuffer(nonce),
          additionalData: copyBuffer(
            canonicalAad(sealedKeyHeader(input.appId, input.key.keyId, kdfSalt, nonce)),
          ),
          tagLength: 128,
        },
        await recoveryWrappingKey(secret, kdfSalt, cryptoImplementation),
        copyBuffer(base64UrlToBytes(sealed.encryptedPrivateKeys)),
      ),
    );
  } catch (error) {
    throw asSyncKitError(
      error,
      "key",
      "This recovery code does not unlock this recovery key.",
    );
  } finally {
    secret.fill(0);
  }
  try {
    return await importSharingIdentity(
      publicKeyFields(input.key),
      packed,
      cryptoImplementation,
    );
  } finally {
    packed.fill(0);
  }
}

/**
 * Finds and unseals the recovery key `code` opens in `envelope`. Needs nothing
 * but the code and this one file, which may be an offline copy.
 */
export async function openSharingRecoveryKeyFromEnvelopeV1(
  input: { code: string; envelope: SharedBackupEnvelopeV1 },
  options: ParticipantKeyOptions = {},
): Promise<{ identity: WebCryptoSharingIdentity; key: SharedBackupAdditionalKeyV1 }> {
  // Validate once up front so a typo is reported as a typo, not as "no match".
  (await parseSharingRecoveryCode(input.code, options)).fill(0);
  for (const key of sharedBackupAdditionalKeys(input.envelope)) {
    if (!key.sealedPrivateKeys) continue;
    try {
      const identity = await openSharingRecoveryKeyV1(
        { appId: input.envelope.appId, code: input.code, key },
        options,
      );
      return { identity, key };
    } catch (error) {
      if (!(error instanceof SyncKitError) || error.code !== "key") throw error;
    }
  }
  throw new SyncKitError(
    "key",
    "This recovery code does not unlock any recovery key in this dataset.",
  );
}

function sealedKeyHeader(
  appId: string,
  keyId: string,
  kdfSalt: Uint8Array,
  nonce: Uint8Array,
): Record<string, unknown> {
  return {
    kind: SEALED_KEY_KIND,
    appId,
    keyId,
    kdf: "HKDF-SHA256",
    kdfSalt: bytesToBase64Url(kdfSalt),
    nonce: bytesToBase64Url(nonce),
  };
}

async function recoveryWrappingKey(
  secret: Uint8Array,
  kdfSalt: Uint8Array,
  cryptoImplementation: Crypto,
): Promise<CryptoKey> {
  const material = await cryptoImplementation.subtle.importKey(
    "raw",
    copyBuffer(secret),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return cryptoImplementation.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: copyBuffer(kdfSalt),
      info: copyBuffer(new TextEncoder().encode(RECOVERY_KDF_INFO)),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}




function codeCrypto(options: ParticipantKeyOptions): RecoveryCodeCrypto {
  const implementation = webCrypto(options);
  return {
    randomBytes: (length) => implementation.getRandomValues(new Uint8Array(length)),
    sha256: async (data) =>
      new Uint8Array(await implementation.subtle.digest("SHA-256", copyBuffer(data))),
  };
}

function webCrypto(options: ParticipantKeyOptions): Crypto {
  const implementation = options.crypto ?? globalThis.crypto;
  if (!implementation?.subtle) {
    throw new SyncKitError("configuration", "WebCrypto is required for participant keys.");
  }
  return implementation;
}

function requireNonEmpty(value: string, name: string): void {
  if (!value.trim()) throw new TypeError(`${name} must not be empty.`);
}
