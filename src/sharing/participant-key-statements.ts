// Internal: the signed statements behind participant-key operations, shared by
// the envelope writer and verifier. Not a public subpath.
//
// Statements are app-scoped, not dataset-scoped, so one signed operation
// applies to every dataset a participant is in. See docs/participant-keys.md.
import { base64UrlToBytes, bytesToBase64Url, canonicalAad } from "../crypto/index.js";
import { copyBuffer } from "../crypto/runtime.js";
import {
  PARTICIPANT_KEY_ADDITION_KIND,
  PARTICIPANT_KEY_REMOVAL_KIND,
  PARTICIPANT_KEY_ROTATION_KIND,
  type SharedBackupAdditionalKeyPurpose,
  type SharedBackupAdditionalKeyV1,
  type SharedBackupSealedKeyV1,
  type SharingPublicKeyV1,
} from "./index.js";

/** Exactly the public fields of a key, so no stray field can enter a signature. */
export function publicKeyFields(key: SharingPublicKeyV1): SharingPublicKeyV1 {
  return {
    keyId: key.keyId,
    encryptionAlgorithm: key.encryptionAlgorithm,
    encryptionPublicKey: key.encryptionPublicKey,
    signatureAlgorithm: key.signatureAlgorithm,
    signingPublicKey: key.signingPublicKey,
  };
}

export function additionStatement(input: {
  appId: string;
  principalKeyId: string;
  addedByKeyId: string;
  key: SharingPublicKeyV1;
  purpose: SharedBackupAdditionalKeyPurpose;
  sealedPrivateKeys?: SharedBackupSealedKeyV1;
}): Record<string, unknown> {
  return {
    kind: PARTICIPANT_KEY_ADDITION_KIND,
    appId: input.appId,
    principalKeyId: input.principalKeyId,
    addedByKeyId: input.addedByKeyId,
    key: publicKeyFields(input.key),
    purpose: input.purpose,
    ...(input.sealedPrivateKeys ? { sealedPrivateKeys: input.sealedPrivateKeys } : {}),
  };
}

/**
 * The statement an additional key's `addition` and `possession` signatures
 * cover, rebuilt from the key as it was first added. `principalKeyId` is the
 * principal at that moment; a later rotation may re-point the stored key.
 */
export function additionStatementForKey(
  appId: string,
  key: SharedBackupAdditionalKeyV1,
  principalKeyId = key.principalKeyId,
): Record<string, unknown> {
  return additionStatement({
    appId,
    principalKeyId,
    addedByKeyId: key.addedByKeyId,
    key,
    purpose: key.purpose,
    ...(key.sealedPrivateKeys ? { sealedPrivateKeys: key.sealedPrivateKeys } : {}),
  });
}

/**
 * Bound to the specific addition it revokes, so it cannot remove a later
 * re-add. It names no principal: the verifier checks the signer belongs to the
 * key's current principal, and a rotation may have moved the key since it was
 * added, so a removal built from the originally added key stays valid.
 */
export function removalStatement(input: {
  appId: string;
  keyId: string;
  addition: string;
}): Record<string, unknown> {
  return {
    kind: PARTICIPANT_KEY_REMOVAL_KIND,
    appId: input.appId,
    keyId: input.keyId,
    addition: input.addition,
  };
}

export function rotationStatement(input: {
  appId: string;
  fromKeyId: string;
  to: SharingPublicKeyV1;
}): Record<string, unknown> {
  return {
    kind: PARTICIPANT_KEY_ROTATION_KIND,
    appId: input.appId,
    fromKeyId: input.fromKeyId,
    to: publicKeyFields(input.to),
  };
}

export async function signStatement(
  signingPrivateKey: CryptoKey,
  statement: Record<string, unknown>,
  cryptoImplementation: Crypto,
): Promise<string> {
  return bytesToBase64Url(
    new Uint8Array(
      await cryptoImplementation.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        signingPrivateKey,
        copyBuffer(canonicalAad(statement)),
      ),
    ),
  );
}

export async function verifyStatement(
  signer: Pick<SharingPublicKeyV1, "signingPublicKey">,
  statement: Record<string, unknown>,
  signature: string,
  cryptoImplementation: Crypto,
): Promise<boolean> {
  const key = await cryptoImplementation.subtle.importKey(
    "raw",
    copyBuffer(base64UrlToBytes(signer.signingPublicKey)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return cryptoImplementation.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    copyBuffer(base64UrlToBytes(signature)),
    copyBuffer(canonicalAad(statement)),
  );
}
