// Internal: the one private-key byte format shared by passkey-protected
// sharing identities and recovery keys. Not a public subpath.
import { SyncKitError } from "../core/errors.js";
import { bytesToBase64Url } from "../crypto/index.js";
import { copyBuffer } from "../crypto/runtime.js";
import type { SharingPublicKeyV1 } from "./index.js";
import {
  createSharingPublicKeyV1,
  type WebCryptoSharingIdentity,
} from "./web-crypto.js";

/**
 * Generates a sharing identity whose private keys are returned packed, so the
 * caller can seal them. The packed bytes are the only copy; zero them after use.
 */
export async function generateSharingIdentityMaterial(
  cryptoImplementation: Crypto,
): Promise<{ publicKey: SharingPublicKeyV1; packed: Uint8Array }> {
  const encryption = await cryptoImplementation.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const signing = await cryptoImplementation.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicKey = await createSharingPublicKeyV1(
    bytesToBase64Url(
      new Uint8Array(await cryptoImplementation.subtle.exportKey("raw", encryption.publicKey)),
    ),
    bytesToBase64Url(
      new Uint8Array(await cryptoImplementation.subtle.exportKey("raw", signing.publicKey)),
    ),
    cryptoImplementation,
  );
  const encryptionPrivate = new Uint8Array(
    await cryptoImplementation.subtle.exportKey("pkcs8", encryption.privateKey),
  );
  const signingPrivate = new Uint8Array(
    await cryptoImplementation.subtle.exportKey("pkcs8", signing.privateKey),
  );
  try {
    return { publicKey, packed: packPrivateKeys(encryptionPrivate, signingPrivate) };
  } finally {
    encryptionPrivate.fill(0);
    signingPrivate.fill(0);
  }
}

/**
 * Imports packed private keys as a non-extractable identity and confirms they
 * match `publicKey`. The caller zeroes `packed`.
 */
export async function importSharingIdentity(
  publicKey: SharingPublicKeyV1,
  packed: Uint8Array,
  cryptoImplementation: Crypto,
): Promise<WebCryptoSharingIdentity> {
  const [encryptionPrivate, signingPrivate] = unpackPrivateKeys(packed);
  try {
    const identity = {
      publicKey,
      encryptionPrivateKey: await cryptoImplementation.subtle.importKey(
        "pkcs8",
        copyBuffer(encryptionPrivate),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      ),
      signingPrivateKey: await cryptoImplementation.subtle.importKey(
        "pkcs8",
        copyBuffer(signingPrivate),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      ),
    };
    const expected = await createSharingPublicKeyV1(
      publicKey.encryptionPublicKey,
      publicKey.signingPublicKey,
      cryptoImplementation,
    );
    if (expected.keyId !== publicKey.keyId) {
      throw new SyncKitError(
        "key",
        "The protected sharing identity public-key fingerprint is invalid.",
      );
    }
    return identity;
  } finally {
    encryptionPrivate.fill(0);
    signingPrivate.fill(0);
  }
}

export function packPrivateKeys(
  encryptionPrivate: Uint8Array,
  signingPrivate: Uint8Array,
): Uint8Array {
  const packed = new Uint8Array(4 + encryptionPrivate.length + signingPrivate.length);
  new DataView(packed.buffer).setUint32(0, encryptionPrivate.length);
  packed.set(encryptionPrivate, 4);
  packed.set(signingPrivate, 4 + encryptionPrivate.length);
  return packed;
}

export function unpackPrivateKeys(packed: Uint8Array): [Uint8Array, Uint8Array] {
  if (packed.length < 5) {
    throw new SyncKitError(
      "compatibility",
      "Protected sharing private-key material is malformed.",
    );
  }
  const encryptionLength = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength,
  ).getUint32(0);
  if (encryptionLength === 0 || 4 + encryptionLength >= packed.length) {
    throw new SyncKitError(
      "compatibility",
      "Protected sharing private-key material is malformed.",
    );
  }
  return [
    packed.slice(4, 4 + encryptionLength),
    packed.slice(4 + encryptionLength),
  ];
}
