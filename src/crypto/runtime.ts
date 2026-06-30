import { SyncKitError } from "../core/errors.js";

export interface CryptoBackend<K> {
  randomBytes(length: number): Uint8Array;
  deriveAesGcmKey(
    inputKeyMaterial: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
  ): Promise<K>;
  encryptAesGcm(
    key: K,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>;
  decryptAesGcm(
    key: K,
    nonce: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
  ): Promise<Uint8Array>;
  gzip(plaintext: Uint8Array): Promise<Uint8Array>;
  gunzip(compressed: Uint8Array): Promise<Uint8Array>;
}

export function createWebCryptoBackend(
  cryptoImplementation: Crypto = globalThis.crypto,
): CryptoBackend<CryptoKey> {
  if (!cryptoImplementation?.subtle) {
    throw new SyncKitError(
      "configuration",
      "A WebCrypto implementation is required.",
    );
  }
  return {
    randomBytes(length) {
      return cryptoImplementation.getRandomValues(new Uint8Array(length));
    },
    async deriveAesGcmKey(inputKeyMaterial, salt, info) {
      const material = await cryptoImplementation.subtle.importKey(
        "raw",
        copyBuffer(inputKeyMaterial),
        "HKDF",
        false,
        ["deriveKey"],
      );
      return cryptoImplementation.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: copyBuffer(salt),
          info: copyBuffer(info),
        },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
    },
    async encryptAesGcm(key, nonce, aad, plaintext) {
      return new Uint8Array(
        await cryptoImplementation.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: copyBuffer(nonce),
            additionalData: copyBuffer(aad),
            tagLength: 128,
          },
          key,
          copyBuffer(plaintext),
        ),
      );
    },
    async decryptAesGcm(key, nonce, aad, ciphertext) {
      return new Uint8Array(
        await cryptoImplementation.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: copyBuffer(nonce),
            additionalData: copyBuffer(aad),
            tagLength: 128,
          },
          key,
          copyBuffer(ciphertext),
        ),
      );
    },
    gzip(value) {
      return transformBytes(value, new CompressionStream("gzip"));
    },
    gunzip(value) {
      return transformBytes(value, new DecompressionStream("gzip"));
    },
  };
}

export function copyBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

async function transformBytes(
  bytes: Uint8Array,
  stream: CompressionStream | DecompressionStream,
): Promise<Uint8Array> {
  try {
    const input = new Blob([copyBuffer(bytes)]).stream().pipeThrough(stream);
    return new Uint8Array(await new Response(input).arrayBuffer());
  } catch (error) {
    throw new SyncKitError(
      stream instanceof DecompressionStream ? "decompression" : "crypto",
      stream instanceof DecompressionStream
        ? "The encrypted snapshot contains invalid gzip data."
        : "The snapshot could not be compressed.",
      { cause: error },
    );
  }
}
