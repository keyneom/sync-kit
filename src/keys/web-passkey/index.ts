import type { KeyProvider } from "../../core/types.js";
import { SyncKitError } from "../../core/errors.js";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  createWebCryptoBackend,
  deriveContentKey,
  type CryptoBackend,
  type SyncEnvelopeV1,
  type V1CompatibilityProfile,
  type V1KeyMetadata,
} from "../../crypto/index.js";
import { copyBuffer } from "../../crypto/runtime.js";

type PrfOutput = AuthenticationExtensionsClientOutputs & {
  prf?: {
    enabled?: boolean;
    results?: { first?: ArrayBuffer };
  };
};

type PublicKeyCredentialLike = {
  rawId: ArrayBuffer;
  getClientExtensionResults(): AuthenticationExtensionsClientOutputs;
};

export type WebPasskeyProviderOptions<K> = {
  rpId: string;
  deriveKey: (secret: Uint8Array, salt: Uint8Array) => Promise<K>;
  crypto?: Pick<Crypto, "getRandomValues">;
  navigator?: Navigator;
  secureContext?: () => boolean;
};

export class WebPasskeyProvider<K>
  implements KeyProvider<SyncEnvelopeV1, K, V1KeyMetadata>
{
  private cached: { identity: string; key: K } | null = null;
  private pending: { identity: string; promise: Promise<K> } | null = null;

  constructor(
    private readonly profile: V1CompatibilityProfile,
    private readonly options: WebPasskeyProviderOptions<K>,
  ) {}

  async create(): Promise<{ metadata: V1KeyMetadata; key: K }> {
    this.assertSupported();
    const cryptoImplementation = this.crypto();
    const prfInput = randomBytes(
      this.profile.prfInputBytes,
      cryptoImplementation,
    );
    const kdfSalt = randomBytes(
      this.profile.kdfSaltBytes,
      cryptoImplementation,
    );
    const credential = asPublicKeyCredential(
      await this.navigator().credentials.create({
        publicKey: {
          rp: {
            id: this.options.rpId,
            name: this.profile.passkey.rpName,
          },
          user: {
            id: copyBuffer(randomBytes(32, cryptoImplementation)),
            name: this.profile.passkey.userName,
            displayName: this.profile.passkey.userDisplayName,
          },
          challenge: copyBuffer(randomBytes(32, cryptoImplementation)),
          pubKeyCredParams: [
            { type: "public-key", alg: this.profile.passkey.algorithm },
          ],
          authenticatorSelection: {
            residentKey: this.profile.passkey.residentKey,
            requireResidentKey: true,
            userVerification: this.profile.passkey.userVerification,
          },
          timeout: this.profile.passkey.timeoutMs,
          attestation: "none",
          extensions: prfExtensions(prfInput),
        },
      }),
    );
    const credentialId = new Uint8Array(credential.rawId);
    const returnedSecret = prfSecret(credential);
    const secret =
      returnedSecret ??
      (await this.evaluatePrf(credentialId, prfInput, this.options.rpId));
    const key = await this.deriveAndZero(secret, kdfSalt);
    const metadata = {
      credentialId: bytesToBase64Url(credentialId),
      rpId: this.options.rpId,
      prfInput,
      kdfSalt,
    };
    this.cached = { identity: metadataIdentity(metadata), key };
    return { metadata, key };
  }

  async unlock(envelope: SyncEnvelopeV1): Promise<K> {
    if (envelope.rpId !== this.options.rpId) {
      throw new SyncKitError(
        "compatibility",
        `The snapshot belongs to ${envelope.rpId}, not ${this.options.rpId}.`,
      );
    }
    const identity = envelopeIdentity(envelope);
    if (this.cached?.identity === identity) return this.cached.key;
    if (this.cached) this.clear();
    if (this.pending?.identity === identity) return this.pending.promise;

    const promise = this.unlockNow(envelope, identity);
    this.pending = { identity, promise };
    try {
      return await promise;
    } finally {
      if (this.pending?.promise === promise) this.pending = null;
    }
  }

  clear(): void {
    this.cached = null;
    this.pending = null;
  }

  supported(): boolean {
    const navigatorImplementation = this.tryNavigator();
    return (
      (this.options.secureContext?.() ??
        (typeof window !== "undefined" && window.isSecureContext)) &&
      Boolean(navigatorImplementation?.credentials)
    );
  }

  private async unlockNow(
    envelope: SyncEnvelopeV1,
    identity: string,
  ): Promise<K> {
    this.assertSupported();
    const secret = await this.evaluatePrf(
      base64UrlToBytes(envelope.credentialId),
      base64UrlToBytes(envelope.prfInput),
      envelope.rpId,
    );
    const key = await this.deriveAndZero(
      secret,
      base64UrlToBytes(envelope.kdfSalt),
    );
    this.cached = { identity, key };
    return key;
  }

  private async evaluatePrf(
    credentialId: Uint8Array,
    prfInput: Uint8Array,
    rpId: string,
  ): Promise<Uint8Array> {
    const credential = asPublicKeyCredential(
      await this.navigator().credentials.get({
        publicKey: {
          challenge: copyBuffer(randomBytes(32, this.crypto())),
          rpId,
          allowCredentials: [
            { type: "public-key", id: copyBuffer(credentialId) },
          ],
          userVerification: this.profile.passkey.userVerification,
          timeout: this.profile.passkey.timeoutMs,
          extensions: prfExtensions(prfInput),
        },
      }),
    );
    const secret = prfSecret(credential);
    if (!secret) {
      throw new SyncKitError(
        "key",
        "The passkey provider did not return a PRF secret.",
      );
    }
    return secret;
  }

  private async deriveAndZero(
    secret: Uint8Array,
    salt: Uint8Array,
  ): Promise<K> {
    try {
      return await this.options.deriveKey(secret, salt);
    } finally {
      secret.fill(0);
    }
  }

  private assertSupported(): void {
    if (!this.supported()) {
      throw new SyncKitError(
        "key",
        "Passkeys with PRF support require a secure, compatible runtime.",
      );
    }
  }

  private crypto(): Pick<Crypto, "getRandomValues"> {
    const implementation = this.options.crypto ?? globalThis.crypto;
    if (!implementation) {
      throw new SyncKitError("configuration", "Crypto randomness is unavailable.");
    }
    return implementation;
  }

  private navigator(): Navigator {
    const implementation = this.tryNavigator();
    if (!implementation) {
      throw new SyncKitError("configuration", "Credential APIs are unavailable.");
    }
    return implementation;
  }

  private tryNavigator(): Navigator | undefined {
    return (
      this.options.navigator ??
      (typeof navigator === "undefined" ? undefined : navigator)
    );
  }
}

export function createWebPasskeyProvider(
  profile: V1CompatibilityProfile,
  options: Omit<WebPasskeyProviderOptions<CryptoKey>, "deriveKey"> & {
    backend?: CryptoBackend<CryptoKey>;
  },
): WebPasskeyProvider<CryptoKey> {
  const backend = options.backend ?? createWebCryptoBackend();
  return new WebPasskeyProvider(profile, {
    ...options,
    deriveKey: (secret, salt) =>
      deriveContentKey(profile, secret, salt, backend),
  });
}

function asPublicKeyCredential(
  value: Credential | null,
): PublicKeyCredentialLike {
  if (
    !value ||
    !("rawId" in value) ||
    typeof (value as unknown as PublicKeyCredentialLike)
      .getClientExtensionResults !==
      "function"
  ) {
    throw new SyncKitError(
      "key",
      "Passkey creation or selection was cancelled.",
    );
  }
  return value as unknown as PublicKeyCredentialLike;
}

function prfSecret(credential: PublicKeyCredentialLike): Uint8Array | null {
  const first = (credential.getClientExtensionResults() as PrfOutput).prf
    ?.results?.first;
  return first ? new Uint8Array(first) : null;
}

function prfExtensions(
  prfInput: Uint8Array,
): AuthenticationExtensionsClientInputs {
  return {
    prf: { eval: { first: copyBuffer(prfInput) } },
  };
}

function randomBytes(
  length: number,
  cryptoImplementation: Pick<Crypto, "getRandomValues">,
): Uint8Array {
  return cryptoImplementation.getRandomValues(new Uint8Array(length));
}

function envelopeIdentity(envelope: SyncEnvelopeV1): string {
  return [envelope.rpId, envelope.credentialId, envelope.kdfSalt].join("\n");
}

function metadataIdentity(metadata: V1KeyMetadata): string {
  return [
    metadata.rpId,
    metadata.credentialId,
    bytesToBase64Url(metadata.kdfSalt),
  ].join("\n");
}
