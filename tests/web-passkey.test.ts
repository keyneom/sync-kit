import { describe, expect, it, vi } from "vitest";
import { WebPasskeyProvider } from "../src/keys/web-passkey/index.js";
import { type SyncEnvelopeV1 } from "../src/crypto/index.js";
import { easyBcTestProfile } from "./compatibility-profiles.js";

describe("web passkey provider", () => {
  it("uses exact WebAuthn inputs and zeros raw PRF output after derivation", async () => {
    const secret = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const credential = fakeCredential(Uint8Array.of(1, 2, 3), secret);
    const create = vi.fn().mockResolvedValue(credential);
    const deriveKey = vi.fn().mockResolvedValue("key");
    const provider = new WebPasskeyProvider(easyBcTestProfile, {
      rpId: "keyneom.github.io",
      deriveKey,
      crypto: deterministicCrypto(),
      navigator: {
        credentials: { create },
      } as unknown as Navigator,
      secureContext: () => true,
    });

    await expect(provider.create()).resolves.toMatchObject({
      metadata: {
        credentialId: "AQID",
        rpId: "keyneom.github.io",
      },
      key: "key",
    });
    const request = create.mock.calls[0]?.[0] as CredentialCreationOptions;
    expect(request.publicKey?.rp).toEqual({
      id: "keyneom.github.io",
      name: "EasyBC",
    });
    expect(request.publicKey?.user.displayName).toBe("EasyBC encrypted sync");
    expect(request.publicKey?.authenticatorSelection).toMatchObject({
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    });
    expect(secret).toEqual(new Uint8Array(32));
  });

  it("coalesces concurrent unlocks, requests only the exact credential, and clears cache", async () => {
    let resolveCredential!: (value: Credential) => void;
    const get = vi.fn().mockReturnValue(
      new Promise<Credential>((resolve) => {
        resolveCredential = resolve;
      }),
    );
    const deriveKey = vi.fn().mockResolvedValue("key");
    const provider = new WebPasskeyProvider(easyBcTestProfile, {
      rpId: "keyneom.github.io",
      deriveKey,
      crypto: deterministicCrypto(),
      navigator: {
        credentials: { get },
      } as unknown as Navigator,
      secureContext: () => true,
    });
    const envelope = fixtureEnvelope();

    const first = provider.unlock(envelope);
    const second = provider.unlock(envelope);
    expect(get).toHaveBeenCalledOnce();
    resolveCredential(
      fakeCredential(
        Uint8Array.of(1, 2, 3),
        Uint8Array.from({ length: 32 }, () => 7),
      ) as unknown as Credential,
    );
    await expect(first).resolves.toBe("key");
    await expect(second).resolves.toBe("key");
    const request = get.mock.calls[0]?.[0] as CredentialRequestOptions;
    expect(
      new Uint8Array(request.publicKey?.allowCredentials?.[0]?.id as ArrayBuffer),
    ).toEqual(Uint8Array.of(1, 2, 3));

    await provider.unlock(envelope);
    expect(get).toHaveBeenCalledOnce();
    get.mockResolvedValue(
      fakeCredential(
        Uint8Array.of(1, 2, 3),
        Uint8Array.from({ length: 32 }, () => 8),
      ),
    );
    await provider.unlock({
      ...envelope,
      prfInput: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    });
    expect(get).toHaveBeenCalledTimes(2);
    provider.clear();
    get.mockResolvedValue(
      fakeCredential(
        Uint8Array.of(1, 2, 3),
        Uint8Array.from({ length: 32 }, () => 8),
      ),
    );
    await provider.unlock(envelope);
    expect(get).toHaveBeenCalledTimes(3);
  });

  it("rejects a snapshot for another RP ID before opening passkey UI", async () => {
    const get = vi.fn();
    const provider = new WebPasskeyProvider(easyBcTestProfile, {
      rpId: "keyneom.github.io",
      deriveKey: async () => "key",
      crypto: deterministicCrypto(),
      navigator: { credentials: { get } } as unknown as Navigator,
      secureContext: () => true,
    });
    await expect(
      provider.unlock({ ...fixtureEnvelope(), rpId: "example.com" }),
    ).rejects.toMatchObject({ code: "compatibility" });
    expect(get).not.toHaveBeenCalled();
  });
});

function fakeCredential(
  credentialId: Uint8Array,
  secret: Uint8Array,
): {
  rawId: ArrayBuffer;
  getClientExtensionResults(): AuthenticationExtensionsClientOutputs;
} {
  return {
    rawId: Uint8Array.from(credentialId).buffer,
    getClientExtensionResults: () =>
      ({
        prf: { results: { first: secret.buffer } },
      }) as AuthenticationExtensionsClientOutputs,
  };
}

function deterministicCrypto(): Pick<Crypto, "getRandomValues"> {
  let next = 0;
  return {
    getRandomValues: <T extends ArrayBufferView | null>(array: T): T => {
      if (array) {
        const bytes = new Uint8Array(
          array.buffer,
          array.byteOffset,
          array.byteLength,
        );
        for (let index = 0; index < bytes.length; index += 1) {
          bytes[index] = next++ & 0xff;
        }
      }
      return array;
    },
  };
}

function fixtureEnvelope(): SyncEnvelopeV1 {
  return {
    schemaVersion: 1,
    algorithm: "AES-256-GCM+HKDF-SHA-256",
    credentialId: "AQID",
    rpId: "keyneom.github.io",
    prfInput: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    kdfSalt: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
    nonce: "QEFCQ0RFRkdISUpL",
    ciphertext: "AA",
    updatedAt: "2026-06-29T00:00:00.000Z",
  };
}
