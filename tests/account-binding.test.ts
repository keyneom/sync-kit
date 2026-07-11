import { describe, expect, it, vi } from "vitest";
import { readFile } from "node:fs/promises";
import type { SharingAccountBindingV1 } from "../src/sharing/index.js";
import { bytesToBase64Url } from "../src/crypto/base64url.js";
import {
  createSharingAccountBindingChallenge,
  createSharingAccountBindingV1,
  GoogleJwksCache,
  verifyGoogleIdToken,
  verifyPasskeyAssertion,
  verifySharingAccountBindingV1,
} from "../src/sharing/account-binding.js";

const encoder = new TextEncoder();

describe("backendless Google/passkey account binding", () => {
  it("verifies one challenge against both Google and WebAuthn signatures", async () => {
    const context = {
      appId: "fixture-app",
      exchangeId: "exchange-1",
      sharingKeyId: bytesToBase64Url(new Uint8Array(32).fill(9)),
      credentialId: "Y3JlZGVudGlhbC0x",
    };
    const challenge = await createSharingAccountBindingChallenge(context);
    const credentialKeys = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const credentialPublicKey = await crypto.subtle.exportKey(
      "jwk",
      credentialKeys.publicKey,
    );
    const clientDataJSON = encoder.encode(
      JSON.stringify({
        type: "webauthn.get",
        challenge,
        origin: "https://example.test",
      }),
    );
    const rpHash = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        encoder.encode("example.test"),
      ),
    );
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(rpHash);
    authenticatorData[32] = 0x05;
    const clientHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", clientDataJSON),
    );
    const signed = new Uint8Array(
      authenticatorData.length + clientHash.length,
    );
    signed.set(authenticatorData);
    signed.set(clientHash, authenticatorData.length);
    const rawSignature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        credentialKeys.privateKey,
        signed,
      ),
    );

    const googleKeys = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: Uint8Array.of(1, 0, 1),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const googleJwk = {
      ...(await crypto.subtle.exportKey("jwk", googleKeys.publicKey)),
      kid: "fixture-google-key",
    };
    const encodedHeader = encodeJwt({
      alg: "RS256",
      kid: "fixture-google-key",
    });
    const encodedPayload = encodeJwt({
      iss: "https://accounts.google.com",
      aud: "google-client-id",
      sub: "google-subject",
      email: "recipient@example.com",
      email_verified: true,
      nonce: challenge,
      iat: 1_899_999_900,
      exp: 2_000_000_000,
    });
    const googleSignature = new Uint8Array(
      await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        googleKeys.privateKey,
        encoder.encode(`${encodedHeader}.${encodedPayload}`),
      ),
    );
    const googleIdToken = [
      encodedHeader,
      encodedPayload,
      bytesToBase64Url(googleSignature),
    ].join(".");
    const binding = createSharingAccountBindingV1(
      challenge,
      googleIdToken,
      {
        credentialId: context.credentialId,
        credentialPublicKey,
        authenticatorData: bytesToBase64Url(authenticatorData),
        clientDataJSON: bytesToBase64Url(clientDataJSON),
        signature: bytesToBase64Url(p1363ToDer(rawSignature)),
      },
    );
    const fetch = vi.fn().mockResolvedValue(
      Response.json({ keys: [googleJwk] }),
    );

    await expect(
      verifySharingAccountBindingV1(binding, context, {
        googleAudience: "google-client-id",
        rpId: "example.test",
        allowedOrigins: ["https://example.test"],
        fetch,
        now: () => 1_900_000_000_000,
      }),
    ).resolves.toEqual({
      subject: "google-subject",
      audience: "google-client-id",
      email: "recipient@example.com",
    });
  });

  it("matches the Kotlin golden challenge", async () => {
    await expect(
      createSharingAccountBindingChallenge({
        appId: "fixture-app",
        exchangeId: "exchange-1",
        sharingKeyId: bytesToBase64Url(new Uint8Array(32).fill(9)),
        credentialId: "Y3JlZGVudGlhbC0x",
      }),
    ).resolves.toBe("F0Pvn8fvoDOa12henhD0jhdyLzQdMdOcEdrjSwu7-lU");
  });

  it("verifies the shared TS-Kotlin golden binding", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL("../fixtures/sharing-v1/account-binding.json", import.meta.url),
        "utf8",
      ),
    ) as {
      context: Parameters<typeof verifySharingAccountBindingV1>[1];
      verification: {
        googleAudience: string;
        rpId: string;
        allowedOrigins: string[];
        nowMillis: number;
      };
      jwks: { keys: JsonWebKey[] };
      binding: SharingAccountBindingV1;
    };
    await expect(
      verifySharingAccountBindingV1(fixture.binding, fixture.context, {
        googleAudience: fixture.verification.googleAudience,
        rpId: fixture.verification.rpId,
        allowedOrigins: fixture.verification.allowedOrigins,
        fetch: vi.fn().mockResolvedValue(Response.json(fixture.jwks)),
        jwksCache: new GoogleJwksCache(),
        now: () => fixture.verification.nowMillis,
      }),
    ).resolves.toMatchObject({ subject: "google-subject" });
  });

  it("rejects altered exchange context and WebAuthn policy failures", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL("../fixtures/sharing-v1/account-binding.json", import.meta.url),
        "utf8",
      ),
    ) as {
      context: Parameters<typeof verifySharingAccountBindingV1>[1];
      binding: SharingAccountBindingV1;
    };
    for (const field of ["appId", "exchangeId", "sharingKeyId", "credentialId"] as const) {
      await expect(
        verifySharingAccountBindingV1(
          fixture.binding,
          { ...fixture.context, [field]: `${fixture.context[field]}-altered` },
          {
            googleAudience: "google-client-id",
            rpId: "example.test",
            allowedOrigins: ["android:apk-key-hash:fixture-release"],
            fetch: vi.fn(),
          },
        ),
      ).rejects.toMatchObject({ code: "authorization" });
    }
    await expect(
      verifyPasskeyAssertion(fixture.binding.passkey, {
        challenge: fixture.binding.challenge,
        rpId: "other.test",
        allowedOrigins: ["android:apk-key-hash:fixture-release"],
      }),
    ).rejects.toMatchObject({ code: "authorization" });
    await expect(
      verifyPasskeyAssertion(fixture.binding.passkey, {
        challenge: fixture.binding.challenge,
        rpId: "example.test",
        allowedOrigins: ["android:apk-key-hash:debug"],
      }),
    ).rejects.toMatchObject({ code: "authorization" });
    const missingUv = structuredClone(fixture.binding.passkey);
    const authData = Buffer.from(missingUv.authenticatorData, "base64url");
    authData[32] = 0x01;
    missingUv.authenticatorData = authData.toString("base64url");
    await expect(
      verifyPasskeyAssertion(missingUv, {
        challenge: fixture.binding.challenge,
        rpId: "example.test",
        allowedOrigins: ["android:apk-key-hash:fixture-release"],
      }),
    ).rejects.toThrow("lacks user verification");
    const invalidSignature = structuredClone(fixture.binding.passkey);
    invalidSignature.signature = "MAQCAQECAQE";
    await expect(
      verifyPasskeyAssertion(invalidSignature, {
        challenge: fixture.binding.challenge,
        rpId: "example.test",
        allowedOrigins: ["android:apk-key-hash:fixture-release"],
      }),
    ).rejects.toMatchObject({ code: "compatibility" });
  });

  it("caches JWKS and refreshes once for an unknown kid", async () => {
    const { token, jwk } = await googleToken({ kid: "rotated-key" });
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json(
          { keys: [] },
          { headers: { "cache-control": "public, max-age=3600" } },
        ),
      )
      .mockResolvedValue(
        Response.json(
          { keys: [jwk] },
          { headers: { "cache-control": "public, max-age=3600" } },
        ),
      );
    const cache = new GoogleJwksCache();

    await expect(
      verifyGoogleIdToken(token, {
        audience: "google-client-id",
        nonce: "nonce-1",
        fetch,
        jwksCache: cache,
        now: () => 1_900_000_000_000,
      }),
    ).resolves.toMatchObject({ subject: "google-subject" });
    await verifyGoogleIdToken(token, {
      audience: "google-client-id",
      nonce: "nonce-1",
      fetch,
      jwksCache: cache,
      now: () => 1_900_000_000_000,
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("rejects a multi-audience token without matching azp", async () => {
    const { token, jwk } = await googleToken({
      kid: "fixture-key",
      aud: ["google-client-id", "another-client"],
    });
    await expect(
      verifyGoogleIdToken(token, {
        audience: "google-client-id",
        nonce: "nonce-1",
        fetch: vi.fn().mockResolvedValue(Response.json({ keys: [jwk] })),
        jwksCache: new GoogleJwksCache(),
        now: () => 1_900_000_000_000,
      }),
    ).rejects.toMatchObject({ code: "authorization" });
  });

  it.each([
    ["issuer", { iss: "https://attacker.example" }],
    ["audience", { aud: "wrong-client" }],
    ["nonce", { nonce: "wrong-nonce" }],
    ["expiration", { exp: 1_800_000_000 }],
  ])("rejects a Google token with the wrong %s", async (_label, claims) => {
    const { token, jwk } = await googleToken({ kid: "fixture-key", claims });
    await expect(
      verifyGoogleIdToken(token, {
        audience: "google-client-id",
        nonce: "nonce-1",
        fetch: vi.fn().mockResolvedValue(Response.json({ keys: [jwk] })),
        jwksCache: new GoogleJwksCache(),
        now: () => 1_900_000_000_000,
      }),
    ).rejects.toMatchObject({ code: "authorization" });
  });
});

async function googleToken(options: {
  kid: string;
  aud?: string | string[];
  claims?: Record<string, unknown>;
}): Promise<{ token: string; jwk: JsonWebKey & { kid: string } }> {
  const keys = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: Uint8Array.of(1, 0, 1),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const jwk = {
    ...(await crypto.subtle.exportKey("jwk", keys.publicKey)),
    kid: options.kid,
  };
  const header = encodeJwt({ alg: "RS256", kid: options.kid });
  const payload = encodeJwt({
    iss: "https://accounts.google.com",
    aud: options.aud ?? "google-client-id",
    sub: "google-subject",
    nonce: "nonce-1",
    iat: 1_899_999_900,
    exp: 2_000_000_000,
    ...options.claims,
  });
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      keys.privateKey,
      encoder.encode(`${header}.${payload}`),
    ),
  );
  return {
    token: `${header}.${payload}.${bytesToBase64Url(signature)}`,
    jwk,
  };
}

function encodeJwt(value: unknown): string {
  return bytesToBase64Url(encoder.encode(JSON.stringify(value)));
}

function p1363ToDer(signature: Uint8Array): Uint8Array {
  const r = derInteger(signature.slice(0, 32));
  const s = derInteger(signature.slice(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

function derInteger(input: Uint8Array): Uint8Array {
  let value = input;
  while (value.length > 1 && value[0] === 0) value = value.slice(1);
  const prefixed =
    (value[0] ?? 0) & 0x80 ? Uint8Array.of(0, ...value) : value;
  return Uint8Array.of(0x02, prefixed.length, ...prefixed);
}
