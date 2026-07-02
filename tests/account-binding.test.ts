import { describe, expect, it, vi } from "vitest";
import { bytesToBase64Url } from "../src/crypto/base64url.js";
import {
  createSharingAccountBindingChallenge,
  createSharingAccountBindingV1,
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
});

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
