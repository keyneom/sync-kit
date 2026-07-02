import { SyncKitError } from "../core/errors.js";
import { base64UrlToBytes, bytesToBase64Url } from "../crypto/base64url.js";
import { canonicalAad } from "../crypto/canonical.js";
import { copyBuffer } from "../crypto/runtime.js";
import type {
  SharingAccountBindingV1,
  SharingPasskeyAssertionV1,
} from "./index.js";

const GOOGLE_CERTS = "https://www.googleapis.com/oauth2/v3/certs";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type SharingAccountBindingContext = {
  appId: string;
  exchangeId: string;
  sharingKeyId: string;
  credentialId: string;
};

export type VerifiedGoogleAccount = {
  subject: string;
  audience: string;
  email?: string;
};

export async function createBackendlessSharingAccountBinding(
  context: Omit<SharingAccountBindingContext, "credentialId">,
  options: {
    credential(): Promise<{
      credentialId: string;
      credentialPublicKey: JsonWebKey;
    }>;
    requestGoogleIdToken(nonce: string): Promise<string>;
    rpId: string;
    timeoutMs?: number;
    navigator?: Navigator;
    crypto?: Crypto;
  },
): Promise<SharingAccountBindingV1> {
  const credential = await options.credential();
  const challenge = await createSharingAccountBindingChallenge(
    {
      ...context,
      credentialId: credential.credentialId,
    },
    options.crypto ?? globalThis.crypto,
  );
  const passkey = await getSharingPasskeyAssertion({
    challenge,
    rpId: options.rpId,
    credentialId: credential.credentialId,
    credentialPublicKey: credential.credentialPublicKey,
    ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.navigator ? { navigator: options.navigator } : {}),
  });
  const googleIdToken = await options.requestGoogleIdToken(challenge);
  return createSharingAccountBindingV1(
    challenge,
    googleIdToken,
    passkey,
  );
}

export async function createSharingAccountBindingChallenge(
  context: SharingAccountBindingContext,
  cryptoImplementation: Crypto = globalThis.crypto,
): Promise<string> {
  for (const [name, value] of Object.entries(context)) {
    if (!value.trim()) throw new TypeError(`${name} must not be empty.`);
  }
  return bytesToBase64Url(
    new Uint8Array(
      await cryptoImplementation.subtle.digest(
        "SHA-256",
        copyBuffer(canonicalAad(context)),
      ),
    ),
  );
}

export function createSharingAccountBindingV1(
  challenge: string,
  googleIdToken: string,
  passkey: SharingPasskeyAssertionV1,
): SharingAccountBindingV1 {
  if (base64UrlToBytes(challenge).length !== 32) {
    throw new TypeError("challenge must be a SHA-256 value.");
  }
  if (!googleIdToken.trim()) {
    throw new TypeError("googleIdToken must not be empty.");
  }
  return {
    schemaVersion: 1,
    kind: "sync-kit-sharing-account-binding",
    challenge,
    googleIdToken,
    passkey,
  };
}

export async function verifySharingAccountBindingV1(
  binding: SharingAccountBindingV1,
  context: SharingAccountBindingContext,
  options: {
    googleAudience: string;
    rpId: string;
    allowedOrigins: string[];
    requireUserVerification?: boolean;
    fetch?: typeof fetch;
    crypto?: Crypto;
    now?: () => number;
  },
): Promise<VerifiedGoogleAccount> {
  const cryptoImplementation = options.crypto ?? globalThis.crypto;
  const expectedChallenge = await createSharingAccountBindingChallenge(
    context,
    cryptoImplementation,
  );
  if (
    binding.challenge !== expectedChallenge ||
    binding.passkey.credentialId !== context.credentialId
  ) {
    throw new SyncKitError(
      "authorization",
      "The account binding does not match this exchange and sharing key.",
    );
  }
  await verifyPasskeyAssertion(binding.passkey, {
    challenge: expectedChallenge,
    rpId: options.rpId,
    allowedOrigins: options.allowedOrigins,
    requireUserVerification: options.requireUserVerification ?? true,
    crypto: cryptoImplementation,
  });
  return verifyGoogleIdToken(binding.googleIdToken, {
    audience: options.googleAudience,
    nonce: expectedChallenge,
    ...(options.fetch ? { fetch: options.fetch } : {}),
    crypto: cryptoImplementation,
    ...(options.now ? { now: options.now } : {}),
  });
}

export async function getSharingPasskeyAssertion(
  input: {
    challenge: string;
    rpId: string;
    credentialId: string;
    credentialPublicKey: JsonWebKey;
    timeoutMs?: number;
    navigator?: Navigator;
  },
): Promise<SharingPasskeyAssertionV1> {
  const navigatorImplementation =
    input.navigator ??
    (typeof navigator === "undefined" ? undefined : navigator);
  if (!navigatorImplementation?.credentials) {
    throw new SyncKitError(
      "configuration",
      "WebAuthn credentials are unavailable.",
    );
  }
  const credential = await navigatorImplementation.credentials.get({
    publicKey: {
      challenge: copyBuffer(base64UrlToBytes(input.challenge)),
      rpId: input.rpId,
      allowCredentials: [
        {
          type: "public-key",
          id: copyBuffer(base64UrlToBytes(input.credentialId)),
        },
      ],
      userVerification: "required",
      timeout: input.timeoutMs ?? 60_000,
    },
  });
  if (
    !credential ||
    !("rawId" in credential) ||
    !("response" in credential)
  ) {
    throw new SyncKitError(
      "key",
      "The passkey assertion was cancelled.",
    );
  }
  const publicKeyCredential = credential as PublicKeyCredential;
  const response =
    publicKeyCredential.response as AuthenticatorAssertionResponse;
  return {
    credentialId: bytesToBase64Url(
      new Uint8Array(publicKeyCredential.rawId),
    ),
    credentialPublicKey: input.credentialPublicKey,
    authenticatorData: bytesToBase64Url(
      new Uint8Array(response.authenticatorData),
    ),
    clientDataJSON: bytesToBase64Url(
      new Uint8Array(response.clientDataJSON),
    ),
    signature: bytesToBase64Url(new Uint8Array(response.signature)),
  };
}

export async function verifyPasskeyAssertion(
  assertion: SharingPasskeyAssertionV1,
  options: {
    challenge: string;
    rpId: string;
    allowedOrigins: string[];
    requireUserVerification?: boolean;
    crypto?: Crypto;
  },
): Promise<void> {
  const cryptoImplementation = options.crypto ?? globalThis.crypto;
  const clientDataBytes = base64UrlToBytes(assertion.clientDataJSON);
  let clientData: unknown;
  try {
    clientData = JSON.parse(decoder.decode(clientDataBytes)) as unknown;
  } catch (error) {
    throw new SyncKitError(
      "compatibility",
      "The WebAuthn client data is invalid.",
      { cause: error },
    );
  }
  if (
    !clientData ||
    typeof clientData !== "object" ||
    Array.isArray(clientData)
  ) {
    throw new SyncKitError(
      "compatibility",
      "The WebAuthn client data is malformed.",
    );
  }
  const client = clientData as Record<string, unknown>;
  if (
    client.type !== "webauthn.get" ||
    client.challenge !== options.challenge ||
    typeof client.origin !== "string" ||
    !options.allowedOrigins.includes(client.origin)
  ) {
    throw new SyncKitError(
      "authorization",
      "The WebAuthn assertion context is invalid.",
    );
  }
  const authenticatorData = base64UrlToBytes(assertion.authenticatorData);
  if (authenticatorData.length < 37) {
    throw new SyncKitError(
      "compatibility",
      "The WebAuthn authenticator data is truncated.",
    );
  }
  const expectedRpHash = new Uint8Array(
    await cryptoImplementation.subtle.digest(
      "SHA-256",
      copyBuffer(encoder.encode(options.rpId)),
    ),
  );
  if (!equalBytes(authenticatorData.slice(0, 32), expectedRpHash)) {
    throw new SyncKitError(
      "authorization",
      "The WebAuthn assertion belongs to another relying party.",
    );
  }
  const flags = authenticatorData[32] ?? 0;
  if ((flags & 0x01) === 0) {
    throw new SyncKitError(
      "authorization",
      "The WebAuthn assertion lacks user presence.",
    );
  }
  if ((options.requireUserVerification ?? true) && (flags & 0x04) === 0) {
    throw new SyncKitError(
      "authorization",
      "The WebAuthn assertion lacks user verification.",
    );
  }
  const clientDataHash = new Uint8Array(
    await cryptoImplementation.subtle.digest(
      "SHA-256",
      copyBuffer(clientDataBytes),
    ),
  );
  const signed = new Uint8Array(
    authenticatorData.length + clientDataHash.length,
  );
  signed.set(authenticatorData);
  signed.set(clientDataHash, authenticatorData.length);
  const publicKey = assertion.credentialPublicKey;
  if (
    publicKey.kty !== "EC" ||
    publicKey.crv !== "P-256" ||
    !publicKey.x ||
    !publicKey.y
  ) {
    throw new SyncKitError(
      "compatibility",
      "The passkey public key must be an ES256 P-256 JWK.",
    );
  }
  const imported = await cryptoImplementation.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: publicKey.x,
      y: publicKey.y,
      ext: true,
      key_ops: ["verify"],
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const valid = await cryptoImplementation.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    imported,
    copyBuffer(derEcdsaToP1363(base64UrlToBytes(assertion.signature), 32)),
    copyBuffer(signed),
  );
  if (!valid) {
    throw new SyncKitError(
      "authorization",
      "The WebAuthn assertion signature is invalid.",
    );
  }
}

export async function verifyGoogleIdToken(
  token: string,
  options: {
    audience: string;
    nonce: string;
    fetch?: typeof fetch;
    crypto?: Crypto;
    now?: () => number;
  },
): Promise<VerifiedGoogleAccount> {
  const cryptoImplementation = options.crypto ?? globalThis.crypto;
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new SyncKitError(
      "compatibility",
      "The Google ID token is not a JWT.",
    );
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw new SyncKitError(
      "compatibility",
      "The Google ID token is incomplete.",
    );
  }
  const header = parseJwtObject(encodedHeader, "header");
  const claims = parseJwtObject(encodedPayload, "claims");
  if (
    header.alg !== "RS256" ||
    typeof header.kid !== "string" ||
    !header.kid
  ) {
    throw new SyncKitError(
      "compatibility",
      "The Google ID token algorithm is unsupported.",
    );
  }
  const fetchImplementation = options.fetch ?? globalThis.fetch;
  if (!fetchImplementation) {
    throw new SyncKitError(
      "configuration",
      "Fetch is required to verify Google identity tokens.",
    );
  }
  const response = await fetchImplementation(GOOGLE_CERTS);
  if (!response.ok) {
    throw new SyncKitError(
      "provider",
      `Google signing keys could not be loaded (${response.status}).`,
      { status: response.status },
    );
  }
  const keySet = (await response.json()) as {
    keys?: (JsonWebKey & { kid?: string })[];
  };
  const jwk = keySet.keys?.find((key) => key.kid === header.kid);
  if (!jwk) {
    throw new SyncKitError(
      "authorization",
      "The Google ID token signing key is unknown.",
    );
  }
  const key = await cryptoImplementation.subtle.importKey(
    "jwk",
    { ...jwk, key_ops: ["verify"], ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await cryptoImplementation.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    copyBuffer(base64UrlToBytes(encodedSignature)),
    copyBuffer(encoder.encode(`${encodedHeader}.${encodedPayload}`)),
  );
  if (!valid) {
    throw new SyncKitError(
      "authorization",
      "The Google ID token signature is invalid.",
    );
  }
  const nowSeconds = Math.floor((options.now?.() ?? Date.now()) / 1_000);
  const audiences = Array.isArray(claims.aud)
    ? claims.aud
    : [claims.aud];
  if (
    (claims.iss !== "https://accounts.google.com" &&
      claims.iss !== "accounts.google.com") ||
    !audiences.includes(options.audience) ||
    typeof claims.exp !== "number" ||
    claims.exp <= nowSeconds ||
    claims.nonce !== options.nonce ||
    typeof claims.sub !== "string" ||
    !claims.sub
  ) {
    throw new SyncKitError(
      "authorization",
      "The Google ID token claims do not match this account binding.",
    );
  }
  if (
    claims.email !== undefined &&
    (typeof claims.email !== "string" ||
      claims.email_verified !== true)
  ) {
    throw new SyncKitError(
      "authorization",
      "The Google ID token email is not verified.",
    );
  }
  return {
    subject: claims.sub,
    audience: options.audience,
    ...(typeof claims.email === "string"
      ? { email: claims.email }
      : {}),
  };
}

function parseJwtObject(
  encoded: string,
  label: string,
): Record<string, unknown> {
  try {
    const value = JSON.parse(
      decoder.decode(base64UrlToBytes(encoded)),
    ) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new TypeError("not an object");
    }
    return value as Record<string, unknown>;
  } catch (error) {
    throw new SyncKitError(
      "compatibility",
      `The Google ID token ${label} is invalid.`,
      { cause: error },
    );
  }
}

function derEcdsaToP1363(der: Uint8Array, width: number): Uint8Array {
  let offset = 0;
  if (der[offset++] !== 0x30) throw invalidDer();
  const sequenceLength = readDerLength(der, offset);
  offset = sequenceLength.offset;
  if (sequenceLength.length !== der.length - offset) throw invalidDer();
  if (der[offset++] !== 0x02) throw invalidDer();
  const rLength = readDerLength(der, offset);
  offset = rLength.offset;
  const r = der.slice(offset, offset + rLength.length);
  offset += rLength.length;
  if (der[offset++] !== 0x02) throw invalidDer();
  const sLength = readDerLength(der, offset);
  offset = sLength.offset;
  const s = der.slice(offset, offset + sLength.length);
  offset += sLength.length;
  if (offset !== der.length) throw invalidDer();
  const result = new Uint8Array(width * 2);
  result.set(normalizeInteger(r, width), 0);
  result.set(normalizeInteger(s, width), width);
  return result;
}

function readDerLength(
  value: Uint8Array,
  offset: number,
): { length: number; offset: number } {
  const first = value[offset];
  if (first === undefined) throw invalidDer();
  if ((first & 0x80) === 0) return { length: first, offset: offset + 1 };
  const bytes = first & 0x7f;
  if (bytes === 0 || bytes > 2 || offset + bytes >= value.length) {
    throw invalidDer();
  }
  let length = 0;
  for (let index = 0; index < bytes; index += 1) {
    length = (length << 8) | (value[offset + 1 + index] ?? 0);
  }
  return { length, offset: offset + 1 + bytes };
}

function normalizeInteger(value: Uint8Array, width: number): Uint8Array {
  let normalized = value;
  while (normalized.length > 1 && normalized[0] === 0) {
    normalized = normalized.slice(1);
  }
  if (normalized.length > width) throw invalidDer();
  const result = new Uint8Array(width);
  result.set(normalized, width - normalized.length);
  return result;
}

function invalidDer(): SyncKitError {
  return new SyncKitError(
    "compatibility",
    "The WebAuthn ECDSA signature is malformed.",
  );
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
