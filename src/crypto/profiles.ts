export const V1_ALGORITHM = "AES-256-GCM+HKDF-SHA-256" as const;

export type V1Compression = "none" | "gzip-if-smaller";

export type PasskeyProfile = {
  rpName: string;
  userName: string;
  userDisplayName: string;
  algorithm: -7;
  residentKey: "required";
  userVerification: "required";
  timeoutMs: number;
};

export type V1CompatibilityProfile = {
  appId: string;
  filename: string;
  aad: string;
  hkdfInfo: string;
  algorithm: typeof V1_ALGORITHM;
  readVersions: readonly [1];
  writeVersion: 1;
  compression: V1Compression;
  nonceBytes: 12;
  kdfSaltBytes: 32;
  prfInputBytes: 32;
  tagBits: 128;
  passkey: PasskeyProfile;
};

export type V1CompatibilityProfileInput = Pick<
  V1CompatibilityProfile,
  "appId" | "filename" | "aad" | "hkdfInfo" | "compression" | "passkey"
>;

/**
 * Creates a consumer-owned v1 profile while fixing protocol-level constants.
 * Application profiles are configuration, not package presets.
 */
export function defineV1CompatibilityProfile(
  input: V1CompatibilityProfileInput,
): Readonly<V1CompatibilityProfile> {
  for (const [name, value] of Object.entries({
    appId: input.appId,
    filename: input.filename,
    aad: input.aad,
    hkdfInfo: input.hkdfInfo,
    rpName: input.passkey.rpName,
    userName: input.passkey.userName,
    userDisplayName: input.passkey.userDisplayName,
  })) {
    if (!value.trim()) throw new TypeError(`${name} must not be empty.`);
  }
  if (
    !Number.isFinite(input.passkey.timeoutMs) ||
    input.passkey.timeoutMs <= 0
  ) {
    throw new TypeError("passkey.timeoutMs must be positive.");
  }
  return Object.freeze({
    ...input,
    passkey: Object.freeze({ ...input.passkey }),
    algorithm: V1_ALGORITHM,
    readVersions: [1] as const,
    writeVersion: 1,
    nonceBytes: 12,
    kdfSaltBytes: 32,
    prfInputBytes: 32,
    tagBits: 128,
  });
}
