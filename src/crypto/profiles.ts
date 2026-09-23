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
  /** Snapshot versions this app reads. Always includes 1. */
  readVersions: readonly (1 | 2)[];
  /** The version a new snapshot is written in. Ordinary sync keeps a snapshot's own version. */
  writeVersion: 1 | 2;
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
> & {
  /**
   * Defaults to `[1]`. Add 2 once every device of this app runs a sync-kit
   * that reads v2; that is the first step of a staged rollout.
   */
  readVersions?: readonly (1 | 2)[];
  /**
   * Defaults to 1. Set 2 only after every device reads v2. It affects new
   * snapshots; an existing snapshot changes version only through an explicit
   * `migrateVersion` or `setRecoveryCode`. See docs/snapshot-recovery.md.
   */
  writeVersion?: 1 | 2;
};

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
  const requested: readonly (1 | 2)[] = input.readVersions ?? [1];
  const readVersions = Object.freeze([...new Set(requested)].sort((left, right) => left - right));
  const writeVersion = input.writeVersion ?? 1;
  if (!readVersions.includes(1)) {
    throw new TypeError("readVersions must include 1: v1 snapshots stay readable indefinitely.");
  }
  if (readVersions.some((version) => version !== 1 && version !== 2)) {
    throw new TypeError("readVersions may contain only 1 and 2.");
  }
  if (!readVersions.includes(writeVersion)) {
    throw new TypeError("writeVersion must be one of readVersions.");
  }
  return Object.freeze({
    ...input,
    passkey: Object.freeze({ ...input.passkey }),
    algorithm: V1_ALGORITHM,
    readVersions,
    writeVersion,
    nonceBytes: 12,
    kdfSaltBytes: 32,
    prfInputBytes: 32,
    tagBits: 128,
  });
}
