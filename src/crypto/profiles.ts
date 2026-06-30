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

export const easyBcV1Profile = {
  appId: "easy-bc",
  filename: "easybc-sync-v1.json",
  aad: "easy-bc-sync-envelope-v1",
  hkdfInfo: "easy-bc-cloud-content-key-v1",
  algorithm: V1_ALGORITHM,
  readVersions: [1],
  writeVersion: 1,
  compression: "gzip-if-smaller",
  nonceBytes: 12,
  kdfSaltBytes: 32,
  prfInputBytes: 32,
  tagBits: 128,
  passkey: {
    rpName: "EasyBC",
    userName: "encrypted-sync",
    userDisplayName: "EasyBC encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
} as const satisfies V1CompatibilityProfile;

export const familyChoresV1Profile = {
  appId: "family-chores",
  filename: "family-chores-sync-v1.json",
  aad: "family-chores-sync-envelope-v1",
  hkdfInfo: "family-chores-cloud-content-key-v1",
  algorithm: V1_ALGORITHM,
  readVersions: [1],
  writeVersion: 1,
  compression: "none",
  nonceBytes: 12,
  kdfSaltBytes: 32,
  prfInputBytes: 32,
  tagBits: 128,
  passkey: {
    rpName: "Family Chores",
    userName: "encrypted-sync",
    userDisplayName: "Family Chores encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
} as const satisfies V1CompatibilityProfile;
