import { defineV1CompatibilityProfile } from "../src/crypto/index.js";

export const easyBcTestProfile = defineV1CompatibilityProfile({
  appId: "easy-bc",
  filename: "easybc-sync-v1.json",
  aad: "easy-bc-sync-envelope-v1",
  hkdfInfo: "easy-bc-cloud-content-key-v1",
  compression: "gzip-if-smaller",
  passkey: {
    rpName: "EasyBC",
    userName: "encrypted-sync",
    userDisplayName: "EasyBC encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
});

export const familyChoresTestProfile = defineV1CompatibilityProfile({
  appId: "family-chores",
  filename: "family-chores-sync-v1.json",
  aad: "family-chores-sync-envelope-v1",
  hkdfInfo: "family-chores-cloud-content-key-v1",
  compression: "none",
  passkey: {
    rpName: "Family Chores",
    userName: "encrypted-sync",
    userDisplayName: "Family Chores encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
});
