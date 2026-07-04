import { mkdir, writeFile } from "node:fs/promises";
import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
} from "node:crypto";
import { gunzipSync } from "node:zlib";

const outputDirectory = new URL("../fixtures/v1/", import.meta.url);
const algorithm = "AES-256-GCM+HKDF-SHA-256";
const secret = sequence(0, 32);
const salt = sequence(32, 32);
const nonce = sequence(64, 12);
const prfInput = sequence(96, 32);

const easyBcProfile = {
  appId: "easy-bc",
  filename: "easybc-sync-v1.json",
  aad: "easy-bc-sync-envelope-v1",
  hkdfInfo: "easy-bc-cloud-content-key-v1",
  compression: "gzip-if-smaller",
  algorithm,
  schemaVersion: 1,
  nonceBytes: 12,
  kdfSaltBytes: 32,
  prfInputBytes: 32,
  tagBits: 128,
  passkey: {
    rpId: "keyneom.github.io",
    rpName: "EasyBC",
    userName: "encrypted-sync",
    userDisplayName: "EasyBC encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
};

const familyChoresProfile = {
  appId: "family-chores",
  filename: "family-chores-sync-v1.json",
  aad: "family-chores-sync-envelope-v1",
  hkdfInfo: "family-chores-cloud-content-key-v1",
  compression: "none",
  algorithm,
  schemaVersion: 1,
  nonceBytes: 12,
  kdfSaltBytes: 32,
  prfInputBytes: 32,
  tagBits: 128,
  passkey: {
    rpId: "keyneom.github.io",
    rpName: "Family Chores",
    userName: "encrypted-sync",
    userDisplayName: "Family Chores encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
};

const easyBcPrfInput = toBase64Url(prfInput);

const easyBcUncompressedEnvelope = {
  schemaVersion: 1,
  algorithm,
  credentialId: "credential",
  rpId: "keyneom.github.io",
  prfInput: easyBcPrfInput,
  kdfSalt: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
  nonce: "QEFCQ0RFRkdISUpL",
  ciphertext:
    "SGk1csrcbFdGshJaXqUdM-SLg9O0ZjtkHuUREJkV5R89VrpDkTmr12IlZ5W6d4Qk4pQ0kVT9XO7F_r4OHtoWNGbjzrdv49y2LhT-uDLjzNu38r-xVoQXGU3HTJdvr6VFk18TbaKAN08gD3wluMP9JH_IKwpGHeAgZyoajp3agwg4bGV-VSw9URAFlHrXtgJKymwNPz_4E4UHbmjcnCK94JngZgqYXnhBueTwX4fTayIrzqXl_JEcGDm6aEcae_FoqhZ1dVUVx5KynVj_JRgPMKOtviGe-LLk7aXbCoRLxSjZDU4nlPQOV2dFkbrwpV6afwsu1IQWwZ-xvnDovfN8eHzVuvdb7JgSIShs62Yy5N-wgCm-BUWxHp5oq0LUFkGB2njyTQjkmSYBiM4eVOYvhBTIRNQZqFMXSEI32-NyCEaLvv63y43OkQ9-kpWKZ7-yDpM-Mcs5ckNk3IKTHTGhl_0DMpZxA5QONtGvDCW4SHr8dKEQ6aDQ",
  updatedAt: "2026-06-21T12:00:00Z",
};

const easyBcGzipEnvelope = {
  schemaVersion: 1,
  algorithm,
  compression: "gzip",
  credentialId: "credential",
  rpId: "keyneom.github.io",
  prfInput: easyBcPrfInput,
  kdfSalt: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
  nonce: "QEFCQ0RFRkdISUpL",
  ciphertext:
    "LMBOEaK5ATYQxI26eKGwIdJ_ELsBJ8rf76MIXyxVsT3kN1K3qY42h07AZHOYkztpJYdhERCZmbG2j_Pd1zhqKRMIMdrj_-pBd6DljWZU0uD7d5rHWCbyAqudt_psdPSHm47MuQauJTsCjVmEkPNKCZZNOZkYnceNyC9MZQM_tY15jJLsHEdOnQS43zyNhv180UmM9POJcsaWBAG6yIfDRDpd2b1IpPuxmIAV3GLMYLiNHbJ4yDUX6PRYFhzI-Hh18rggXBENhWfq9kZ3hBpPKGkms-j4MHFIGhg_o3GY_rZTHCzq3phTdD3Mo4iSWf7D6FXezQP6H_jwyhDE0ydJyTjNfIPPyCESZtc",
  updatedAt: "2026-06-22T12:00:00Z",
};

const familyChoresPayload = {
  schemaVersion: 1,
  exportedAt: "2026-06-21T00:00:00.000Z",
  state: {
    children: [],
    tasks: [],
    taskInstances: [],
    completedTasks: {},
    timers: {},
    timedCompletions: [],
    actionLog: [],
    parentSettings: {
      approvals: { task: false, reward: false },
      timedAutoApproveDefault: false,
      pins: [],
      childDisplayOrder: [],
      onboardingCompleted: false,
      voiceAnnouncements: false,
    },
  },
  metadata: {
    schemaVersion: 1,
    collections: Object.fromEntries(
      [
        "children",
        "tasks",
        "taskInstances",
        "completedTasks",
        "timers",
        "timedCompletions",
        "actionLog",
      ].map((collection) => [
        collection,
        { updatedAt: {}, deletedAt: {} },
      ]),
    ),
    parentSettingsUpdatedAt: "1970-01-01T00:00:00.000Z",
  },
};

await mkdir(outputDirectory, { recursive: true });

const easyBcUncompressedPayload = decryptFixture(
  easyBcProfile,
  easyBcUncompressedEnvelope,
  secret,
);
const easyBcGzipPayload = decryptFixture(
  easyBcProfile,
  easyBcGzipEnvelope,
  secret,
);
const familyChoresEnvelope = encryptFixture(
  familyChoresProfile,
  familyChoresPayload,
  secret,
  {
    credentialId: "fixture-credential",
    rpId: "keyneom.github.io",
    prfInput,
    salt,
    nonce,
  },
);

const badGzipEnvelope = encryptBytes(
  easyBcProfile,
  Buffer.from("authenticated plaintext that is not a gzip stream"),
  secret,
  {
    credentialId: "fixture-credential",
    rpId: "keyneom.github.io",
    prfInput,
    salt,
    nonce,
    compression: "gzip",
    updatedAt: "2026-06-29T00:00:00.000Z",
  },
);

await writeJson("profiles.json", {
  generatedAt: "2026-06-29",
  profiles: [easyBcProfile, familyChoresProfile],
});
await writeJson("easybc-web-uncompressed.json", {
  provenance:
    "EasyBC Android SyncCryptoTest.decryptsWebCryptoVector and live web crypto.ts",
  secret: toBase64Url(secret),
  payload: easyBcUncompressedPayload,
  envelope: easyBcUncompressedEnvelope,
});
await writeJson("easybc-web-android-gzip.json", {
  provenance:
    "Shared by live EasyBC web crypto.test.ts and Android SyncCryptoTest.decryptsSharedGzipCryptoVector",
  secret: toBase64Url(secret),
  payload: easyBcGzipPayload,
  envelope: easyBcGzipEnvelope,
});
await writeJson("family-chores-web-uncompressed.json", {
  provenance:
    "Generated from the uncommitted live Family Chores sync implementation",
  secret: toBase64Url(secret),
  payload: familyChoresPayload,
  envelope: familyChoresEnvelope,
});
await writeJson("failures.json", {
  wrongSecret: toBase64Url(sequence(224, 32)),
  tamperedEnvelope: {
    ...easyBcUncompressedEnvelope,
    ciphertext: replaceFirstCharacter(easyBcUncompressedEnvelope.ciphertext),
  },
  wrongContextEnvelope: familyChoresEnvelope,
  malformedEnvelope: {
    schemaVersion: 1,
    algorithm,
    credentialId: "fixture-credential",
  },
  decompressionErrorEnvelope: badGzipEnvelope,
});

function decryptFixture(profile, envelope, inputKeyMaterial) {
  const key = deriveKey(profile, inputKeyMaterial, fromBase64Url(envelope.kdfSalt));
  const encrypted = fromBase64Url(envelope.ciphertext);
  const ciphertext = encrypted.subarray(0, -16);
  const tag = encrypted.subarray(-16);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    fromBase64Url(envelope.nonce),
  );
  decipher.setAAD(Buffer.from(profile.aad));
  decipher.setAuthTag(tag);
  let plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  if (envelope.compression === "gzip") plaintext = gunzipSync(plaintext);
  return JSON.parse(plaintext.toString("utf8"));
}

function encryptFixture(profile, payload, inputKeyMaterial, options) {
  return encryptBytes(
    profile,
    Buffer.from(JSON.stringify(payload)),
    inputKeyMaterial,
    { ...options, updatedAt: payload.exportedAt },
  );
}

function encryptBytes(profile, plaintext, inputKeyMaterial, options) {
  const key = deriveKey(profile, inputKeyMaterial, options.salt);
  const cipher = createCipheriv("aes-256-gcm", key, options.nonce);
  cipher.setAAD(Buffer.from(profile.aad));
  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return {
    schemaVersion: 1,
    algorithm,
    ...(options.compression ? { compression: options.compression } : {}),
    credentialId: options.credentialId,
    rpId: options.rpId,
    prfInput: toBase64Url(options.prfInput),
    kdfSalt: toBase64Url(options.salt),
    nonce: toBase64Url(options.nonce),
    ciphertext: toBase64Url(encrypted),
    updatedAt: options.updatedAt,
  };
}

function deriveKey(profile, inputKeyMaterial, kdfSalt) {
  return hkdfSync(
    "sha256",
    inputKeyMaterial,
    kdfSalt,
    Buffer.from(profile.hkdfInfo),
    32,
  );
}

function sequence(start, length) {
  return Buffer.from(
    Array.from({ length }, (_, index) => (start + index) & 0xff),
  );
}

function toBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function fromBase64Url(value) {
  return Buffer.from(value, "base64url");
}

function replaceFirstCharacter(value) {
  return `${value.startsWith("A") ? "B" : "A"}${value.slice(1)}`;
}

async function writeJson(filename, value) {
  await writeFile(
    new URL(filename, outputDirectory),
    `${JSON.stringify(value, null, 2)}\n`,
  );
}
