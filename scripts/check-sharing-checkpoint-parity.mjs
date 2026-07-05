import { readFile } from "node:fs/promises";

const root = new URL("..", import.meta.url);
await readFile(new URL("fixtures/sharing-checkpoint.schema.json", root), "utf8");

const sampleCheckpoint = {
  lastPollAt: "2026-07-01T12:00:00.000Z",
  lastSeenKeyResponseFileIds: ["response-1"],
  datasetHeads: {
    tasks: {
      datasetId: "tasks",
      fileId: "file-1",
      etag: '"1"',
      modifiedTime: "2026-07-01T11:00:00.000Z",
    },
  },
};

const sampleEvents = [
  {
    kind: "pending-key-response",
    exchangeId: "exchange-1",
    fileId: "response-2",
  },
  {
    kind: "shared-dataset-changed",
    datasetId: "tasks",
    fileId: "file-1",
  },
  { kind: "token-expiring-soon", expiresAt: "2026-07-01T12:55:00.000Z" },
  { kind: "token-expired" },
];

assertCheckpoint(sampleCheckpoint);
for (const event of sampleEvents) {
  assertNotificationEvent(event);
}

const kotlinPath = new URL(
  "android/synckit/src/main/java/com/keyneom/synckit/sharing/checkpoint/SharingSyncCheckpoint.kt",
  root,
);
try {
  const kotlinSource = await readFile(kotlinPath, "utf8");
  for (const field of [
    "lastPollAt",
    "lastSeenKeyResponseFileIds",
    "datasetHeads",
    "PendingKeyResponse",
    "SharedDatasetChanged",
    "TokenExpiringSoon",
    "TokenExpired",
  ]) {
    if (!kotlinSource.includes(field)) {
      throw new Error(`Kotlin checkpoint source is missing ${field}.`);
    }
  }
} catch (error) {
  if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
    throw new Error(
      "Kotlin SharingSyncCheckpoint.kt is required for sharing checkpoint parity.",
    );
  }
  throw error;
}

console.log("Sharing checkpoint schema parity verified.");

function assertCheckpoint(value) {
  assertObject(value, "checkpoint");
  if (value.lastPollAt !== undefined && typeof value.lastPollAt !== "string") {
    throw new Error("checkpoint.lastPollAt must be a string.");
  }
  if (value.lastSeenKeyResponseFileIds !== undefined) {
    if (!Array.isArray(value.lastSeenKeyResponseFileIds)) {
      throw new Error("checkpoint.lastSeenKeyResponseFileIds must be an array.");
    }
    for (const fileId of value.lastSeenKeyResponseFileIds) {
      if (typeof fileId !== "string" || fileId.length === 0) {
        throw new Error("checkpoint.lastSeenKeyResponseFileIds entries must be strings.");
      }
    }
  }
  if (value.datasetHeads !== undefined) {
    assertObject(value.datasetHeads, "checkpoint.datasetHeads");
    for (const head of Object.values(value.datasetHeads)) {
      assertDatasetHead(head);
    }
  }
}

function assertDatasetHead(value) {
  assertObject(value, "dataset head");
  requireString(value.datasetId, "datasetId");
  requireString(value.fileId, "fileId");
  for (const field of ["modifiedTime", "version", "headRevisionId", "etag"]) {
    if (value[field] !== undefined && typeof value[field] !== "string") {
      throw new Error(`dataset head ${field} must be a string.`);
    }
  }
}

function assertNotificationEvent(value) {
  assertObject(value, "notification event");
  requireString(value.kind, "kind");
  switch (value.kind) {
    case "pending-key-response":
      requireString(value.exchangeId, "exchangeId");
      requireString(value.fileId, "fileId");
      break;
    case "shared-dataset-changed":
      requireString(value.datasetId, "datasetId");
      requireString(value.fileId, "fileId");
      break;
    case "token-expiring-soon":
      requireString(value.expiresAt, "expiresAt");
      break;
    case "token-expired":
      break;
    default:
      throw new Error(`Unsupported notification event kind ${value.kind}.`);
  }
}

function assertObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
}

function requireString(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be a non-empty string.`);
  }
}
