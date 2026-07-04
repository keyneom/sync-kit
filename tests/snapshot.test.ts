import { describe, expect, it, vi } from "vitest";
import {
  createSnapshotSync,
  type SnapshotSyncOptions,
} from "../src/snapshot/index.js";

type Value = { revision: number; exportedAt: string };
type Envelope = {
  value: Value;
  keyId: string;
  updatedAt: string;
};
type Metadata = { keyId: string };
type Authorization = { token: string };

function harness(
  initial: Envelope | null,
  local: Value = value(1),
): {
  controller: ReturnType<
    typeof createSnapshotSync<Value, Envelope, string, Metadata, Authorization>
  >;
  state: {
    remote: Envelope | null;
    writes: number;
    deletes: number;
    unlocks: number;
    clears: number;
    authorizations: number;
    applied: Value[];
  };
} {
  const state = {
    remote: initial,
    writes: 0,
    deletes: 0,
    unlocks: 0,
    clears: 0,
    authorizations: 0,
    applied: [] as Value[],
  };
  const options: SnapshotSyncOptions<
    Value,
    Envelope,
    string,
    Metadata,
    Authorization
  > = {
    appId: "fixture",
    codec: {
      serialize: (item) => item,
      parse: (item) => item as Value,
      merge: (left, right) =>
        left.revision >= right.revision ? left : right,
      fingerprint: (item) => String(item.revision),
      updatedAt: (item) => item.exportedAt,
    },
    envelopeCrypto: {
      encrypt: async (item, _key, metadata) => ({
        value: item,
        keyId: metadata.keyId,
        updatedAt: item.exportedAt,
      }),
      decrypt: async (envelope) => envelope.value,
      metadataFromEnvelope: (envelope) => ({ keyId: envelope.keyId }),
    },
    keyProvider: {
      create: async () => ({
        metadata: { keyId: "created-key" },
        key: "created-key",
      }),
      unlock: async (envelope) => {
        state.unlocks += 1;
        return envelope.keyId;
      },
      clear: () => {
        state.clears += 1;
      },
    },
    authorizationProvider: {
      authorize: async () => {
        state.authorizations += 1;
        return { token: "token" };
      },
      clear: () => {
        state.clears += 1;
      },
    },
    cloudStore: {
      find: async () =>
        state.remote
          ? { fileId: "file", envelope: state.remote }
          : null,
      write: async (_appId, envelope) => {
        state.writes += 1;
        state.remote = envelope;
        return "file";
      },
      delete: async () => {
        state.deletes += 1;
        state.remote = null;
      },
    },
    readLocal: () => local,
    applyMerged: (item) => {
      state.applied.push(item);
    },
    envelopeUpdatedAt: (envelope) => envelope.updatedAt,
  };
  return { controller: createSnapshotSync(options), state };
}

describe("snapshot orchestration", () => {
  it("creates a new encrypted snapshot and refuses to replace an existing one", async () => {
    const created = harness(null);
    await expect(created.controller.setup()).resolves.toMatchObject({
      outcome: "created",
      fileId: "file",
    });
    expect(created.state.writes).toBe(1);
    await expect(created.controller.setup()).rejects.toMatchObject({
      code: "state",
    });
  });

  it("applies remote state without uploading a stable no-op merge", async () => {
    const remote = envelope(2);
    const test = harness(remote, value(1));
    await expect(test.controller.enable()).resolves.toMatchObject({
      outcome: "unchanged",
      value: value(2),
    });
    expect(test.state.writes).toBe(0);
    expect(test.state.applied).toEqual([value(2)]);
  });

  it("uploads a real local change with the existing key metadata", async () => {
    const test = harness(envelope(1), value(2));
    await expect(test.controller.sync("manual")).resolves.toMatchObject({
      outcome: "merged",
      value: value(2),
    });
    expect(test.state.writes).toBe(1);
    expect(test.state.remote?.keyId).toBe("fixture-key");
  });

  it("serializes operations, ignores visibility feedback, and queues one change", async () => {
    let release!: () => void;
    const authorizationGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const test = harness(envelope(1), value(1));
    const authorize = vi
      .fn()
      .mockImplementationOnce(async () => {
        await authorizationGate;
        return { token: "token" };
      })
      .mockResolvedValue({ token: "token" });
    const controller = createSnapshotSync({
      appId: "fixture",
      codec: {
        serialize: (item: Value) => item,
        parse: (item) => item as Value,
        merge: (left, right) =>
          left.revision >= right.revision ? left : right,
        fingerprint: (item) => String(item.revision),
      },
      envelopeCrypto: {
        encrypt: async (item: Value, _key: string, metadata: Metadata) => ({
          value: item,
          keyId: metadata.keyId,
          updatedAt: item.exportedAt,
        }),
        decrypt: async (item: Envelope) => item.value,
        metadataFromEnvelope: (item: Envelope) => ({ keyId: item.keyId }),
      },
      keyProvider: {
        create: async () => ({
          metadata: { keyId: "created" },
          key: "created",
        }),
        unlock: async () => "fixture-key",
        clear: vi.fn(),
      },
      authorizationProvider: { authorize, clear: vi.fn() },
      cloudStore: {
        find: async () => ({ fileId: "file", envelope: envelope(1) }),
        write: async () => "file",
      },
      readLocal: () => value(1),
      applyMerged: vi.fn(),
      envelopeUpdatedAt: (item: Envelope) => item.updatedAt,
    });

    const active = controller.sync("manual");
    expect(controller.operationInProgress()).toBe(true);
    await expect(controller.sync("foreground")).resolves.toMatchObject({
      outcome: "coalesced",
    });
    const firstChange = controller.sync("change");
    const secondChange = controller.sync("change");
    expect(firstChange).toBe(secondChange);
    release();
    await Promise.all([active, firstChange, secondChange]);

    expect(authorize).toHaveBeenCalledTimes(2);
    expect(controller.operationInProgress()).toBe(false);
    expect(test.state.writes).toBe(0);
  });

  it("queues another change after a queued sync has started reading local state", async () => {
    let local = value(1);
    let remote = envelope(0);
    let readCount = 0;
    let writes = 0;
    let releaseFirstRead!: () => void;
    let releaseSecondRead!: () => void;
    let signalFirstRead!: () => void;
    let signalSecondRead!: () => void;
    const firstReadStarted = new Promise<void>((resolve) => {
      signalFirstRead = resolve;
    });
    const secondReadStarted = new Promise<void>((resolve) => {
      signalSecondRead = resolve;
    });
    const firstReadGate = new Promise<void>((resolve) => {
      releaseFirstRead = resolve;
    });
    const secondReadGate = new Promise<void>((resolve) => {
      releaseSecondRead = resolve;
    });
    const controller = createSnapshotSync({
      appId: "fixture",
      codec: {
        serialize: (item: Value) => item,
        parse: (item) => item as Value,
        merge: (left, right) =>
          left.revision >= right.revision ? left : right,
        fingerprint: (item) => String(item.revision),
      },
      envelopeCrypto: {
        encrypt: async (item: Value, _key: string, metadata: Metadata) => ({
          value: item,
          keyId: metadata.keyId,
          updatedAt: item.exportedAt,
        }),
        decrypt: async (item: Envelope) => item.value,
        metadataFromEnvelope: (item: Envelope) => ({ keyId: item.keyId }),
      },
      keyProvider: {
        create: async () => ({
          metadata: { keyId: "fixture-key" },
          key: "fixture-key",
        }),
        unlock: async () => "fixture-key",
        clear: vi.fn(),
      },
      authorizationProvider: {
        authorize: async () => ({ token: "token" }),
        clear: vi.fn(),
      },
      cloudStore: {
        find: async () => ({ fileId: "file", envelope: remote }),
        write: async (_appId, next) => {
          writes += 1;
          remote = next;
          return "file";
        },
      },
      readLocal: async () => {
        readCount += 1;
        const captured = local;
        if (readCount === 1) {
          signalFirstRead();
          await firstReadGate;
        } else if (readCount === 2) {
          signalSecondRead();
          await secondReadGate;
        }
        return captured;
      },
      applyMerged: vi.fn(),
      envelopeUpdatedAt: (item: Envelope) => item.updatedAt,
    });

    const active = controller.sync("manual");
    await firstReadStarted;
    const queued = controller.sync("change");
    local = value(2);
    releaseFirstRead();
    await secondReadStarted;
    local = value(3);
    const followUp = controller.sync("change");
    expect(followUp).not.toBe(queued);
    releaseSecondRead();

    await Promise.all([active, queued, followUp]);
    expect(readCount).toBe(3);
    expect(writes).toBe(3);
    expect(remote.value).toEqual(value(3));
  });

  it("resets keys, deletes safely, and clears both session caches", async () => {
    const test = harness(envelope(1), value(3));
    await expect(test.controller.reset()).resolves.toMatchObject({
      outcome: "reset",
    });
    expect(test.state.remote?.keyId).toBe("created-key");
    await test.controller.delete();
    expect(test.state.deletes).toBe(1);
    expect(test.state.remote).toBeNull();
    expect(test.state.clears).toBeGreaterThanOrEqual(3);
  });
});

function value(revision: number): Value {
  return {
    revision,
    exportedAt: `2026-06-29T00:00:0${revision}.000Z`,
  };
}

function envelope(revision: number): Envelope {
  return {
    value: value(revision),
    keyId: "fixture-key",
    updatedAt: value(revision).exportedAt,
  };
}
