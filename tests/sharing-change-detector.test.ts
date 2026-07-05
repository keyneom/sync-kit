import { describe, expect, it } from "vitest";
import {
  createSharingChangeDetectorFromTransport,
  detectSharingChanges,
} from "../src/sharing/change-detector.js";
import type { SharedDatasetHead } from "../src/sharing/checkpoint.js";

describe("detectSharingChanges", () => {
  it("emits pending key responses for unseen exchange files", async () => {
    const result = await detectSharingChanges(
      async () => [
        { fileId: "response-1", exchangeId: "exchange-1" },
        { fileId: "response-2", exchangeId: "exchange-2" },
      ],
      async () => [],
      { lastSeenKeyResponseFileIds: ["response-1"] },
      { now: () => new Date("2026-07-01T12:00:00.000Z") },
    );

    expect(result.events).toEqual([
      {
        kind: "pending-key-response",
        exchangeId: "exchange-2",
        fileId: "response-2",
      },
    ]);
    expect(result.checkpoint.lastSeenKeyResponseFileIds).toEqual([
      "response-1",
      "response-2",
    ]);
    expect(result.checkpoint.lastPollAt).toBe("2026-07-01T12:00:00.000Z");
  });

  it("emits shared-dataset-changed when a head signature changes", async () => {
    const previousHead: SharedDatasetHead = {
      datasetId: "tasks",
      fileId: "file-1",
      etag: `"1"`,
    };
    const result = await detectSharingChanges(
      async () => [],
      async () => [
        {
          datasetId: "tasks",
          fileId: "file-1",
          etag: `"2"`,
        },
      ],
      { datasetHeads: { tasks: previousHead } },
      { now: () => new Date("2026-07-01T12:00:00.000Z") },
    );

    expect(result.events).toEqual([
      {
        kind: "shared-dataset-changed",
        datasetId: "tasks",
        fileId: "file-1",
      },
    ]);
    expect(result.checkpoint.datasetHeads?.tasks?.etag).toBe(`"2"`);
  });

  it("returns token-expired without polling when the access token expired", async () => {
    let polled = false;
    const result = await detectSharingChanges(
      async () => {
        polled = true;
        return [];
      },
      async () => {
        polled = true;
        return [];
      },
      {},
      {
        now: () => new Date("2026-07-01T12:00:00.000Z"),
        tokenExpiresAt: Date.parse("2026-07-01T11:59:59.000Z"),
      },
    );

    expect(polled).toBe(false);
    expect(result.events).toEqual([{ kind: "token-expired" }]);
  });

  it("builds a detector from transport listExchanges and listDatasetHeads", async () => {
    const detector = createSharingChangeDetectorFromTransport({
      listExchanges: async () => [
        {
          fileId: "response-1",
          exchangeId: "exchange-1",
          kind: "key-response",
        },
      ],
      listDatasetHeads: async () => [
        { datasetId: "tasks", fileId: "file-1", etag: `"1"` },
      ],
    });

    const result = await detector.detect({});
    expect(result.events).toEqual([
      {
        kind: "pending-key-response",
        exchangeId: "exchange-1",
        fileId: "response-1",
      },
    ]);
    expect(result.checkpoint.datasetHeads?.tasks?.fileId).toBe("file-1");
  });
});
