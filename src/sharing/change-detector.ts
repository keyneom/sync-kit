import type {
  SharingChangeDetectionResult,
  SharingNotificationEvent,
  SharingSyncCheckpoint,
  SharedDatasetHead,
} from "./checkpoint.js";
export type {
  SharedDatasetHead,
  SharingChangeDetectionResult,
  SharingNotificationEvent,
  SharingSyncCheckpoint,
} from "./checkpoint.js";

function datasetHeadSignature(head: SharedDatasetHead): string {
  return [
    head.etag ?? "",
    head.version ?? "",
    head.headRevisionId ?? "",
    head.modifiedTime ?? "",
  ].join("|");
}

export type SharingChangeDetectorOptions = {
  now?: () => Date;
  tokenExpiresAt?: number;
  tokenExpiringSoonMs?: number;
};

/**
 * Metadata-only poll for Tier A notifications. Does not decrypt, sign, or
 * mutate Drive state.
 */
export async function detectSharingChanges(
  listKeyResponses: () => Promise<
    readonly { fileId: string; exchangeId: string }[]
  >,
  listDatasetHeads: () => Promise<readonly SharedDatasetHead[]>,
  checkpoint: SharingSyncCheckpoint,
  options: SharingChangeDetectorOptions = {},
): Promise<SharingChangeDetectionResult> {
  const now = options.now ?? (() => new Date());
  const events: SharingNotificationEvent[] = [];
  const tokenExpiringSoonMs = options.tokenExpiringSoonMs ?? 5 * 60_000;
  if (options.tokenExpiresAt !== undefined) {
    if (options.tokenExpiresAt <= now().getTime()) {
      events.push({ kind: "token-expired" });
      return {
        checkpoint: { ...checkpoint, lastPollAt: now().toISOString() },
        events,
      };
    }
    if (options.tokenExpiresAt - now().getTime() <= tokenExpiringSoonMs) {
      events.push({
        kind: "token-expiring-soon",
        expiresAt: new Date(options.tokenExpiresAt).toISOString(),
      });
    }
  }
  const seenResponses = new Set(checkpoint.lastSeenKeyResponseFileIds ?? []);
  const responses = await listKeyResponses();
  for (const response of responses) {
    if (!seenResponses.has(response.fileId)) {
      events.push({
        kind: "pending-key-response",
        exchangeId: response.exchangeId,
        fileId: response.fileId,
      });
    }
  }
  const previousHeads = checkpoint.datasetHeads ?? {};
  const nextHeads: Record<string, SharedDatasetHead> = {};
  const heads = await listDatasetHeads();
  for (const head of heads) {
    nextHeads[head.datasetId] = head;
    const previous = previousHeads[head.datasetId];
    if (
      previous &&
      datasetHeadSignature(previous) !== datasetHeadSignature(head)
    ) {
      events.push({
        kind: "shared-dataset-changed",
        datasetId: head.datasetId,
        fileId: head.fileId,
      });
    }
  }
  return {
    checkpoint: {
      lastPollAt: now().toISOString(),
      lastSeenKeyResponseFileIds: responses.map((response) => response.fileId),
      datasetHeads: nextHeads,
    },
    events,
  };
}

export class SharingChangeDetector {
  constructor(
    private readonly options: {
      listKeyResponses: () => Promise<
        readonly { fileId: string; exchangeId: string }[]
      >;
      listDatasetHeads: () => Promise<readonly SharedDatasetHead[]>;
      tokenExpiresAt?: () => number | undefined;
      now?: () => Date;
      tokenExpiringSoonMs?: number;
    },
  ) {}

  detect(checkpoint: SharingSyncCheckpoint): Promise<SharingChangeDetectionResult> {
    const tokenExpiresAt = this.options.tokenExpiresAt?.();
    return detectSharingChanges(
      this.options.listKeyResponses,
      this.options.listDatasetHeads,
      checkpoint,
      {
        ...(this.options.now ? { now: this.options.now } : {}),
        ...(tokenExpiresAt !== undefined ? { tokenExpiresAt } : {}),
        ...(this.options.tokenExpiringSoonMs !== undefined
          ? { tokenExpiringSoonMs: this.options.tokenExpiringSoonMs }
          : {}),
      },
    );
  }
}

export function createSharingChangeDetectorFromTransport(
  transport: {
    listExchanges(options?: {
      kind?: "invitation" | "key-response";
    }): Promise<
      readonly { fileId: string; exchangeId: string; kind: string }[]
    >;
    listDatasetHeads(): Promise<readonly SharedDatasetHead[]>;
  },
  options: Omit<
    ConstructorParameters<typeof SharingChangeDetector>[0],
    "listKeyResponses" | "listDatasetHeads"
  > = {},
): SharingChangeDetector {
  return new SharingChangeDetector({
    listKeyResponses: async () => {
      const exchanges = await transport.listExchanges({ kind: "key-response" });
      return exchanges.map((exchange) => ({
        fileId: exchange.fileId,
        exchangeId: exchange.exchangeId,
      }));
    },
    listDatasetHeads: () => transport.listDatasetHeads(),
    ...options,
  });
}
