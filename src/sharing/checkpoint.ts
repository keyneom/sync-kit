export type SharedDatasetHead = {
  datasetId: string;
  fileId: string;
  modifiedTime?: string;
  version?: string;
  headRevisionId?: string;
  etag?: string;
};

export type SharingSyncCheckpoint = {
  lastPollAt?: string;
  lastSeenKeyResponseFileIds?: string[];
  datasetHeads?: Record<string, SharedDatasetHead>;
};

export type SharingNotificationEvent =
  | {
      kind: "pending-key-response";
      exchangeId: string;
      fileId: string;
    }
  | {
      kind: "shared-dataset-changed";
      datasetId: string;
      fileId: string;
    }
  | {
      kind: "token-expiring-soon";
      expiresAt: string;
    }
  | {
      kind: "token-expired";
    };

export type SharingChangeDetectionResult = {
  checkpoint: SharingSyncCheckpoint;
  events: SharingNotificationEvent[];
};
