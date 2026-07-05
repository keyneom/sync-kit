import type { SharingChangeDetectionResult, SharingSyncCheckpoint } from "./checkpoint.js";
import { SharingChangeDetector } from "./change-detector.js";

export type SharingPollBindingOptions = {
  intervalMs?: number;
  pollOnForeground?: boolean;
  minimumBackgroundMs?: number;
  window?: Window;
  document?: Document;
  now?: () => number;
};

export type SharingPollController = {
  poll(): Promise<SharingChangeDetectionResult>;
  stop(): void;
};

/**
 * Foreground polling hook for Tier A sharing change detection. Does not show
 * notifications; applications map events to UI or service-worker messages.
 */
export function bindSharingPoll(
  detector: SharingChangeDetector,
  checkpoint: SharingSyncCheckpoint,
  onResult: (result: SharingChangeDetectionResult) => void | Promise<void>,
  options: SharingPollBindingOptions = {},
): SharingPollController {
  const documentImplementation = options.document ?? document;
  const now = options.now ?? Date.now;
  let currentCheckpoint = structuredClone(checkpoint);
  let hiddenAt: number | null = null;
  let intervalId: ReturnType<typeof setInterval> | null = null;

  const poll = async (): Promise<SharingChangeDetectionResult> => {
    const result = await detector.detect(currentCheckpoint);
    currentCheckpoint = result.checkpoint;
    await onResult(result);
    return result;
  };

  const startInterval = () => {
    if (intervalId !== null) return;
    const intervalMs = options.intervalMs ?? 60_000;
    intervalId = setInterval(() => {
      void poll();
    }, intervalMs);
  };

  const stopInterval = () => {
    if (intervalId === null) return;
    clearInterval(intervalId);
    intervalId = null;
  };

  const visibilityChanged = () => {
    if (documentImplementation.visibilityState === "hidden") {
      hiddenAt = now();
      stopInterval();
      return;
    }
    const timeAway = hiddenAt === null ? 0 : now() - hiddenAt;
    hiddenAt = null;
    if (
      options.pollOnForeground !== false &&
      timeAway >= (options.minimumBackgroundMs ?? 30_000)
    ) {
      void poll();
    }
    startInterval();
  };

  documentImplementation.addEventListener(
    "visibilitychange",
    visibilityChanged,
  );
  startInterval();

  return {
    poll,
    stop: () => {
      stopInterval();
      documentImplementation.removeEventListener(
        "visibilitychange",
        visibilityChanged,
      );
    },
  };
}
