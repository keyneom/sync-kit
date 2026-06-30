import type { SnapshotSyncController } from "./controller.js";

export type LifecycleBindingOptions = {
  backgroundGraceMs?: number;
  syncOnForeground?: boolean;
  minimumBackgroundMs?: number;
  window?: Window;
  document?: Document;
  now?: () => number;
};

export function bindWebLifecycle<T>(
  controller: SnapshotSyncController<T>,
  options: LifecycleBindingOptions = {},
): () => void {
  const windowImplementation = options.window ?? window;
  const documentImplementation = options.document ?? document;
  const now = options.now ?? Date.now;
  let hiddenAt: number | null = null;
  let lockTimer: ReturnType<typeof setTimeout> | null = null;

  const cancelTimer = () => {
    if (lockTimer !== null) clearTimeout(lockTimer);
    lockTimer = null;
  };
  const visibilityChanged = () => {
    if (documentImplementation.visibilityState === "hidden") {
      hiddenAt = now();
      cancelTimer();
      lockTimer = setTimeout(
        () => controller.lock(),
        options.backgroundGraceMs ?? 15 * 60_000,
      );
      return;
    }
    cancelTimer();
    const timeAway = hiddenAt === null ? 0 : now() - hiddenAt;
    hiddenAt = null;
    if (
      options.syncOnForeground &&
      timeAway >= (options.minimumBackgroundMs ?? 60_000) &&
      !controller.operationInProgress()
    ) {
      void controller.sync("foreground");
    }
  };
  const pageHidden = () => controller.lock();
  documentImplementation.addEventListener(
    "visibilitychange",
    visibilityChanged,
  );
  windowImplementation.addEventListener("pagehide", pageHidden);

  return () => {
    cancelTimer();
    documentImplementation.removeEventListener(
      "visibilitychange",
      visibilityChanged,
    );
    windowImplementation.removeEventListener("pagehide", pageHidden);
  };
}
