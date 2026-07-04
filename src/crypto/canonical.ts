import { SyncKitError } from "../core/errors.js";

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

export function canonicalAad(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

/**
 * Compares strings by UTF-16 code units so canonicalization is independent of
 * the host locale and matches Java String.compareTo.
 */
export function compareUtf16CodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalValue(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new SyncKitError(
        "serialization",
        "Canonical JSON does not support non-finite numbers.",
      );
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, child]) => child !== undefined)
        .sort(([left], [right]) => compareUtf16CodeUnits(left, right))
        .map(([key, child]) => [key, canonicalValue(child)]),
    );
  }
  throw new SyncKitError(
    "serialization",
    `Canonical JSON does not support ${typeof value}.`,
  );
}
