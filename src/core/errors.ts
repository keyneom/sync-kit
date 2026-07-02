export type SyncErrorCode =
  | "authorization"
  | "compatibility"
  | "configuration"
  | "conflict"
  | "crypto"
  | "decompression"
  | "key"
  | "not-found"
  | "provider"
  | "serialization"
  | "state";

export class SyncKitError extends Error {
  readonly code: SyncErrorCode;
  readonly status: number | undefined;

  constructor(
    code: SyncErrorCode,
    message: string,
    options: ErrorOptions & { status?: number } = {},
  ) {
    super(message, options);
    this.name = "SyncKitError";
    this.code = code;
    this.status = options.status;
  }
}

export function isSyncKitError(value: unknown): value is SyncKitError {
  return value instanceof SyncKitError;
}

export function asSyncKitError(
  value: unknown,
  code: SyncErrorCode,
  message: string,
): SyncKitError {
  return isSyncKitError(value)
    ? value
    : new SyncKitError(code, message, { cause: value });
}
