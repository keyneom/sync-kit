import { SyncKitError } from "../core/errors.js";

const base64UrlPattern = /^[A-Za-z0-9_-]*$/u;

export function bytesToBase64Url(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64url");
  }
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function base64UrlToBytes(value: string): Uint8Array {
  if (!base64UrlPattern.test(value) || value.length % 4 === 1) {
    throw new SyncKitError("serialization", "Invalid base64url value.");
  }
  try {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(value, "base64url"));
    }
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch (error) {
    throw new SyncKitError("serialization", "Invalid base64url value.", {
      cause: error,
    });
  }
}
