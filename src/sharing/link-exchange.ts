import { SyncKitError } from "../core/errors.js";
import { base64UrlToBytes, bytesToBase64Url } from "../crypto/index.js";
import {
  parseSharingInvitationV1,
  parseSharingPublicKeyResponseV1,
  type SharingInvitationV1,
  type SharingPublicKeyResponseV1,
  type SharingRole,
} from "./index.js";
import {
  SHARING_JOIN_EXCHANGE_PARAM,
  SHARING_JOIN_FOLDER_PARAM,
  SHARING_JOIN_MARKER_PARAM,
} from "./join.js";

/**
 * Link-carried key exchange. The signed invitation and key-response travel in
 * the join/response links (base64url of the existing structs) instead of Drive
 * `exchanges/` files, so a `drive.file` recipient never has to read a file the
 * owner authored and the owner never has to read a file the recipient authored.
 * The only Drive object either side reads is the encrypted dataset, which the
 * recipient grants by picking the specific file(s) — see
 * docs/sync-kit-linkbased-join.md.
 */

/** A dataset file the recipient is granted, so the Picker can offer it by id. */
export type SharingDatasetFileV1 = {
  datasetId: string;
  fileId: string;
  role: Exclude<SharingRole, "owner">;
};

export const SHARING_JOIN_INVITATION_PARAM = "sk-inv";
export const SHARING_JOIN_FILES_PARAM = "sk-files";
export const SHARING_RESPONSE_MARKER_PARAM = "sk-resp";
export const SHARING_RESPONSE_PAYLOAD_PARAM = "sk-kr";

export type SharingJoinLinkV1 = {
  invitation: SharingInvitationV1;
  files: SharingDatasetFileV1[];
};

export type SharingResponseLinkV1 = {
  response: SharingPublicKeyResponseV1;
};

// --- payload encode/decode (signed structs are unchanged; only transported) ---

export function encodeSharingInvitationV1(
  invitation: SharingInvitationV1,
): string {
  return encodeJson(parseSharingInvitationV1(invitation));
}

export function decodeSharingInvitationV1(encoded: string): SharingInvitationV1 {
  return parseSharingInvitationV1(decodeJson(encoded, "invitation"));
}

export function encodeSharingPublicKeyResponseV1(
  response: SharingPublicKeyResponseV1,
): string {
  return encodeJson(parseSharingPublicKeyResponseV1(response));
}

export function decodeSharingPublicKeyResponseV1(
  encoded: string,
): SharingPublicKeyResponseV1 {
  return parseSharingPublicKeyResponseV1(decodeJson(encoded, "key response"));
}

export function encodeSharingDatasetFilesV1(
  files: SharingDatasetFileV1[],
): string {
  if (files.length === 0) {
    throw new SyncKitError("compatibility", "A join link needs at least one dataset file.");
  }
  return encodeJson(files.map(normalizeDatasetFile));
}

export function decodeSharingDatasetFilesV1(
  encoded: string,
): SharingDatasetFileV1[] {
  const value = decodeJson(encoded, "dataset files");
  if (!Array.isArray(value) || value.length === 0) {
    throw new SyncKitError("compatibility", "The join link dataset file list is malformed.");
  }
  return value.map(normalizeDatasetFile);
}

// --- link builders / parsers ---

/**
 * Builds a join link carrying the signed invitation and the recipient's granted
 * dataset files. Keeps the legacy folder/exchange/marker params so existing
 * deep-link handlers still recognize it as a join link.
 */
export function buildSharingJoinLinkV1(input: {
  landingUrl: string;
  invitation: SharingInvitationV1;
  files: SharingDatasetFileV1[];
}): string {
  const url = new URL(input.landingUrl);
  url.searchParams.set(SHARING_JOIN_MARKER_PARAM, "1");
  url.searchParams.set(SHARING_JOIN_FOLDER_PARAM, input.invitation.appFolderId);
  url.searchParams.set(SHARING_JOIN_EXCHANGE_PARAM, input.invitation.exchangeId);
  url.searchParams.set(
    SHARING_JOIN_INVITATION_PARAM,
    encodeSharingInvitationV1(input.invitation),
  );
  url.searchParams.set(
    SHARING_JOIN_FILES_PARAM,
    encodeSharingDatasetFilesV1(input.files),
  );
  return url.toString();
}

export function parseSharingJoinLinkV1(
  input: string | URLSearchParams,
): SharingJoinLinkV1 | null {
  const params = toSearchParams(input);
  const invitation = params.get(SHARING_JOIN_INVITATION_PARAM);
  const files = params.get(SHARING_JOIN_FILES_PARAM);
  if (!invitation || !files) return null;
  return {
    invitation: decodeSharingInvitationV1(invitation),
    files: decodeSharingDatasetFilesV1(files),
  };
}

/** Builds a response link the recipient sends back to the owner to finish join. */
export function buildSharingResponseLinkV1(input: {
  landingUrl: string;
  response: SharingPublicKeyResponseV1;
}): string {
  const url = new URL(input.landingUrl);
  url.searchParams.set(SHARING_RESPONSE_MARKER_PARAM, "1");
  url.searchParams.set(SHARING_JOIN_EXCHANGE_PARAM, input.response.exchangeId);
  url.searchParams.set(
    SHARING_RESPONSE_PAYLOAD_PARAM,
    encodeSharingPublicKeyResponseV1(input.response),
  );
  return url.toString();
}

export function parseSharingResponseLinkV1(
  input: string | URLSearchParams,
): SharingResponseLinkV1 | null {
  const params = toSearchParams(input);
  if (params.get(SHARING_RESPONSE_MARKER_PARAM) !== "1") return null;
  const response = params.get(SHARING_RESPONSE_PAYLOAD_PARAM);
  if (!response) return null;
  return { response: decodeSharingPublicKeyResponseV1(response) };
}

// --- internals ---

function encodeJson(value: unknown): string {
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function decodeJson(encoded: string, label: string): unknown {
  let text: string;
  try {
    text = new TextDecoder().decode(base64UrlToBytes(encoded));
  } catch (error) {
    throw new SyncKitError("compatibility", `The ${label} payload is not valid base64url.`, {
      cause: error,
    });
  }
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new SyncKitError("compatibility", `The ${label} payload is not valid JSON.`, {
      cause: error,
    });
  }
}

function normalizeDatasetFile(value: unknown): SharingDatasetFileV1 {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new SyncKitError("compatibility", "A dataset file entry must be an object.");
  }
  const entry = value as Record<string, unknown>;
  for (const field of ["datasetId", "fileId", "role"]) {
    const fieldValue = entry[field];
    if (typeof fieldValue !== "string" || fieldValue.length === 0) {
      throw new SyncKitError("compatibility", `A dataset file ${field} must be a non-empty string.`);
    }
  }
  const role = entry.role as string;
  if (role !== "admin" && role !== "writer" && role !== "viewer") {
    throw new SyncKitError("compatibility", `A dataset file has an unsupported role: ${role}.`);
  }
  return {
    datasetId: entry.datasetId as string,
    fileId: entry.fileId as string,
    role,
  };
}

function toSearchParams(input: string | URLSearchParams): URLSearchParams {
  if (input instanceof URLSearchParams) return input;
  if (input.startsWith("?")) return new URLSearchParams(input.slice(1));
  if (input.includes("://")) return new URL(input).searchParams;
  return new URLSearchParams(input);
}
