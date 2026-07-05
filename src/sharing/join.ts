import { SyncKitError } from "../core/errors.js";
import type { SharingInvitationV1 } from "./index.js";
import type { SharedBackupTransport } from "./transport.js";

export const SHARING_JOIN_MARKER_PARAM = "sync-kit-join";
export const SHARING_JOIN_EXCHANGE_PARAM = "sync-kit-exchange";
export const SHARING_JOIN_FOLDER_PARAM = "sync-kit-folder";

/** Common consumer alias: `?sync=join&folder=…` with optional `exchange=…` */
export const SHARING_JOIN_SHORT_MARKER_PARAM = "sync";
export const SHARING_JOIN_SHORT_MARKER_VALUE = "join";
export const SHARING_JOIN_SHORT_EXCHANGE_PARAM = "exchange";
export const SHARING_JOIN_SHORT_FOLDER_PARAM = "folder";

export type SharingJoinParams = {
  appFolderId: string;
  /** Optional when only one pending invitation exists in the app folder. */
  exchangeId?: string;
};

export type SharingJoinParamStyle = "sync-kit" | "short";

export type SharingJoinInvitationMatch = {
  invitationFileId: string;
  invitation: SharingInvitationV1;
};

/**
 * Parses a join URL or query string. Returns null when the input is not a
 * recognized sharing join link. The app folder ID is required; exchange ID is
 * optional and only needed to disambiguate multiple pending invitations.
 */
export function parseSharingJoinParams(
  input: string | URLSearchParams,
): SharingJoinParams | null {
  const params = toSearchParams(input);
  const appFolderId = readJoinParam(params, [
    SHARING_JOIN_FOLDER_PARAM,
    SHARING_JOIN_SHORT_FOLDER_PARAM,
  ]);
  if (!appFolderId || !isJoinMarkerPresent(params)) return null;
  const exchangeId = readJoinParam(params, [
    SHARING_JOIN_EXCHANGE_PARAM,
    SHARING_JOIN_SHORT_EXCHANGE_PARAM,
  ]);
  return {
    appFolderId,
    ...(exchangeId ? { exchangeId } : {}),
  };
}

/**
 * Builds join query params for appending to a consumer landing URL.
 */
export function buildSharingJoinSearchParams(
  params: SharingJoinParams,
  style: SharingJoinParamStyle = "sync-kit",
): URLSearchParams {
  if (!params.appFolderId.trim()) {
    throw new TypeError("appFolderId must not be empty.");
  }
  const search = new URLSearchParams();
  if (style === "short") {
    search.set(SHARING_JOIN_SHORT_MARKER_PARAM, SHARING_JOIN_SHORT_MARKER_VALUE);
    search.set(SHARING_JOIN_SHORT_FOLDER_PARAM, params.appFolderId);
    if (params.exchangeId?.trim()) {
      search.set(SHARING_JOIN_SHORT_EXCHANGE_PARAM, params.exchangeId);
    }
    return search;
  }
  search.set(SHARING_JOIN_MARKER_PARAM, "1");
  search.set(SHARING_JOIN_FOLDER_PARAM, params.appFolderId);
  if (params.exchangeId?.trim()) {
    search.set(SHARING_JOIN_EXCHANGE_PARAM, params.exchangeId);
  }
  return search;
}

/**
 * Appends join params to a consumer landing URL. The landing origin and path
 * remain application-owned.
 */
export function appendSharingJoinParams(
  landingUrl: string,
  params: SharingJoinParams,
  style: SharingJoinParamStyle = "sync-kit",
): string {
  const url = new URL(landingUrl);
  const joinParams = buildSharingJoinSearchParams(params, style);
  for (const [key, value] of joinParams.entries()) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

/**
 * Formats a Drive sharing notification body that points recipients to the app
 * join flow instead of relying on Google's folder-only notification.
 */
export function formatSharingInviteEmailMessage(options: {
  joinUrl: string;
  appDisplayName: string;
  intro?: string;
}): string {
  if (!options.joinUrl.trim()) {
    throw new TypeError("joinUrl must not be empty.");
  }
  if (!options.appDisplayName.trim()) {
    throw new TypeError("appDisplayName must not be empty.");
  }
  const intro =
    options.intro?.trim() ??
    `You have been invited to share ${options.appDisplayName} data.`;
  return `${intro}\n\nOpen this link to join in ${options.appDisplayName}:\n${options.joinUrl.trim()}`;
}

/**
 * Finds a pending invitation file for a join exchange ID inside the transport's
 * current app folder.
 */
export async function findSharingJoinInvitation(
  transport: SharedBackupTransport,
  exchangeId: string,
): Promise<SharingJoinInvitationMatch | null> {
  if (!exchangeId.trim()) throw new TypeError("exchangeId must not be empty.");
  const exchanges = await transport.listExchanges({
    exchangeId,
    kind: "invitation",
  });
  const invitationFile = exchanges[0];
  if (!invitationFile) return null;
  const invitation = await transport.readInvitation(invitationFile.fileId);
  return { invitationFileId: invitationFile.fileId, invitation };
}

/**
 * Resolves join params against a transport whose app folder already matches
 * `params.appFolderId` (typically via `selectedAppFolderId`). When exchange ID
 * is omitted, the sole pending invitation in the folder is used.
 */
export async function resolveSharingJoinInvitation(
  transport: SharedBackupTransport,
  params: SharingJoinParams,
): Promise<SharingJoinInvitationMatch> {
  const storage = await transport.ensureStorage();
  if (storage.appFolderId !== params.appFolderId) {
    throw new SyncKitError(
      "configuration",
      "The transport app folder does not match the join link.",
    );
  }
  if (params.exchangeId) {
    const match = await findSharingJoinInvitation(transport, params.exchangeId);
    if (!match) {
      throw new SyncKitError(
        "not-found",
        "No invitation matches the join exchange ID.",
      );
    }
    return match;
  }
  const invitations = await transport.listExchanges({ kind: "invitation" });
  if (invitations.length === 0) {
    throw new SyncKitError(
      "not-found",
      "No pending invitation was found in the shared app folder.",
    );
  }
  if (invitations.length > 1) {
    throw new SyncKitError(
      "state",
      "Multiple pending invitations were found; include exchangeId in the join link.",
    );
  }
  const invitationFile = invitations[0];
  if (!invitationFile) {
    throw new SyncKitError(
      "not-found",
      "No pending invitation was found in the shared app folder.",
    );
  }
  const invitation = await transport.readInvitation(invitationFile.fileId);
  return { invitationFileId: invitationFile.fileId, invitation };
}

function toSearchParams(input: string | URLSearchParams): URLSearchParams {
  if (input instanceof URLSearchParams) return input;
  if (input.startsWith("?")) return new URLSearchParams(input.slice(1));
  if (input.includes("://")) {
    return new URL(input).searchParams;
  }
  return new URLSearchParams(input);
}

function isJoinMarkerPresent(params: URLSearchParams): boolean {
  if (params.get(SHARING_JOIN_MARKER_PARAM) === "1") return true;
  return params.get(SHARING_JOIN_SHORT_MARKER_PARAM) === SHARING_JOIN_SHORT_MARKER_VALUE;
}

function readJoinParam(
  params: URLSearchParams,
  keys: readonly string[],
): string | null {
  for (const key of keys) {
    const value = params.get(key);
    if (value?.trim()) return value.trim();
  }
  return null;
}
