const DRIVE_FOLDER_NAME_MAX_LENGTH = 200;
const INVALID_DRIVE_FOLDER_CHARS = /[\u0000-\u001f\\/]/g;

export type SyncKitFolderNameInput = {
  appDisplayName: string;
  profileLabel: string;
  ownerLabel?: string;
};

/**
 * Sanitizes a human-readable Google Drive folder title. Names are presentation
 * metadata only; protocol identity uses folder IDs and app properties.
 */
export function sanitizeDriveFolderName(name: string): string {
  const collapsed = name
    .replace(INVALID_DRIVE_FOLDER_CHARS, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (collapsed.length === 0) {
    throw new TypeError("The Drive folder name must not be empty.");
  }
  if (collapsed.length <= DRIVE_FOLDER_NAME_MAX_LENGTH) {
    return collapsed;
  }
  return collapsed.slice(0, DRIVE_FOLDER_NAME_MAX_LENGTH).trimEnd();
}

/**
 * Builds a consumer-facing app-folder title from app branding, a user-chosen
 * profile label, and optional owner disambiguation for shared views.
 */
export function buildSyncKitFolderName(input: SyncKitFolderNameInput): string {
  if (!input.appDisplayName.trim()) {
    throw new TypeError("appDisplayName must not be empty.");
  }
  if (!input.profileLabel.trim()) {
    throw new TypeError("profileLabel must not be empty.");
  }
  const base = `${input.appDisplayName.trim()} — ${input.profileLabel.trim()}`;
  const withOwner = input.ownerLabel?.trim()
    ? `${base} (${input.ownerLabel.trim()})`
    : base;
  return sanitizeDriveFolderName(withOwner);
}
