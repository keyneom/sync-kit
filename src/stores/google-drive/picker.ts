import type { Authorization } from "../../core/types.js";
import { SyncKitError } from "../../core/errors.js";

const PICKER_SCRIPT = "https://apis.google.com/js/api.js";
const DRIVE_FOLDER_MIME_TYPE = "application/vnd.google-apps.folder";

type PickerDocument = {
  id?: string;
  name?: string;
  mimeType?: string;
  url?: string;
};

type PickerResponse = {
  action?: string;
  docs?: PickerDocument[];
};

type Picker = {
  setVisible(visible: boolean): void;
  dispose?(): void;
};

type DocsView = {
  setIncludeFolders(value: boolean): DocsView;
  setMimeTypes(value: string): DocsView;
  setSelectFolderEnabled(value: boolean): DocsView;
  setOwnedByMe(value: boolean): DocsView;
};

type PickerBuilder = {
  addView(view: DocsView): PickerBuilder;
  enableFeature(feature: string): PickerBuilder;
  setAppId(appId: string): PickerBuilder;
  setCallback(callback: (response: PickerResponse) => void): PickerBuilder;
  setDeveloperKey(key: string): PickerBuilder;
  setOAuthToken(token: string): PickerBuilder;
  setOrigin(origin: string): PickerBuilder;
  setTitle(title: string): PickerBuilder;
  build(): Picker;
};

type GooglePicker = {
  Action: { PICKED: string; CANCEL: string };
  DocsView: new (viewId: string) => DocsView;
  PickerBuilder: new () => PickerBuilder;
  ViewId: { FOLDERS: string; DOCS: string };
  Feature: { MULTISELECT_ENABLED: string };
};

type GoogleApiWindow = Window & {
  gapi?: {
    load(name: string, callback: { callback(): void; onerror(): void }): void;
  };
  google?: { picker?: GooglePicker };
};

export type GoogleDrivePickedFolder = {
  folderId: string;
  name?: string;
  url?: string;
};

export type GoogleDrivePickedFile = {
  fileId: string;
  name?: string;
  url?: string;
};

export type GoogleDriveFolderPickerOptions = {
  developerKey: string;
  cloudProjectNumber: string;
  origin?: string;
  title?: string;
  window?: GoogleApiWindow;
  document?: Document;
};

/**
 * Browser-only folder picker for granting drive.file access to a shared app
 * folder. Loading and UI are explicit; importing this module has no effects.
 */
export class GoogleDriveFolderPicker {
  private scriptPromise: Promise<void> | null = null;
  private pickerPromise: Promise<void> | null = null;

  constructor(private readonly options: GoogleDriveFolderPickerOptions) {
    if (!options.developerKey.trim()) {
      throw new TypeError("developerKey must not be empty.");
    }
    if (!options.cloudProjectNumber.trim()) {
      throw new TypeError("cloudProjectNumber must not be empty.");
    }
  }

  async pickFolder(
    authorization: Authorization,
  ): Promise<GoogleDrivePickedFolder | null> {
    await this.loadPicker();
    const pickerApi = this.browserWindow().google?.picker;
    if (!pickerApi) {
      throw new SyncKitError(
        "provider",
        "Google Picker loaded without its folder API.",
      );
    }
    return new Promise((resolve, reject) => {
      let picker: Picker | undefined;
      const finish = (value: GoogleDrivePickedFolder | null): void => {
        picker?.dispose?.();
        resolve(value);
      };
      const view = new pickerApi.DocsView(pickerApi.ViewId.FOLDERS)
        .setIncludeFolders(true)
        .setMimeTypes(DRIVE_FOLDER_MIME_TYPE)
        .setSelectFolderEnabled(true);
      try {
        picker = new pickerApi.PickerBuilder()
          .addView(view)
          .setAppId(this.options.cloudProjectNumber)
          .setDeveloperKey(this.options.developerKey)
          .setOAuthToken(authorization.accessToken)
          .setOrigin(
            this.options.origin ?? this.browserWindow().location.origin,
          )
          .setTitle(this.options.title ?? "Choose the shared app folder")
          .setCallback((response) => {
            if (response.action === pickerApi.Action.CANCEL) {
              finish(null);
              return;
            }
            if (response.action !== pickerApi.Action.PICKED) return;
            const document = response.docs?.[0];
            if (
              !document?.id ||
              (document.mimeType &&
                document.mimeType !== DRIVE_FOLDER_MIME_TYPE)
            ) {
              reject(
                new SyncKitError(
                  "compatibility",
                  "Google Picker did not return a Drive folder.",
                ),
              );
              return;
            }
            finish({
              folderId: document.id,
              ...(document.name ? { name: document.name } : {}),
              ...(document.url ? { url: document.url } : {}),
            });
          })
          .build();
        picker.setVisible(true);
      } catch (error) {
        reject(
          new SyncKitError(
            "provider",
            "Google Picker could not be opened.",
            { cause: error },
          ),
        );
      }
    });
  }

  /**
   * Lets the user select one or more files shared with their account (including
   * "shared with me" from another owner), granting the app `drive.file` access
   * to each selected file. This is how a recipient grants the specific shared
   * dataset files — a folder grant does not cascade to reading files inside it.
   */
  async pickFiles(
    authorization: Authorization,
    options: { multiSelect?: boolean } = {},
  ): Promise<GoogleDrivePickedFile[]> {
    await this.loadPicker();
    const pickerApi = this.browserWindow().google?.picker;
    if (!pickerApi) {
      throw new SyncKitError(
        "provider",
        "Google Picker loaded without its file API.",
      );
    }
    return new Promise((resolve, reject) => {
      let picker: Picker | undefined;
      const finish = (value: GoogleDrivePickedFile[]): void => {
        picker?.dispose?.();
        resolve(value);
      };
      // Show files the user can see, including those shared with them by another
      // account (setOwnedByMe(false)). Folders are included so the user can
      // navigate into the shared folder to reach the dataset files.
      const view = new pickerApi.DocsView(pickerApi.ViewId.DOCS)
        .setIncludeFolders(true)
        .setSelectFolderEnabled(false)
        .setOwnedByMe(false);
      try {
        let builder = new pickerApi.PickerBuilder()
          .addView(view)
          .setAppId(this.options.cloudProjectNumber)
          .setDeveloperKey(this.options.developerKey)
          .setOAuthToken(authorization.accessToken)
          .setOrigin(this.options.origin ?? this.browserWindow().location.origin)
          .setTitle(this.options.title ?? "Select the shared files");
        if (options.multiSelect) {
          builder = builder.enableFeature(pickerApi.Feature.MULTISELECT_ENABLED);
        }
        picker = builder
          .setCallback((response) => {
            if (response.action === pickerApi.Action.CANCEL) {
              finish([]);
              return;
            }
            if (response.action !== pickerApi.Action.PICKED) return;
            const docs = (response.docs ?? []).filter(
              (document): document is { id: string; name?: string; url?: string } =>
                Boolean(document.id) &&
                document.mimeType !== DRIVE_FOLDER_MIME_TYPE,
            );
            if (docs.length === 0) {
              reject(
                new SyncKitError(
                  "compatibility",
                  "Google Picker did not return a Drive file.",
                ),
              );
              return;
            }
            finish(
              docs.map((document) => ({
                fileId: document.id,
                ...(document.name ? { name: document.name } : {}),
                ...(document.url ? { url: document.url } : {}),
              })),
            );
          })
          .build();
        picker.setVisible(true);
      } catch (error) {
        reject(
          new SyncKitError(
            "provider",
            "Google Picker could not be opened.",
            { cause: error },
          ),
        );
      }
    });
  }

  private async loadPicker(): Promise<void> {
    if (this.browserWindow().google?.picker) return;
    await this.loadScript();
    this.pickerPromise ??= new Promise((resolve, reject) => {
      const gapi = this.browserWindow().gapi;
      if (!gapi) {
        reject(
          new SyncKitError(
            "provider",
            "The Google API loader is unavailable.",
          ),
        );
        return;
      }
      gapi.load("picker", {
        callback: () => resolve(),
        onerror: () => {
          this.pickerPromise = null;
          reject(
            new SyncKitError(
              "provider",
              "The Google Picker API could not be loaded.",
            ),
          );
        },
      });
    });
    await this.pickerPromise;
  }

  private loadScript(): Promise<void> {
    if (this.browserWindow().gapi) return Promise.resolve();
    if (this.scriptPromise) return this.scriptPromise;
    this.scriptPromise = new Promise((resolve, reject) => {
      const script = this.browserDocument().createElement("script");
      script.src = PICKER_SCRIPT;
      script.async = true;
      script.defer = true;
      script.onload = () => resolve();
      script.onerror = () => {
        this.scriptPromise = null;
        reject(
          new SyncKitError(
            "provider",
            "The Google API loader could not be loaded.",
          ),
        );
      };
      this.browserDocument().head.append(script);
    });
    return this.scriptPromise;
  }

  private browserWindow(): GoogleApiWindow {
    const value =
      this.options.window ??
      (typeof window === "undefined"
        ? undefined
        : window);
    if (!value) {
      throw new SyncKitError(
        "configuration",
        "Google Picker requires a browser window.",
      );
    }
    return value;
  }

  private browserDocument(): Document {
    const value =
      this.options.document ??
      (typeof document === "undefined" ? undefined : document);
    if (!value) {
      throw new SyncKitError(
        "configuration",
        "Google Picker requires a browser document.",
      );
    }
    return value;
  }
}

export type GoogleDriveOpenState = {
  action: "open";
  fileIds: string[];
  resourceKeys: Record<string, string>;
  userId?: string;
};

export function parseGoogleDriveOpenState(
  input: string | URLSearchParams,
): GoogleDriveOpenState | null {
  const params =
    typeof input === "string"
      ? new URLSearchParams(input.startsWith("?") ? input.slice(1) : input)
      : input;
  const encoded = params.get("state");
  if (!encoded) return null;
  let value: unknown;
  try {
    value = JSON.parse(encoded) as unknown;
  } catch (error) {
    throw new SyncKitError(
      "compatibility",
      "The Google Drive Open-with state is not valid JSON.",
      { cause: error },
    );
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new SyncKitError(
      "compatibility",
      "The Google Drive Open-with state must be an object.",
    );
  }
  const state = value as Record<string, unknown>;
  if (state.action !== "open") return null;
  if (
    !Array.isArray(state.ids) ||
    state.ids.length === 0 ||
    !state.ids.every((id) => typeof id === "string" && id.length > 0)
  ) {
    throw new SyncKitError(
      "compatibility",
      "The Google Drive Open-with state has no file IDs.",
    );
  }
  const resourceKeys: Record<string, string> = {};
  if (state.resourceKeys !== undefined) {
    if (
      !state.resourceKeys ||
      typeof state.resourceKeys !== "object" ||
      Array.isArray(state.resourceKeys)
    ) {
      throw new SyncKitError(
        "compatibility",
        "The Google Drive resource keys are malformed.",
      );
    }
    for (const [fileId, resourceKey] of Object.entries(state.resourceKeys)) {
      if (typeof resourceKey !== "string" || resourceKey.length === 0) {
        throw new SyncKitError(
          "compatibility",
          "A Google Drive resource key is malformed.",
        );
      }
      resourceKeys[fileId] = resourceKey;
    }
  }
  return {
    action: "open",
    fileIds: state.ids.map((id): string => String(id)),
    resourceKeys,
    ...(typeof state.userId === "string" && state.userId
      ? { userId: state.userId }
      : {}),
  };
}
