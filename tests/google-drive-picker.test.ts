import { describe, expect, it, vi } from "vitest";
import {
  GoogleDriveFolderPicker,
  parseGoogleDriveOpenState,
} from "../src/stores/google-drive/picker.js";

describe("Google Drive Picker", () => {
  it("opens a folder-only picker and returns the selected folder", async () => {
    const setVisible = vi.fn();
    const dispose = vi.fn();
    class DocsView {
      setIncludeFolders(): this {
        return this;
      }
      setMimeTypes(): this {
        return this;
      }
      setSelectFolderEnabled(): this {
        return this;
      }
    }
    class PickerBuilder {
      private callback?: (response: unknown) => void;
      addView(): this {
        return this;
      }
      setAppId(): this {
        return this;
      }
      setDeveloperKey(): this {
        return this;
      }
      setOAuthToken(): this {
        return this;
      }
      setOrigin(): this {
        return this;
      }
      setTitle(): this {
        return this;
      }
      setCallback(callback: (response: unknown) => void): this {
        this.callback = callback;
        return this;
      }
      build() {
        return {
          dispose,
          setVisible: (visible: boolean) => {
            setVisible(visible);
            this.callback?.({
              action: "picked",
              docs: [
                {
                  id: "shared-folder",
                  name: "Fixture Sync",
                  mimeType: "application/vnd.google-apps.folder",
                },
              ],
            });
          },
        };
      }
    }
    const picker = new GoogleDriveFolderPicker({
      developerKey: "developer-key",
      cloudProjectNumber: "project-number",
      origin: "https://example.test",
      window: {
        location: { origin: "https://example.test" },
        google: {
          picker: {
            Action: { PICKED: "picked", CANCEL: "cancel" },
            DocsView,
            PickerBuilder,
            ViewId: { FOLDERS: "folders" },
          },
        },
      } as never,
      document: {} as Document,
    });

    await expect(
      picker.pickFolder({ accessToken: "access-token" }),
    ).resolves.toEqual({
      folderId: "shared-folder",
      name: "Fixture Sync",
    });
    expect(setVisible).toHaveBeenCalledWith(true);
    expect(dispose).toHaveBeenCalledOnce();
  });

  it("parses and validates Drive Open-with state", () => {
    const state = encodeURIComponent(
      JSON.stringify({
        action: "open",
        ids: ["folder-id"],
        resourceKeys: { "folder-id": "resource-key" },
        userId: "google-user",
      }),
    );
    expect(parseGoogleDriveOpenState(`?state=${state}`)).toEqual({
      action: "open",
      fileIds: ["folder-id"],
      resourceKeys: { "folder-id": "resource-key" },
      userId: "google-user",
    });
    expect(parseGoogleDriveOpenState("?state=%7B%22action%22%3A%22create%22%7D"))
      .toBeNull();
  });
});
