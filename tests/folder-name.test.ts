import { describe, expect, it } from "vitest";
import {
  buildSyncKitFolderName,
  sanitizeDriveFolderName,
} from "../src/stores/google-drive/folder-name.js";

describe("sync-kit folder names", () => {
  it("builds a profile label with optional owner disambiguation", () => {
    expect(
      buildSyncKitFolderName({
        appDisplayName: "EasyBC",
        profileLabel: "Personal",
      }),
    ).toBe("EasyBC — Personal");
    expect(
      buildSyncKitFolderName({
        appDisplayName: "EasyBC",
        profileLabel: "Personal",
        ownerLabel: "alice@example.com",
      }),
    ).toBe("EasyBC — Personal (alice@example.com)");
  });

  it("sanitizes invalid Drive folder characters and collapses whitespace", () => {
    expect(sanitizeDriveFolderName("  Clinic\\West  ")).toBe("Clinic West");
  });

  it("rejects empty folder names", () => {
    expect(() => sanitizeDriveFolderName("   ")).toThrow(
      "The Drive folder name must not be empty.",
    );
    expect(() =>
      buildSyncKitFolderName({
        appDisplayName: "EasyBC",
        profileLabel: " ",
      }),
    ).toThrow("profileLabel must not be empty.");
  });
});
