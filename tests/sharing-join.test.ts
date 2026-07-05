import { describe, expect, it } from "vitest";
import {
  appendSharingJoinParams,
  buildSharingJoinSearchParams,
  formatSharingInviteEmailMessage,
  parseSharingJoinParams,
  SHARING_JOIN_EXCHANGE_PARAM,
  SHARING_JOIN_FOLDER_PARAM,
} from "../src/sharing/join.js";

describe("sharing join params", () => {
  const folderOnly = {
    appFolderId: "folder-1",
  };

  const withExchange = {
    ...folderOnly,
    exchangeId: "exchange-1",
  };

  it("parses folder-only sync-kit join params", () => {
    expect(
      parseSharingJoinParams(
        `?sync-kit-join=1&${SHARING_JOIN_FOLDER_PARAM}=folder-1`,
      ),
    ).toEqual(folderOnly);
  });

  it("parses sync-kit-prefixed join params with optional exchange", () => {
    expect(
      parseSharingJoinParams(
        `?sync-kit-join=1&${SHARING_JOIN_EXCHANGE_PARAM}=exchange-1&${SHARING_JOIN_FOLDER_PARAM}=folder-1`,
      ),
    ).toEqual(withExchange);
  });

  it("parses short consumer folder-only join params", () => {
    expect(parseSharingJoinParams("?sync=join&folder=folder-1")).toEqual(
      folderOnly,
    );
  });

  it("parses short consumer join params with optional exchange", () => {
    expect(
      parseSharingJoinParams("?sync=join&exchange=exchange-1&folder=folder-1"),
    ).toEqual(withExchange);
  });

  it("returns null for unrelated query strings", () => {
    expect(parseSharingJoinParams("?foo=bar")).toBeNull();
  });

  it("builds folder-only and exchange-qualified join params", () => {
    expect(buildSharingJoinSearchParams(folderOnly, "short").toString()).toBe(
      "sync=join&folder=folder-1",
    );
    expect(buildSharingJoinSearchParams(withExchange, "short").toString()).toBe(
      "sync=join&folder=folder-1&exchange=exchange-1",
    );
    expect(
      appendSharingJoinParams("https://example.com/app/", folderOnly, "short"),
    ).toBe("https://example.com/app/?sync=join&folder=folder-1");
  });

  it("formats an invite email message with the join URL", () => {
    expect(
      formatSharingInviteEmailMessage({
        joinUrl: "https://example.com/app/?sync=join&folder=folder-1",
        appDisplayName: "EasyBC",
      }),
    ).toContain("Open this link to join in EasyBC");
    expect(
      formatSharingInviteEmailMessage({
        joinUrl: "https://example.com/app/?sync=join&folder=folder-1",
        appDisplayName: "EasyBC",
      }),
    ).toContain("folder=folder-1");
  });
});
