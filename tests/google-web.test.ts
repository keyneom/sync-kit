import { describe, expect, it, vi } from "vitest";
import { GoogleWebAuthorizationProvider } from "../src/auth/google-web/index.js";

describe("Google web authorization", () => {
  it("coalesces requests and reuses only unexpired memory tokens", async () => {
    let callback!: (response: {
      access_token?: string;
      expires_in?: number;
    }) => void;
    let now = 1_000;
    const requestAccessToken = vi.fn();
    const initTokenClient = vi.fn((config) => {
      callback = config.callback;
      return { requestAccessToken };
    });
    const browserWindow = {
      google: { accounts: { oauth2: { initTokenClient } } },
    } as unknown as Window & {
      google: {
        accounts: {
          oauth2: { initTokenClient: typeof initTokenClient };
        };
      };
    };
    const provider = new GoogleWebAuthorizationProvider({
      clientId: "client",
      now: () => now,
      expirySkewMs: 100,
      window: browserWindow,
    });

    const first = provider.authorize();
    const concurrent = provider.authorize();
    await Promise.resolve();
    expect(requestAccessToken).toHaveBeenCalledTimes(1);
    callback({ access_token: "token", expires_in: 10 });
    await expect(first).resolves.toMatchObject({ accessToken: "token" });
    await expect(concurrent).resolves.toMatchObject({ accessToken: "token" });

    await expect(provider.authorize()).resolves.toMatchObject({
      accessToken: "token",
    });
    expect(requestAccessToken).toHaveBeenCalledTimes(1);

    now = 11_000;
    const expired = provider.authorize();
    await Promise.resolve();
    callback({ access_token: "fresh", expires_in: 10 });
    await expect(expired).resolves.toMatchObject({ accessToken: "fresh" });
    expect(requestAccessToken).toHaveBeenCalledTimes(2);
  });

  it("does not repopulate the cache after explicit clear", async () => {
    let callback!: (response: {
      access_token?: string;
      expires_in?: number;
    }) => void;
    const requestAccessToken = vi.fn();
    const browserWindow = {
      google: {
        accounts: {
          oauth2: {
            initTokenClient: (config: typeof callback extends never ? never : {
              callback: typeof callback;
            }) => {
              callback = config.callback;
              return { requestAccessToken };
            },
          },
        },
      },
    } as unknown as Window;
    const provider = new GoogleWebAuthorizationProvider({
      clientId: "client",
      window: browserWindow,
    });

    const pending = provider.authorize();
    await Promise.resolve();
    provider.clear();
    callback({ access_token: "old", expires_in: 3600 });
    await pending;
    const next = provider.authorize();
    await Promise.resolve();
    expect(requestAccessToken).toHaveBeenCalledTimes(2);
    callback({ access_token: "new", expires_in: 3600 });
    await expect(next).resolves.toMatchObject({ accessToken: "new" });
  });
});
