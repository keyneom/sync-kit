import type {
  Authorization,
  AuthorizationProvider,
} from "../../core/types.js";
import { SyncKitError } from "../../core/errors.js";

export const GOOGLE_DRIVE_APPDATA_SCOPE =
  "https://www.googleapis.com/auth/drive.appdata";

type TokenResponse = {
  access_token?: string;
  expires_in?: number;
  error?: string;
  error_description?: string;
};

type TokenClient = {
  requestAccessToken(options?: { prompt?: string }): void;
};

type GoogleIdentity = {
  accounts: {
    oauth2: {
      initTokenClient(config: {
        client_id: string;
        scope: string;
        callback(response: TokenResponse): void;
        error_callback?(error: { type?: string }): void;
      }): TokenClient;
    };
  };
};

export type GoogleWebAuthorizationOptions = {
  clientId: string;
  scope?: string;
  expirySkewMs?: number;
  now?: () => number;
  window?: Window & { google?: GoogleIdentity };
  document?: Document;
};

export class GoogleWebAuthorizationProvider
  implements AuthorizationProvider<Authorization>
{
  private scriptPromise: Promise<void> | null = null;
  private cached: (Authorization & { clientId: string }) | null = null;
  private pending: Promise<Authorization> | null = null;
  private generation = 0;

  constructor(private readonly options: GoogleWebAuthorizationOptions) {}

  async authorize(): Promise<Authorization> {
    const now = this.options.now?.() ?? Date.now();
    if (
      this.cached?.clientId === this.options.clientId &&
      (this.cached.expiresAt ?? 0) > now
    ) {
      return {
        accessToken: this.cached.accessToken,
        ...(this.cached.expiresAt === undefined
          ? {}
          : { expiresAt: this.cached.expiresAt }),
      };
    }
    if (this.pending) return this.pending;
    const generation = this.generation;
    const promise = this.requestFresh(generation);
    this.pending = promise;
    try {
      return await promise;
    } finally {
      if (this.pending === promise) this.pending = null;
    }
  }

  clear(): void {
    this.cached = null;
    this.pending = null;
    this.generation += 1;
  }

  private async requestFresh(generation: number): Promise<Authorization> {
    await this.loadScript();
    const google = this.window().google;
    if (!google?.accounts.oauth2) {
      throw new SyncKitError(
        "authorization",
        "Google authorization is unavailable.",
      );
    }
    return new Promise((resolve, reject) => {
      const client = google.accounts.oauth2.initTokenClient({
        client_id: this.options.clientId,
        scope: this.options.scope ?? GOOGLE_DRIVE_APPDATA_SCOPE,
        callback: (response) => {
          if (!response.access_token) {
            reject(
              new SyncKitError(
                "authorization",
                response.error_description ??
                  response.error ??
                  "Google authorization failed.",
              ),
            );
            return;
          }
          const now = this.options.now?.() ?? Date.now();
          const expiresInMs = Math.max(0, (response.expires_in ?? 0) * 1_000);
          const expiresAt =
            now +
            Math.max(
              0,
              expiresInMs - (this.options.expirySkewMs ?? 60_000),
            );
          const authorization = {
            accessToken: response.access_token,
            expiresAt,
          };
          if (generation === this.generation && expiresAt > now) {
            this.cached = {
              ...authorization,
              clientId: this.options.clientId,
            };
          }
          resolve(authorization);
        },
        error_callback: (error) =>
          reject(
            new SyncKitError(
              "authorization",
              error.type ?? "Google authorization was cancelled.",
            ),
          ),
      });
      client.requestAccessToken({ prompt: "" });
    });
  }

  private loadScript(): Promise<void> {
    if (this.window().google?.accounts.oauth2) return Promise.resolve();
    if (this.scriptPromise) return this.scriptPromise;
    this.scriptPromise = new Promise((resolve, reject) => {
      const script = this.document().createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      script.onload = () => resolve();
      script.onerror = () => {
        this.scriptPromise = null;
        reject(
          new SyncKitError(
            "authorization",
            "Google authorization could not be loaded.",
          ),
        );
      };
      this.document().head.append(script);
    });
    return this.scriptPromise;
  }

  private window(): Window & { google?: GoogleIdentity } {
    const value =
      this.options.window ??
      (typeof window === "undefined" ? undefined : window);
    if (!value) {
      throw new SyncKitError(
        "configuration",
        "Google web authorization requires a browser window.",
      );
    }
    return value;
  }

  private document(): Document {
    const value =
      this.options.document ??
      (typeof document === "undefined" ? undefined : document);
    if (!value) {
      throw new SyncKitError(
        "configuration",
        "Google web authorization requires a browser document.",
      );
    }
    return value;
  }
}
