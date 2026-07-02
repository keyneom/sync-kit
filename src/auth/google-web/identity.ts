import { SyncKitError } from "../../core/errors.js";

type GoogleCredentialResponse = {
  credential?: string;
};

type PromptMomentNotification = {
  isNotDisplayed(): boolean;
  isSkippedMoment(): boolean;
  getNotDisplayedReason?(): string;
  getSkippedReason?(): string;
};

type GoogleIdentityWindow = Window & {
  google?: {
    accounts?: {
      id?: {
        initialize(options: {
          client_id: string;
          nonce: string;
          callback(response: GoogleCredentialResponse): void;
          auto_select?: boolean;
          cancel_on_tap_outside?: boolean;
          use_fedcm_for_prompt?: boolean;
        }): void;
        prompt(
          callback?: (notification: PromptMomentNotification) => void,
        ): void;
        cancel(): void;
      };
    };
  };
};

export type GoogleWebIdentityOptions = {
  clientId: string;
  window?: GoogleIdentityWindow;
  document?: Document;
  useFedCm?: boolean;
};

/**
 * Requests a Google-signed ID token whose nonce is the sharing-account
 * binding challenge. The token is returned to the caller and is not cached.
 */
export class GoogleWebIdentityProvider {
  private scriptPromise: Promise<void> | null = null;

  constructor(private readonly options: GoogleWebIdentityOptions) {
    if (!options.clientId.trim()) {
      throw new TypeError("clientId must not be empty.");
    }
  }

  async requestIdToken(nonce: string): Promise<string> {
    if (!nonce.trim()) throw new TypeError("nonce must not be empty.");
    await this.loadScript();
    const identity = this.browserWindow().google?.accounts?.id;
    if (!identity) {
      throw new SyncKitError(
        "authorization",
        "Google identity services are unavailable.",
      );
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (message: string): void => {
        if (settled) return;
        settled = true;
        reject(new SyncKitError("authorization", message));
      };
      identity.initialize({
        client_id: this.options.clientId,
        nonce,
        auto_select: false,
        cancel_on_tap_outside: true,
        use_fedcm_for_prompt: this.options.useFedCm ?? true,
        callback: (response) => {
          if (settled) return;
          if (!response.credential) {
            fail("Google did not return an identity token.");
            return;
          }
          settled = true;
          resolve(response.credential);
        },
      });
      identity.prompt((notification) => {
        if (notification.isNotDisplayed()) {
          fail(
            notification.getNotDisplayedReason?.() ??
              "Google sign-in could not be displayed.",
          );
        } else if (notification.isSkippedMoment()) {
          fail(
            notification.getSkippedReason?.() ??
              "Google sign-in was skipped.",
          );
        }
      });
    });
  }

  cancel(): void {
    this.browserWindow().google?.accounts?.id?.cancel();
  }

  private loadScript(): Promise<void> {
    if (this.browserWindow().google?.accounts?.id) {
      return Promise.resolve();
    }
    if (this.scriptPromise) return this.scriptPromise;
    this.scriptPromise = new Promise((resolve, reject) => {
      const script = this.browserDocument().createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      script.onload = () => resolve();
      script.onerror = () => {
        this.scriptPromise = null;
        reject(
          new SyncKitError(
            "authorization",
            "Google identity services could not be loaded.",
          ),
        );
      };
      this.browserDocument().head.append(script);
    });
    return this.scriptPromise;
  }

  private browserWindow(): GoogleIdentityWindow {
    const value =
      this.options.window ??
      (typeof window === "undefined"
        ? undefined
        : window);
    if (!value) {
      throw new SyncKitError(
        "configuration",
        "Google identity requires a browser window.",
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
        "Google identity requires a browser document.",
      );
    }
    return value;
  }
}
