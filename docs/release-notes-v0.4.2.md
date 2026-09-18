# sync-kit 0.4.2

Additive; no signature or behavior changes. Driven by two consumer reports from
building Keyweb against 0.4.1 (keyneom/sync-kit#6, #7).

## Android passkey failures name the missing asset link

`AndroidPasskeyKeyProvider` wrapped neither `createCredential` nor
`getCredential`, so a missing Digital Asset Links entry surfaced as a raw
`NoCredentialException` — indistinguishable from the user simply having no
passkey. A consumer hitting that on a first attempt reasonably concludes Android
cannot derive the PRF secret at all. One did, designed a second Android-only key
path around it, and the diverging envelopes cost a user their cloud backup.

Both paths now raise `SyncKitErrorCode.KEY` naming the likely cause and the fix:
serve `https://<rp-id>/.well-known/assetlinks.json` with
`delegate_permission/common.get_login_creds`. The original exception is retained
as the cause.

Android derives the same passkey PRF secret as the browser. One envelope serves
both platforms; do not design a second key path for Android.

## `launchGrantInBrowser`

`com.keyneom.synckit.stores.launchGrantInBrowser(activity, url)` opens a web
Picker grant page in a full browser tab. Every consumer needs this and all three
pitfalls live inside it: a Custom Tab breaks Google Identity Services' popup
token flow; an unaddressed `ACTION_VIEW` routes back into an app that owns its
own App Link, so the browser package must be resolved against a neutral URL and
forced; and there must be a fallback when nothing resolves (returns `false`).

It also skips `android`, the system disambiguation activity, and falls back to
querying all browsable handlers rather than depending on `androidx.browser`.

No return channel from the grant page is required — `listAccessibleSyncKitDatasets`
already enumerates exactly what the grant covers.

## `GoogleDrivePicker`

`/stores/google-drive/picker` now exports `GoogleDrivePicker` and
`GoogleDrivePickerOptions`. The class picks files as well as folders, so the
original `GoogleDriveFolderPicker` name understated it. Both names refer to the
same class and existing imports keep working.

## `docs/` ships in the npm package

`files` was `["dist", "README.md", "LICENSE"]`, so every `docs/` link in the
README was dead for anyone reading from `node_modules`. `docs/` is now included.

## Platform parity

Every change here is a platform-local facility — Android error text and an
Android intent helper, an npm-only export alias and packaging. None creates or
mutates cross-platform state, so the parity gate in `AGENTS.md` does not require
a matching implementation on the other platform.
