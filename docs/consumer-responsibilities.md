# Consumer responsibilities

This document explains what `@keyneom/sync-kit` owns versus what each adopting
application must build. Use it when planning sharing integration, multi-profile
UX, or folder naming — especially if you expect the package to absorb setup
wizards, profile switchers, or Drive presentation logic.

The protocol rationale lives in [shared-backups.md](shared-backups.md). The
implementation handoff and settled defaults are in
[sharing-implementation-handoff.md](sharing-implementation-handoff.md).

## Two different "profile" concepts

Do not conflate these:

| Concept | Owned by | Purpose |
| --- | --- | --- |
| **Compatibility profile** | App defines values; sync-kit defines the type | v1 crypto context: `appId`, filename, AAD, HKDF info, passkey labels |
| **Sync/sharing profile** | App entirely | User-facing backup context: which folder, which role, which Google account, display label |

sync-kit validates and orchestrates the protocol using `appId` and Drive file
IDs. It does not know whether the user calls a context "Personal", "West
Clinic", or "Sarah's EasyBC".

## Responsibility matrix

### sync-kit owns

- Encrypted envelope formats, sharing protocol types, and validation.
- Headless orchestration: `SharedBackupController`, transport contracts,
  invitation/key-response flows, role changes, revocation, fork detection.
- Google Drive transport: managed app/exchange folders, conditional writes,
  provenance checks, per-dataset permissions.
- Browser adapters: OAuth token reuse, Picker, Open-with state parsing,
  passkey-encrypted sharing identities (optional IndexedDB ciphertext store).
- Standardized errors and operation serialization.
- Optional override hooks: `folderName`, `selectedAppFolderId`, `parentFolderId`
  on Google Drive transports.

### Each application owns

- Compatibility profile values for its product.
- Data schema, merge policy, tombstones, and stable fingerprints.
- **Sync/sharing profile index** — local persistence of which backup contexts
  exist and how to reconnect to each one.
- **Folder naming policy** — human-readable Drive titles, including
  user-chosen labels and owner disambiguation.
- Setup and onboarding UI: OAuth consent, passkey creation, folder Picker,
  invitation review, join deeplinks, "Copy join link".
- Profile switcher, status presentation, privacy copy, and rename flows.
- OAuth client configuration and deployment URLs.
- Lifecycle policy: foreground sync, debounce, background grace, lock timing.
- Local persistence technology (IndexedDB, SQLite, etc.) for app state and,
  unless using a future optional sync-kit adapter, the dataset registry.
- Choosing whether email, display name, or other metadata appears in Drive
  folder names (with documented privacy tradeoffs).

## Why certain work stays in applications

**Product shape varies.** EasyBC may distinguish clinic vs personal contexts;
Family Chores may expose one household backup; Keynote may use manifests and
blobs. A single profile model or switcher UX in sync-kit would fit one consumer
and constrain others.

**Names are presentation; IDs are authoritative.** Drive folder names help
humans browse Google Drive. Protocol correctness depends on `appFolderId`,
`sync-kit-app-id` app properties, dataset IDs, and signed envelopes — not on
whether two folders are both called `Sync Kit - easy-bc`. Presentation choices
(personalization, localization, privacy) belong with the product.

**Privacy tradeoffs are application decisions.** Appending an owner email to a
folder name helps recipients distinguish shares, but anyone with folder access
sees that metadata in Drive. Some apps will prefer display-name-only labels,
others will require email disambiguation. sync-kit should not pick that policy.

**UI and routing are explicitly out of scope.** The sharing handoff requires
headless APIs and typed state; consumers own all UI. Join URLs like
`https://example.com/my-app/?sync=join&…` depend on deployment origin and app
router conventions — not on a shared npm package.

**Registry persistence is application storage.** sync-kit defines
`SharedBackupRegistry` and ships `MemorySharedBackupRegistry` for tests. The
dataset registry records trust roots and revision heads for the protocol. Where
and how that survives reloads (and how it relates to profile switcher metadata)
is consumer persistence — parallel to how snapshot merge state stays in the app.

## Multi-profile model (recommended pattern)

One **sync/sharing profile** maps to exactly one app-folder context:

```ts
type AppSyncProfile = {
  profileId: string;
  displayName: string; // user-chosen; in-app switcher label
  appFolderId: string; // authoritative; persist after first connect
  folderName: string; // Drive title used at folder creation
  role: "owner" | "recipient";
  ownerEmail?: string; // label metadata only; not a protocol identity key
  googleAccountHint?: string; // which Google account opens this profile
};
```

Each profile binds:

- one `GoogleDriveSharedBackupTransport` (with `folderName` and/or
  `selectedAppFolderId`);
- one `SharedBackupRegistry` instance (or namespaced partition);
- one sharing identity scope for that app folder;
- one set of controller options for datasets in that folder.

Never key profiles by folder name alone. Always persist `appFolderId` after the
first successful `ensureStorage()` or Picker selection, then prefer
`selectedAppFolderId` on subsequent sessions.

### Scenarios that need multiple profiles

| Scenario | Typical profiles |
| --- | --- |
| Owner with private and shared backups | `Personal` (owner), `Clinic` (owner, shared with staff) |
| Recipient with shares from several people | One profile per shared app folder, each with a distinct `appFolderId` |
| Same human, multiple Google accounts | One profile per account × folder context |
| Legacy private v1 + new shared normal-Drive backup | Separate profiles until migration completes |

The default folder name `Sync Kit - <appId>` is adequate only for **single
owner, single context** integrations. As soon as users can share personal
datasets or maintain more than one backup context, require explicit profile
labels.

## Folder naming guidance

### Recommended format

For owner-created folders, compose a Drive title from app branding plus a
user-chosen profile label:

```text
<AppDisplayName> — <ProfileLabel>
```

Examples:

```text
EasyBC — Personal
EasyBC — West Clinic
Family Chores — Home
```

When recipients may see several similar folders (especially from different
owners), add owner disambiguation:

```text
EasyBC — Personal (alice@example.com)
```

Collect `ProfileLabel` during setup. Pass the computed string as `folderName`
when constructing `GoogleDriveSharedBackupTransport` or calling
`ensureGoogleDriveSyncKitFolder`. Persist `{ appFolderId, folderName,
profileLabel, … }` in the app profile index so the switcher can show
**"Sarah's EasyBC (sarah@…)"** even when Drive shows a different title.

### In-app display name vs Drive folder name

These are related but not identical:

| Field | Purpose |
| --- | --- |
| `folderName` | Drive title at creation; visible to everyone with folder access |
| `displayName` | In-app switcher label; recipient may use a local alias |
| `appFolderId` | Protocol and transport identity; survives renames if persisted |

Recipients cannot always rename shared folders in Drive. Let them override
`displayName` locally without changing the owner's `folderName`.

### Sanitization

Google Drive restricts folder name length and characters. Sanitize in the
application (or a future sync-kit helper) before the first `createFolder`.
Do not put sensitive schema content or decrypted data in folder names — only
presentation metadata the product accepts exposing in Drive.

### Renames and rediscovery

Folder lookup during `ensureGoogleDriveSyncKitFolder` matches **both**
`sync-kit-app-id` app properties and the **exact** `folderName`. After first
creation:

1. Persist `appFolderId`.
2. Pass `selectedAppFolderId` on the transport for subsequent operations.

If the user renames the folder in Drive without updating app state, a transport
configured with only `folderName` may fail to find the folder and create a
duplicate. Treat post-create identity as **folder ID**, not folder title.

## Background notifications

See [background-notifications.md](background-notifications.md) for the full model.

| Tier | sync-kit | Application |
| --- | --- | --- |
| **A — Drive detect** | `SharingChangeDetector`, checkpoints, events; opt-in token cache (web) | SW / WorkManager, notification copy, deep links |
| **B — Local remind** | Checkpoint timestamp fields only | Schedule rules, local reminder index, alarms |
| **Full sync** | Headless accept/sync APIs | OAuth, passkey unlock, merge UI |

sync-kit does not register service workers, schedule local product reminders,
or perform accept/decrypt/sign in background workers.

**Web:** Tier A is best-effort for ~one hour after last OAuth (Google access
token lifetime). **Android:** Tier A can run continuously when the app supplies
refresh-token authorization to `SharingSyncWorker`.

## Join deeplinks and invitations

Google's share notification opens Drive, not your application. Apps typically
add a join URL for SMS, clinic portals, or email copy buttons:

```text
https://<your-origin>/<app-path>/?sync=join&folder=<appFolderId>
```

Optional `exchange=<exchangeId>` disambiguates when several pending invitations
exist in the same app folder's `exchanges/` child. The folder ID is the primary
join anchor; invitations live under that folder hierarchy.

| Piece | Owner |
| --- | --- |
| Landing origin and path | Application deployment |
| Query routing (`?sync=join`) | Application router |
| OAuth and Picker UI | Application |
| `listExchanges` → `submitKeyResponse` sequence | sync-kit controller (headless) |
| Stable join **parameter** names (future optional helper) | sync-kit |

Typical recipient join sequence:

1. Parse join params from the URL (app).
2. Run OAuth for the intended Google account (app + sync-kit auth provider).
3. Construct transport with `selectedAppFolderId` from the URL (app).
4. Unlock or create sharing identity (sync-kit web-passkey + app store).
5. `listExchanges({ exchangeId? })` → `submitKeyResponse(invitationFileId)`
   (sync-kit controller).
6. Persist a new `AppSyncProfile` entry (app).

For invites, `inviteParticipant` already accepts `emailMessage`. The application
builds the join URL; sync-kit may later offer a message formatter, not a
deployment-specific URL builder.

## "We want sync-kit to do X"

| Expectation | Where it belongs |
| --- | --- |
| Profile switcher UI | Application |
| User-chosen backup / profile names | Application (`folderName` + profile index) |
| Deeplink landing URL and router | Application |
| Join URL query param contract | `@keyneom/sync-kit/sharing` — `parseSharingJoinParams`, `buildSharingJoinSearchParams`, `appendSharingJoinParams` |
| Resolve join invitation file | `@keyneom/sync-kit/sharing` — `findSharingJoinInvitation`, `resolveSharingJoinInvitation` |
| Dataset registry persistence across reloads | `@keyneom/sync-kit/sharing/controller` — `IndexedDbSharedBackupRegistry` (optional; one registry per app profile) |
| Invite email wording + appended join link | App provides `joinLandingUrl`; sync-kit appends `folder=` before the Drive notification, or use `formatSharingInviteEmailMessage` with a fully built URL |
| List sync-kit app folders visible to the signed-in user | `@keyneom/sync-kit/stores/google-drive` — `listAccessibleSyncKitAppFolders()` |
| Drive folder title composition + sanitization | `@keyneom/sync-kit/stores/google-drive` — `buildSyncKitFolderName`, `sanitizeDriveFolderName` |
| ACL drift after Drive-side permission changes | `@keyneom/sync-kit/sharing/controller` — `reconcileDrivePermissions()` |
| Drive change detection for notifications | `@keyneom/sync-kit/sharing` — `SharingChangeDetector`, `SharingSyncCheckpoint` |
| Foreground sharing poll hook | `@keyneom/sync-kit/sharing/lifecycle` — `bindSharingPoll` |
| Opt-in OAuth cache for SW polling (web) | `@keyneom/sync-kit/auth/google-web/cache` — `IndexedDbAuthorizationCache` |
| Background WorkManager poll (Android) | `@keyneom/sync-kit-android` — `SharingSyncWorker` |
| Local date / stale-sync reminders | Application (Tier B) |
| Merge conflicts and tombstones | Application codec |
| Passkey / OAuth prompts | Application triggers; sync-kit providers perform ceremonies |

## Anti-patterns

**Using folder name as the primary key.** Two owners can both create
`EasyBC — Personal`. Always persist and route by `appFolderId`.

**Relying on the default `Sync Kit - <appId>` name in multi-share products.**
Recipients with several shares see indistinguishable folders in Drive.

**Expecting `MemorySharedBackupRegistry` to survive reload.** Wire a persistent
`SharedBackupRegistry` implementation in the app or adopt a future optional
sync-kit store.

**Omitting `selectedAppFolderId` after first connect.** Re-finding by name alone
breaks after Drive renames and is ambiguous when multiple app-root folders
share the same `appId` property with different titles.

**Putting PII in protocol public fields.** Envelope and invitation public
metadata are visible to Drive participants. Emails in folder names or app UI
are a product choice; do not embed them in signed protocol fields unless the
spec explicitly allows it.

**Assuming sync-kit will run a full "join router".** The package stays headless.
Applications own page load, error surfaces, and when to open Picker vs join from
URL params.

## Minimal integration checklist

When adding shared backups to an application:

- [ ] Define compatibility profile values (`appId`, AAD, etc.) in the app.
- [ ] Introduce an `AppSyncProfile` index in app persistence.
- [ ] Collect a user profile label at setup; compute sanitized `folderName`.
- [ ] Persist `appFolderId` after first folder creation or Picker selection.
- [ ] Bind transport, registry, identity, and controller per profile — no
      cross-profile mixing.
- [ ] Implement profile switcher UI from the index, not from raw Drive listing.
- [ ] Document privacy copy if folder names include email or other identifiers.
- [ ] Implement join URL routing and post-OAuth join sequence for recipients.
- [ ] Offer "Copy join link" when inviting (app-built URL + optional
      `emailMessage` on `inviteParticipant`).

## Related exports today

```ts
import { GoogleDriveSharedBackupTransport } from "@keyneom/sync-kit/stores/google-drive/sharing";
import {
  buildSyncKitFolderName,
  ensureGoogleDriveSyncKitFolder,
  defaultSyncKitAppFolderName,
  listAccessibleSyncKitAppFolders,
} from "@keyneom/sync-kit/stores/google-drive";
import {
  SharedBackupController,
  MemorySharedBackupRegistry,
  IndexedDbSharedBackupRegistry,
} from "@keyneom/sync-kit/sharing/controller";
import {
  appendSharingJoinParams,
  buildSharingJoinSearchParams,
  findSharingJoinInvitation,
  formatSharingInviteEmailMessage,
  parseSharingJoinParams,
  resolveSharingJoinInvitation,
} from "@keyneom/sync-kit/sharing";
import { GoogleDriveFolderPicker, parseGoogleDriveOpenState } from "@keyneom/sync-kit/stores/google-drive/picker";
import {
  SharingChangeDetector,
  type SharingSyncCheckpoint,
} from "@keyneom/sync-kit/sharing";
import { bindSharingPoll } from "@keyneom/sync-kit/sharing/lifecycle";
import { IndexedDbAuthorizationCache } from "@keyneom/sync-kit/auth/google-web/cache";
```

- `folderName` — override the default `Sync Kit - <appId>` title. Prefer
  `buildSyncKitFolderName({ appDisplayName, profileLabel, ownerLabel })` for
  multi-profile apps.
- `selectedAppFolderId` — reconnect to an existing app folder (required for
  recipients; recommended for owners after first creation).
- `defaultSyncKitAppFolderName(appId)` — fallback only for single-context apps.
- `inviteParticipant({ joinLandingUrl, appDisplayName })` — appends the app
  folder ID to the landing URL and formats the Drive notification. Use `joinUrl`
  only when the URL is already complete (including `folder=`).
- `reconcileDrivePermissions({ datasetId, participantEmails })` — repairs Drive
  ACL drift for tracked participants when the signed-in user is owner/admin.
