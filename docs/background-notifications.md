# Background notifications and change detection

This document defines how sync-kit helps applications notify users about
sharing and sync activity without performing cryptographic writes in the
background. It complements [consumer-responsibilities.md](consumer-responsibilities.md).

Android is the primary target for continuous background detection. Web
support is best-effort within Google access-token lifetime (~one hour).

## Two notification tiers

| Tier | Needs Google token? | Needs passkey unlock? | sync-kit | Application |
| --- | --- | --- | --- | --- |
| **A — Drive detect** | Yes | No | Poll helpers, checkpoints, events | SW / WorkManager, notification UI |
| **B — Local remind** | No | No | Checkpoint field types only | Schedule rules, local index, alarms |
| **Full sync** | Yes | Yes | Headless APIs | OAuth, unlock, merge UI |

Tier A detects **that something changed on Drive**. Tier B reminds users based
on **local app data** (dates, last sync time, preferences). Full sync runs
only after the user opens the app and unlocks.

## Tier A: Drive-aware detection

### What sync-kit polls (metadata only)

- **Pending key responses** — new files in `exchanges/` with kind `key-response`
- **Dataset head changes** — `etag` / `modifiedTime` per dataset file without
  downloading envelope bodies
- **Token state** — access token valid, expiring soon, or expired

### Events

Applications map these to OS notifications:

| Event | Typical meaning |
| --- | --- |
| `pending-key-response` | A recipient submitted a key; owner should open and accept |
| `shared-dataset-changed` | A dataset head changed on Drive; participant should sync |
| `token-expiring-soon` | Poll will stop working soon (web) |
| `token-expired` | Re-authenticate to resume Drive detection |

### Security rules

- **Web:** opt-in `IndexedDbAuthorizationCache` stores **access token + expiry
  only**. No refresh tokens in browser storage. Default remains memory-only.
- **Android:** refresh tokens stay in app secure storage; sync-kit accepts
  tokens from an `AuthorizationProvider` the app implements.
- **Never in background workers:** `acceptKeyResponse`, decrypt, sign,
  `syncDataset`, or passkey ceremonies.

### Platform limits

**Web**

- Google user access tokens expire in ~one hour and cannot be extended.
- Tier A works until expiry after the last interactive OAuth; then emit
  `token-expired` and fall back to Tier B nudges.
- Service worker integration is documented as a pattern; sync-kit does not
  register workers.

**Android**

- `SharingSyncWorker` (WorkManager) refreshes access via the app provider,
  then polls metadata.
- Subject to Doze, battery optimization, and minimum periodic intervals.
- Can approach continuous detection with refresh tokens.

## Tier B: Local reminders (application-owned)

sync-kit does **not** implement local schedule logic. Applications may:

- Store a denormalized reminder index (dates, flags) readable by SW / worker
- Notify when `now - lastSyncAt > threshold`
- Notify on product-specific dates without any Google token

Examples belong in consumer apps, not in this package.

## Checkpoints

`SharingSyncCheckpoint` is JSON-serializable and shared across platforms:

```json
{
  "lastPollAt": "2026-07-05T12:00:00.000Z",
  "lastSeenExchangeIds": ["exchange-1"],
  "datasetHeads": {
    "tasks": { "fileId": "abc", "etag": "\"1\"", "modifiedTime": "..." }
  }
}
```

Persist checkpoints per sync/sharing profile in application storage.

## Invite join links and exchange IDs

Invite email join URLs use **folder ID only** (`?sync=join&folder=…`).
`exchangeId` is assigned after the Drive notification is sent and is optional
in join URLs for runtime disambiguation when multiple pending invitations exist.

## Service worker integration (web)

sync-kit does **not** ship a service worker. Applications that want Tier A
polling while the tab is closed can:

1. Register a service worker in the consumer app.
2. On foreground OAuth success, wrap the authorization provider with
   `CachingAuthorizationProvider` and persist short-lived access tokens via
   `IndexedDbAuthorizationCache` (opt-in; cleared on lock/logout).
3. In the service worker `fetch` or periodic sync handler, load the cached
   token and checkpoint, construct a `SharingChangeDetector` from a transport
   bound to that token, call `detect(checkpoint)`, persist the updated
   checkpoint, and post notification events to clients.
4. When the token is expired (~1 hour), emit or handle `token-expired` and
   defer accept/decrypt/sync until the user opens the app.

```typescript
// Foreground: mirror tokens for SW polling
import { CachingAuthorizationProvider, IndexedDbAuthorizationCache } from "@keyneom/sync-kit/auth/google-web/cache";

// SW message handler (app-owned):
// checkpoint → SharingChangeDetector.detect → showNotification / postMessage
```

Never call `acceptKeyResponse`, decrypt, or `syncDataset` from the service
worker.

## API surfaces

**npm**

- `/sharing` — `SharingSyncCheckpoint`, `SharingChangeDetector`,
  `SharingNotificationEvent`
- `/sharing/lifecycle` — `bindSharingPoll` (foreground polling)
- `/auth/google-web/cache` — opt-in `IndexedDbAuthorizationCache`

**Android (`com.keyneom:sync-kit-android`)**

- `sharing.SharingChangeDetector`
- `sharing.SharingSyncCheckpoint`
- `sharing.work.SharingSyncWorker`
- App implements refresh policy and WorkManager scheduling

## Integration sketch

```text
Background (Tier A):
  load checkpoint + authorization
  → SharingChangeDetector.poll(...)
  → save checkpoint
  → app shows notification for each new event

User taps notification:
  → open app → OAuth if needed → passkey unlock
  → acceptKeyResponse / syncDataset
```

See [android-library.md](android-library.md) for the Android-first integration
path and [consumer-responsibilities.md](consumer-responsibilities.md) for the
full boundary matrix.
