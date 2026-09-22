# sync-kit 0.4.4

Corrections to published guidance, and a release check that prevents the same
class of error from shipping again. No signature, behavior, or format change.

## Corrected import paths

0.4.3 named the single-account multi-device identity pattern but attributed
`DriveAppDataProtectedSharingIdentityStore` and
`MigratingProtectedSharingIdentityStore` to `/sharing`. Neither is exported
there. The README shipped in the 0.4.3 package carries the wrong paths.

```ts
import { PasskeyProtectedSharingIdentityProvider } from "@keyneom/sync-kit/sharing/web-passkey";
import { DriveAppDataProtectedSharingIdentityStore } from "@keyneom/sync-kit/sharing/appdata-identity-store";
import { MigratingProtectedSharingIdentityStore } from "@keyneom/sync-kit/sharing/migrating-identity-store";
```

A wrong path was worse than none here: those exports were named precisely
because a consumer could not find them, and authoritative guidance to a dead end
reproduces that failure.

## Android install coordinate

`docs/android-library.md` told consumers to install
`com.keyneom:sync-kit-android:0.3.0` — pre-mutator, and older than every
contract the rest of that page describes. It had drifted for four releases.

## Android asset-link error links somewhere reachable

The 0.4.2 `AndroidPasskeyKeyProvider` error pointed at `docs/android-library.md`,
which is not part of the Android artifact. It now links the section on GitHub.

## `pack:check` verifies what the documentation promises

Three changes to `scripts/check-package.mjs`, which runs on every release:

- **Every exported subpath is import-tested**, derived from the exports map.
  The list was hardcoded and had silently stopped covering three subpaths —
  `/sharing/control`, `/sharing/appdata-identity-store`, and
  `/sharing/migrating-identity-store`, the latter two being the stores the docs
  call the supported pattern.
- **Documented imports must resolve against the packed tarball.** Every
  `import { … } from "@keyneom/sync-kit/…"` in the README and `docs/`, plus the
  `` `Name` (`/subpath`) `` and `` `/subpath` — `Name` `` shapes, is checked
  against the installed package, not the source tree. The exports map is
  invisible from `src/`, which is why the 0.4.3 error read as correct there.
  Verified to fail on that exact error when it is reintroduced.
- **The Android install snippet must name the version being released.**

This is narrower than the open checklist gate of integrating a real consumer
from the packed artifact: it proves the documentation matches the package, not
that a consumer following it succeeds.
