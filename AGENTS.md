# Repository instructions

This repository is a compatibility-preserving extraction from existing
applications, not a greenfield sync redesign.

Before implementation:

1. Read `README.md`, `docs/implementation-plan.md`,
   `docs/execution-checklist.md`, and `docs/source-inventory.md`.
2. Re-check the live EasyBC and Family Chores source trees. Family Chores sync
   code was uncommitted when this repository was created.
3. Freeze deterministic v1 fixtures before moving crypto or envelope code.

Engineering constraints:

- Keep one package with subpath exports.
- Keep `/core`, `/crypto`, and the package root browser-independent and free of
  import-time side effects.
- Preserve exact v1 compatibility constants and formats.
- Keep consumer schemas, merge policy, persistence, UI, and lifecycle policy
  outside this package.
- Keep `package.json` private until publication decisions are explicit.
- Do not claim Android/web compatibility without cross-platform fixture tests.
- Work in releasable phases and record completed gates in the execution
  checklist.

Platform parity:

- Do not cut, tag, or publish a release that introduces a consumer-facing
  sharing/sync protocol, persisted format, invitation, or controller behavior
  on web without an interoperable Android implementation (or vice versa).
  Platform-only facilities are acceptable only when they do not create or
  mutate cross-platform state the other platform cannot consume. Any exception
  requires the user's explicit approval for that specific release; record the
  approved exception and its exact interoperability limit in the execution
  checklist and release notes before tagging. Silence, schedule pressure, and
  a green single-platform test suite are not approval.
- Android is the reference implementation for consumer-facing behavior; the
  web package makes a best effort to match it (some capabilities, such as
  background sync, cannot match a native app).
- JVM unit tests passing does not prove Android compatibility. Verify
  platform-dependent behavior on a real device: desktop JDKs ship JCA
  algorithms Android lacks (e.g. `SHA256withECDSAinP1363Format`), Android
  negotiates HTTP/2 with googleapis.com and receives lowercased response
  header names, and Drive v3 does not send HTTP ETags on dataset reads —
  use metadata change tokens (`headRevisionId`, `version`) instead.
- `drive.file` cannot see files shared from another account (Drive returns
  404) until the user grants them explicitly — on web that grant is the
  Google Picker; Android's SAF/Files app cannot substitute (its grants are
  device-local, never reaching the Drive API ACL). Picker grants are keyed
  to the Cloud project, so native apps can hand off to a web page running
  the Picker and the grant covers their tokens too.
