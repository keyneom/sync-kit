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

- Android is the reference implementation for consumer-facing behavior; the
  web package makes a best effort to match it (some capabilities, such as
  background sync, cannot match a native app).
- JVM unit tests passing does not prove Android compatibility. Verify
  platform-dependent behavior on a real device: desktop JDKs ship JCA
  algorithms Android lacks (e.g. `SHA256withECDSAinP1363Format`), Android
  negotiates HTTP/2 with googleapis.com and receives lowercased response
  header names, and Drive v3 does not send HTTP ETags on dataset reads —
  use metadata change tokens (`headRevisionId`, `version`) instead.
