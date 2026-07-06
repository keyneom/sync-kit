# Drive v2+v3 hybrid: true conditional writes

Status: **designed, gated on live validation** (`scripts/validate-drive-v2-etag.mjs`).

## Why

Drive v3 removed ETags entirely — the v3 discovery document contains no `etag`
field on any resource — so v3 offers **no server-side compare-and-swap**. The
sharing design assumed ETag/`If-Match` preconditions (a Drive v2 idiom); the
"validate against live Drive" checklist items were never run, and mocks kept
the assumption alive until on-device testing failed with "did not expose an
ETag" (fixed in 0.2.0-rc.4 by falling back to `headRevisionId`/`version`
change tokens plus a pre-write freshness check).

The rc.4 model is data-safe — a lost race becomes a fork that
`resolveFork`/merge recovers, because the envelope `parentRevisionId` chain is
the real ordering authority — but the write itself is not conditional: a
narrow preflight→upload window remains where the last HTTP writer wins.

## What v2 still offers

Verified from the public discovery documents (2026-07-06):

- v2 `File` has `etag`, `headRevisionId`, and `version` **in the JSON body**
  (immune to HTTP/2 lowercasing and browser CORS header filtering — the two
  failure modes that bit v3 header handling).
- v2 `files.get` and `files.update` accept the same `drive.file` and
  `drive.appdata` scopes; the OAuth token needs no changes.
- v2 media upload exists at `PUT /upload/drive/v2/files/{fileId}?uploadType=media`.
- File IDs are shared between v2 and v3 — the same file can be read through
  either surface.

## Design

Everything stays on v3 except the conditional write inside
`GoogleDriveSharedBackupTransport.writeDataset`:

1. Replace the current v3 freshness preflight with a **v2 metadata GET**
   (`GET /drive/v2/files/{id}?fields=etag,headRevisionId`).
   - Compare `headRevisionId` to the version token captured at read time —
     rejects anything that changed since we read (same semantics as today).
2. Upload via the **v2 media endpoint** with `If-Match: <etag from step 1>`.
   - This closes the remaining preflight→upload window: a concurrent writer
     changes the etag and our upload fails with **HTTP 412** → `CONFLICT`.
   - The v2 update response body returns the new `etag`, so the fresh version
     token comes back without any extra request or header dependency.
3. Reads (`readDataset`), listing, permissions, exchanges, folder management
   all remain v3. Stored version tokens remain v3 `headRevisionId` values;
   the v2 etag is fetched only inside the write and never persisted.
4. **Runtime fallback:** if the v2 endpoints ever return 404/410 (API
   shutdown), log once and degrade to the rc.4 preflight-only path. The
   envelope chain and fork-merge remain as the correctness backstop either
   way, so v2 disappearing can never break writes — it only widens the race
   window back to rc.4's.

Net cost: zero additional round trips versus rc.4 (the preflight GET moves
from v3 to v2), one added header, and one fallback branch.

## Necessary changes

- `android/.../stores/GoogleDriveSharedBackupTransport.kt` and
  `src/stores/google-drive/sharing.ts`: swap the preflight to v2, add
  `If-Match` on the upload, parse the response-body etag, add the fallback.
- `GoogleDriveFileStore` (both platforms): small helpers for the v2 metadata
  GET and v2 media upload (the v2 JSON shape differs from v3; only
  `etag`/`headRevisionId` are needed).
- Tests: MockWebServer/vitest coverage for match → 200, stale → 412 →
  `CONFLICT`, and the 404/410 → fallback path.
- No wire-format or registry changes: version tokens are local-only state.

## Gate before implementing

Run `ACCESS_TOKEN=... node scripts/validate-drive-v2-etag.mjs` (drive.file
token, e.g. from the OAuth playground). It must show: body etag present,
matching If-Match update → 200, stale If-Match update → 412. If the stale
write does **not** 412, Drive no longer enforces v2 preconditions and this
design is dead — stay on the rc.4 model.

## Risk

Drive v2 is legacy surface and may eventually be shut down; the runtime
fallback bounds the blast radius to "races behave like rc.4 again". Re-run
the validation script when Google announces Drive API changes.
