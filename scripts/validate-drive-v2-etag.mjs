// Live validation: does Drive v2 still enforce ETag/If-Match preconditions?
//
// Drive v3 removed ETags entirely (no etag field anywhere in its discovery
// document), so the only way to get true server-side compare-and-swap is the
// v2 endpoints. This script proves — against the real API, not mocks — that:
//   1. v2 files.get returns an etag in the JSON body,
//   2. a media update with a matching If-Match succeeds,
//   3. a media update with a stale If-Match fails with HTTP 412.
//
// Usage:
//   ACCESS_TOKEN=ya29... node scripts/validate-drive-v2-etag.mjs
//
// Get a token with the drive.file scope from
// https://developers.google.com/oauthplayground (the script only touches a
// throwaway file it creates itself, and deletes it afterwards).

const token = process.env.ACCESS_TOKEN;
if (!token) {
  console.error("Set ACCESS_TOKEN (drive.file scope).");
  process.exit(1);
}

const auth = { Authorization: `Bearer ${token}` };

async function call(label, url, init = {}, expected = [200]) {
  const response = await fetch(url, {
    ...init,
    headers: { ...auth, ...(init.headers ?? {}) },
  });
  const body = await response.text();
  const ok = expected.includes(response.status);
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}: HTTP ${response.status}`);
  if (!ok) {
    console.error(body.slice(0, 400));
    process.exit(1);
  }
  return body ? JSON.parse(body) : {};
}

// Create a throwaway file (v3 create so drive.file scope owns it).
const created = await call(
  "create test file (v3)",
  "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id",
  {
    method: "POST",
    headers: { "Content-Type": "multipart/related; boundary=b" },
    body: [
      "--b",
      "Content-Type: application/json",
      "",
      JSON.stringify({ name: "sync-kit-etag-probe.json" }),
      "--b",
      "Content-Type: application/json",
      "",
      '{"probe":1}',
      "--b--",
    ].join("\r\n"),
  },
);
const fileId = created.id;

try {
  // 1. v2 metadata carries etag + headRevisionId in the body.
  const meta = await call(
    "read v2 metadata etag",
    `https://www.googleapis.com/drive/v2/files/${fileId}?fields=etag,headRevisionId,version`,
  );
  if (!meta.etag) {
    console.error("FAIL  v2 metadata has no etag field value.");
    process.exit(1);
  }
  console.log(`      etag=${meta.etag} headRevisionId=${meta.headRevisionId ?? "-"}`);

  // 2. Conditional write with the current etag must succeed.
  await call(
    "If-Match write with current etag",
    `https://www.googleapis.com/upload/drive/v2/files/${fileId}?uploadType=media`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json", "If-Match": meta.etag },
      body: '{"probe":2}',
    },
  );

  // 3. Re-using the now-stale etag must be rejected with 412.
  await call(
    "If-Match write with stale etag (expect 412)",
    `https://www.googleapis.com/upload/drive/v2/files/${fileId}?uploadType=media`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json", "If-Match": meta.etag },
      body: '{"probe":3}',
    },
    [412],
  );

  console.log("\nAll checks passed: Drive v2 ETag/If-Match CAS is live.");
} finally {
  await call(
    "delete test file",
    `https://www.googleapis.com/drive/v3/files/${fileId}`,
    { method: "DELETE" },
    [204, 200],
  );
}
