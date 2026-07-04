#!/usr/bin/env bash
# Compare deterministic v1 outputs from the JS package and Kotlin Android library,
# then cross-decrypt each platform's compressed peerChallenge envelope.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="${TMPDIR:-/tmp}/sync-kit-js-kotlin-parity-$$"
JS_REPORT="$OUT/js.json"
KT_REPORT="$OUT/kotlin.json"
JS_IDENTICAL="$OUT/js-identical.json"
KT_IDENTICAL="$OUT/kotlin-identical.json"

cleanup() {
  rm -rf "$OUT"
}
trap cleanup EXIT

mkdir -p "$OUT"

if [ -z "${JAVA_HOME:-}" ] && \
  [ -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
  export PATH="$JAVA_HOME/bin:$PATH"
fi

if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
  if [ -f "$ROOT/android/local.properties" ]; then
    sdk_dir=$(sed -n 's/^sdk.dir=//p' "$ROOT/android/local.properties" | head -n1 | tr -d '\r')
    if [ -n "$sdk_dir" ]; then
      export ANDROID_HOME="$sdk_dir"
    fi
  fi
fi

echo "→ Build JS package"
(cd "$ROOT" && npm run build --silent)

echo "→ JS parity report"
node "$ROOT/scripts/parity-v1-report.mjs" >"$JS_REPORT"

echo "→ Kotlin parity report (+ decrypt JS peerChallenge)"
rm -f "$ROOT/android/synckit/build/reports/parity-v1.json"
(
  cd "$ROOT/android"
  PARITY_OUTPUT="$KT_REPORT" \
  PARITY_PEER_REPORT="$JS_REPORT" \
    ./gradlew --quiet :synckit:testDebugUnitTest \
      --tests 'com.keyneom.synckit.parity.ParityReportTest'
)

if [ ! -f "$KT_REPORT" ]; then
  if [ -f "$ROOT/android/synckit/build/reports/parity-v1.json" ]; then
    cp "$ROOT/android/synckit/build/reports/parity-v1.json" "$KT_REPORT"
  else
    echo "Kotlin parity report was not written to $KT_REPORT" >&2
    exit 1
  fi
fi

echo "→ Normalize identical sections"
node "$ROOT/scripts/normalize-parity-identical.mjs" "$JS_REPORT" "$JS_IDENTICAL"
node "$ROOT/scripts/normalize-parity-identical.mjs" "$KT_REPORT" "$KT_IDENTICAL"

echo "→ Diff identical section (content keys, fixtures, encrypt, rejections)"
if ! diff -u "$JS_IDENTICAL" "$KT_IDENTICAL"; then
  echo "JS and Kotlin identical sections differ." >&2
  exit 1
fi

echo "→ JS decrypts Kotlin compressed peerChallenge"
node "$ROOT/scripts/parity-v1-cross-decrypt.mjs" "$KT_REPORT" >/dev/null

echo "OK: JS and Kotlin v1 private-snapshot crypto are at parity."
