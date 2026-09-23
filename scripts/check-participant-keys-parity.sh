#!/usr/bin/env bash
# Android writes a participant-keys history; the web package must verify it and
# open the Android-sealed recovery key. The reverse direction is
# fixtures/sharing-v1/participant-keys.json, verified by ParticipantKeysTest.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="${TMPDIR:-/tmp}/sync-kit-participant-keys-$$"
REPORT="$OUT/android.json"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT"

if [ -z "${JAVA_HOME:-}" ] && \
  [ -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
  export PATH="$JAVA_HOME/bin:$PATH"
fi

echo "→ Build JS package"
(cd "$ROOT" && npm run build --silent)

echo "→ Android writes a participant-keys history"
(
  cd "$ROOT/android"
  PARTICIPANT_KEYS_OUTPUT="$REPORT" \
    ./gradlew --quiet --rerun-tasks :synckit:testDebugUnitTest \
      --tests 'com.keyneom.synckit.sharing.ParticipantKeysTest'
)
[ -f "$REPORT" ] || { echo "Android did not write $REPORT" >&2; exit 1; }

echo "→ Web verifies it"
node "$ROOT/scripts/check-participant-keys-parity.mjs" "$REPORT"
