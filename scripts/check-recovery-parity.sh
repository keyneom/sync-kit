#!/usr/bin/env bash
# Android writes recovery-code artifacts and the web package must open them:
# a participant-keys history with an Android-sealed recovery key, and a v2
# private snapshot with an Android-sealed recovery lock. The reverse directions
# are fixtures/sharing-v1/participant-keys.json and fixtures/v2/snapshot-recovery.json,
# verified by ParticipantKeysTest and SnapshotRecoveryTest.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="${TMPDIR:-/tmp}/sync-kit-recovery-$$"
REPORT="$OUT/participant-keys.json"
SNAPSHOT="$OUT/snapshot.json"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT"

if [ -z "${JAVA_HOME:-}" ] && \
  [ -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
  export PATH="$JAVA_HOME/bin:$PATH"
fi

echo "→ Build JS package"
(cd "$ROOT" && npm run build --silent)

echo "→ Android writes a participant-keys history and a v2 snapshot"
(
  cd "$ROOT/android"
  PARTICIPANT_KEYS_OUTPUT="$REPORT" SNAPSHOT_RECOVERY_OUTPUT="$SNAPSHOT" \
    ./gradlew --quiet --rerun-tasks :synckit:testDebugUnitTest \
      --tests 'com.keyneom.synckit.sharing.ParticipantKeysTest' \
      --tests 'com.keyneom.synckit.snapshot.SnapshotRecoveryTest'
)
for file in "$REPORT" "$SNAPSHOT"; do
  [ -f "$file" ] || { echo "Android did not write $file" >&2; exit 1; }
done

echo "→ Web opens them"
node "$ROOT/scripts/check-participant-keys-parity.mjs" "$REPORT"
node "$ROOT/scripts/check-snapshot-recovery-parity.mjs" "$SNAPSHOT"
