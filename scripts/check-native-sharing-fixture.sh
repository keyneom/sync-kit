#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT="${TMPDIR:-/tmp}/sync-kit-native-sharing"

if [ -z "${JAVA_HOME:-}" ] && \
  [ -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]; then
  JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
  export JAVA_HOME
  PATH="$JAVA_HOME/bin:$PATH"
  export PATH
fi

mkdir -p "$OUTPUT"
javac -d "$OUTPUT" "$ROOT/native/java/SharingFixtureVerifier.java"
java -cp "$OUTPUT" SharingFixtureVerifier \
  "$ROOT/fixtures/sharing-v1/webcrypto-owner-viewer.json"

# Kotlin parity: SharingFixtureTest reads the same fixture from test resources.
(cd "$ROOT/android" && ./gradlew :synckit:test --quiet)
