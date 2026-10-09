#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/kpqc-swift.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM

cd "$root"
ruby scripts/generate_native_sources.rb

find Sources/KpqCCore/Generated -name '*.c' -print | sort | while IFS= read -r source; do
  object="$build/$(printf '%s' "$source" | tr '/+' '__').o"
  clang -std=c11 -O2 -fvisibility=hidden -fno-strict-aliasing -w \
    -I "$root" -c "$source" -o "$object"
done
clang -std=c11 -O2 -fvisibility=hidden -w -I "$root" \
  -c native/csrc/secure_zero.c -o "$build/secure_zero.o"
ar rcs "$build/libKpqCCore.a" "$build"/*.o

swiftc -module-name KpqC \
  -module-cache-path "$build/module-cache" \
  -import-objc-header Sources/KpqCCore/include/KpqCCore.h \
  Sources/KpqC/*.swift Tests/Smoke/main.swift \
  "$build/libKpqCCore.a" -o "$build/kpqc-smoke"
"$build/kpqc-smoke"

if [ "$(uname -s)" = "Darwin" ]; then
  shared_flags="-dynamiclib"
  extension="dylib"
else
  shared_flags="-shared"
  extension="so"
fi

# shellcheck disable=SC2086
clang $shared_flags -std=c11 -O2 -fPIC -fvisibility=hidden \
  -fno-strict-aliasing -w -DKPQC_TEST_ENTROPY -I "$root" \
  $(find Sources/KpqCCore/Generated -name '*.c' -print | sort) \
  -o "$build/libkpqc_test.$extension"
if [ -n "${KPQC_TEST_VECTORS:-}" ]; then
  python3 Tests/KpqCTests/test_kat.py \
    "$build/libkpqc_test.$extension" "$KPQC_TEST_VECTORS"
else
  python3 Tests/KpqCTests/test_kat.py "$build/libkpqc_test.$extension"
fi
