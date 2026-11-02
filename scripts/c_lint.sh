#!/usr/bin/env bash
# Static gates for the C tree (run inside WSL/Linux): banned functions, dependency licences, and GCC's static analyser.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
fail=0

echo "== banned functions in production sources"
if grep -rnE "\b(strcpy|strcat|sprintf|vsprintf|gets|strncpy|strtok|alloca)\s*\(" --include=*.c --include=*.h libs nf \
     | grep -v "/tests/" | grep -vE "/(schema|defs)\.c:"; then
  echo "FAIL: use g5c_bytes / snprintf / memcpy with checked lengths instead"; fail=1
else echo "ok"; fi

echo "== dependency licences"
deps="$(grep -rhE "find_package|pkg_check_modules" --include=CMakeLists.txt . | grep -v '^\./build' \
        | sed -E 's/.*(find_package\(([A-Za-z0-9]+)|pkg_check_modules\([A-Z0-9_]+ +REQUIRED +IMPORTED_TARGET +([a-z0-9]+)).*/\2\3/' | sort -u)"
for d in $deps; do
  case "$d" in
    OpenSSL|libnghttp2|libuv|Threads|PkgConfig) echo "ok   $d" ;;
    *) echo "FAIL $d is not listed in docs/legal/THIRD_PARTY.md"; fail=1 ;;
  esac
done

# libpq is found with find_library (the UDR builds without it): its licence is the PostgreSQL licence, permissive, and it is listed in docs/legal/THIRD_PARTY.md
if grep -q "find_library(G5C_PQ_LIB" nf/udr/CMakeLists.txt; then
  grep -q "libpq" docs/legal/THIRD_PARTY.md && echo "ok   libpq (PostgreSQL licence, optional)" || { echo "FAIL libpq is not listed in docs/legal/THIRD_PARTY.md"; fail=1; }
fi

echo "== GCC static analyser (-fanalyzer, warnings are errors)"
out="${G5C_C_BUILD:-$HOME/g5c-cbuild}/analyze"
CFLAGS="-fanalyzer" cmake -S . -B "$out" -DG5C_SANITIZE=OFF >/dev/null
if cmake --build "$out" -j"$(nproc)" -k 2>&1 | grep -E "error|warning"; then fail=1; else echo "ok"; fi

exit $fail
