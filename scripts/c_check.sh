#!/usr/bin/env bash
# Build and test the C tree twice: plain and under ASan+UBSan. Run inside WSL.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="${G5C_C_BUILD:-$HOME/g5c-cbuild}"
for mode in plain asan; do
  flag=OFF; [ "$mode" = asan ] && flag=ON
  cmake -S "$here" -B "$out/$mode" -DG5C_SANITIZE=$flag >/dev/null
  cmake --build "$out/$mode" -j"$(nproc)"
  ctest --test-dir "$out/$mode" --output-on-failure
done
