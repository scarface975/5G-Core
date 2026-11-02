#!/usr/bin/env bash
# Run named ctest tests in the plain, ASan+UBSan and TSan builds (builds them first).
# usage: scripts/run_in_modes.sh <ctest -R regex>
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="${G5C_C_BUILD:-$HOME/g5c-cbuild}"
for m in "plain:-DG5C_SANITIZE=OFF" "asan:-DG5C_SANITIZE=ON" "tsan:-DG5C_TSAN=ON"; do
  mode="${m%%:*}"; flag="${m#*:}"
  cmake -S "$here" -B "$out/$mode" $flag >/dev/null && cmake --build "$out/$mode" -j"$(nproc)" 2>&1 | grep -E ' error|warning:' -A5
  echo "== $mode"
  TSAN_OPTIONS="halt_on_error=1" ctest --test-dir "$out/$mode" -R "$1" --output-on-failure 2>&1 | grep -E "Test +#|tests passed|FAIL|ERROR|Sanitizer|runtime error|SUMMARY" | head -20
done
