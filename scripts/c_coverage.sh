#!/usr/bin/env bash
# Line coverage of the product code (gcov), per directory and per file. Run inside WSL.
# usage: scripts/c_coverage.sh [min-percent-for-nf-and-libs]   (exit 1 if any NF/library file is below it; default: report only)
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="${G5C_C_BUILD:-$HOME/g5c-cbuild}/cov"
cmake -S "$here" -B "$out" -DG5C_COVERAGE=ON >/dev/null
cmake --build "$out" -j"$(nproc)" >/dev/null
find "$out" -name '*.gcda' -delete
ctest --test-dir "$out" -j4 --output-on-failure >/dev/null || { echo "tests failed under coverage build"; exit 1; }
python3 "$here/scripts/gcov_report.py" "$out" "$here" "${1:-0}"
