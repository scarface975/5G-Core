#!/usr/bin/env bash
# usage: scripts/cov_missing.sh <path-substring>...   (after scripts/c_coverage.sh) lists uncovered line ranges
here="$(cd "$(dirname "$0")/.." && pwd)"
for m in "$@"; do MISSING="$m" python3 "$here/scripts/gcov_report.py" "${G5C_C_BUILD:-$HOME/g5c-cbuild}/cov" "$here" 0 | grep -E '^(nf|libs|ctl)/[^ ]* [0-9]'; done
