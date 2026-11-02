#!/usr/bin/env bash
# ThreadSanitizer run of the whole suite (the SBI server and the NFs are multi-threaded). Run inside WSL.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="${G5C_C_BUILD:-$HOME/g5c-cbuild}/tsan"
cmake -S "$here" -B "$out" -DG5C_TSAN=ON >/dev/null
cmake --build "$out" -j"$(nproc)"
TSAN_OPTIONS="halt_on_error=1 second_deadlock_stack=1" ctest --test-dir "$out" --output-on-failure "$@"
