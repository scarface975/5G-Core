#!/usr/bin/env bash
# Build the optimised C tree and install the NF binaries to $G5C_PREFIX (default ~/.cache/g5c-bin). Run inside WSL/Linux.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="${G5C_C_BUILD:-$HOME/g5c-cbuild}/release"
prefix="${G5C_PREFIX:-$HOME/.cache/g5c-bin}"
cmake -S "$here" -B "$out" -DG5C_SANITIZE=OFF >/dev/null
cmake --build "$out" -j"$(nproc)"
cmake --install "$out" --prefix "$prefix" >/dev/null
echo "installed: $(ls "$prefix/bin" | tr '\n' ' ') -> $prefix/bin"
