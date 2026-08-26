#!/usr/bin/env bash
set -euo pipefail
# omlz needs the zig toolchain, the solana-zig symlink, and the zxcaml-p1
# opam switch. The default wrapper sets all three.
OMLZ="${OMLZ:-$HOME/Documents/claude1/zxcaml-bench/omlz-run.sh}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/out"
for name in zx_core zx_charset zx_step zx_window; do
  "$OMLZ" build "$here/$name.ml" --target=bpf -o "$here/out/$name.so"
done
ls -la "$here"/out/*.so
