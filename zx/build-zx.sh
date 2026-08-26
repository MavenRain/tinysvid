#!/usr/bin/env bash
set -euo pipefail
# omlz needs the zig toolchain, the solana-zig symlink, and the zxcaml-p1
# opam switch. The default wrapper sets all three.
OMLZ="${OMLZ:-$HOME/Documents/claude1/zxcaml-bench/omlz-run.sh}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/out"
"$OMLZ" build "$here/zx_core.ml" --target=bpf -o "$here/out/zx_core.so"
ls -la "$here/out/zx_core.so"
