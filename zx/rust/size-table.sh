#!/usr/bin/env bash
set -euo pipefail
# M19: print the size table comparing each ZxCaml artifact (zx/out)
# with its Rust equivalent (zx/rust/out). Build both first:
#   ./zx/build-zx.sh && ./zx/rust/build-rust.sh
here="$(cd "$(dirname "$0")" && pwd)"
zxout="$here/../out"
printf '%-12s %12s %10s %7s\n' artifact "zxcaml (B)" "rust (B)" ratio
for name in zx_core zx_charset zx_step zx_window; do
  z=$(stat -f%z "$zxout/$name.so")
  r=$(stat -f%z "$here/out/$name.so")
  printf '%-12s %12s %10s %7s\n' "$name" "$z" "$r" \
    "$(awk -v r="$r" -v z="$z" 'BEGIN { printf "%.2f", r / z }')"
done
