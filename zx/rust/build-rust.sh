#!/usr/bin/env bash
set -euo pipefail
# Build the Rust equivalents of the zx artifacts for the M19 size
# table. cargo-build-sbf (Solana platform-tools) targets the same SBF
# machine the ZxCaml artifacts target; the crates have no
# dependencies, so the platform-tools cargo 1.84 edition-2024
# lockfile trap cannot bite.
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/out"
for name in zx_core zx_charset zx_step zx_window; do
  cargo-build-sbf --manifest-path "$here/$name/Cargo.toml" --sbf-out-dir "$here/out"
done
ls -la "$here"/out/*.so
