#!/usr/bin/env bash
set -euo pipefail
# Host gate for the Rust artifact equivalents: each crate's gate test
# recompiles lib.rs for the host and requires entrypoint to return 0,
# its own violation count -- the same standard test/test_zx.ml holds
# the zx sources to. Also holds each crate to fmt and clippy.
CARGO="${CARGO:-cargo}"
here="$(cd "$(dirname "$0")" && pwd)"
for name in zx_core zx_charset zx_step zx_window; do
  "$CARGO" test --quiet --manifest-path "$here/$name/Cargo.toml" -j 2
  "$CARGO" fmt --check --manifest-path "$here/$name/Cargo.toml"
  "$CARGO" clippy --quiet --manifest-path "$here/$name/Cargo.toml" --no-deps -- -D warnings
done
echo "rust host gate: all four crates green"
