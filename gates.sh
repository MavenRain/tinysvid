#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dune build --root "$here"
dune runtest --root "$here" --force
if [ "${1:-}" = "--zx" ]; then
  "$here/zx/build-zx.sh"
fi
echo "gates green"
