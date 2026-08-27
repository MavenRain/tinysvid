#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

# model checker + every test suite (model/check is a dune test)
dune build --root "$here"
dune runtest --root "$here" --force

# M28 end-to-end demo: the fake agent and the client over a real socket,
# with its own negative controls
"$here/demo/demo.sh"

# zx artifacts: rebuild on --zx, otherwise use what is in zx/out
if [ "${1:-}" = "--zx" ]; then
  "$here/zx/build-zx.sh"
fi

# M30 size regression: every artifact in the budget must exist (once any
# artifact does), be newer than every zx source, and fit its budget. A
# stale artifact would make the check a false pass, so it is a failure,
# not a skip.
budget="$here/zx/size-budget.txt"
if ls "$here"/zx/out/*.so >/dev/null 2>&1; then
  while read -r name max; do
    case "$name" in ''|'#'*) continue ;; esac
    so="$here/zx/out/$name.so"
    if [ ! -f "$so" ]; then
      echo "size: $name.so missing (run ./gates.sh --zx)"
      exit 1
    fi
    stale=$(find "$here/zx" -maxdepth 1 \( -name '*.ml' -o -name 'build-zx.sh' \) -newer "$so")
    if [ -n "$stale" ]; then
      echo "size: $name.so is older than $(echo "$stale" | tr '\n' ' ')(run ./gates.sh --zx)"
      exit 1
    fi
    actual=$(wc -c < "$so" | tr -d ' ')
    if [ "$actual" -gt "$max" ]; then
      echo "size regression: $name.so $actual B > budget $max B"
      exit 1
    fi
    echo "size ok: $name.so $actual B <= $max B"
  done < "$budget"
else
  echo "size: skipped (no zx artifacts in zx/out; run ./gates.sh --zx)"
fi

echo "gates green"
