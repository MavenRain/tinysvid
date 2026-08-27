#!/usr/bin/env bash
# M28: the end-to-end demo, self-contained. A fake Workload API agent
# serves one FetchX509SVID call over a real Unix-domain socket; the
# demo client fetches through the typed engine. Two negative controls
# keep the run honest: a truncated response body and an empty bundle
# must both fail. Sockets live under /tmp because the sun_path bound
# (103 bytes on macOS) rejects deep temp paths.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

dune build --root "$root" demo/fetch_svid.exe demo/fake_agent.exe
fetch="$root/_build/default/demo/fetch_svid.exe"
fake="$root/_build/default/demo/fake_agent.exe"

sockdir="$(mktemp -d /tmp/tinysvid-demo.XXXXXX)"
agent=""
# an early abort (a socket that never appears, a failed wait) must not
# leave the backgrounded agent running
cleanup() {
  [ -n "$agent" ] && kill "$agent" 2>/dev/null || true
  rm -rf "$sockdir"
}
trap cleanup EXIT

wait_sock() {
  for _ in $(seq 1 100); do
    [ -S "$1" ] && return 0
    sleep 0.05
  done
  echo "demo: socket $1 never appeared"
  return 1
}

# positive: fetch succeeds and prints the served identity and one root
sock="$sockdir/api.sock"
"$fake" "$sock" & agent=$!
wait_sock "$sock"
out="$("$fetch" "$sock")"
echo "$out"
wait "$agent"
case "$out" in
  *"svid: spiffe://example.org/demo"*) ;;
  *) echo "demo: expected identity missing"; exit 1 ;;
esac
case "$out" in
  *"roots: 1"*) ;;
  *) echo "demo: expected one bundle root"; exit 1 ;;
esac

# negative: a truncated response body must fail the client
sock="$sockdir/bad.sock"
"$fake" "$sock" bad & agent=$!
wait_sock "$sock"
if "$fetch" "$sock" >/dev/null 2>&1; then
  echo "demo: truncated response was accepted"; exit 1
fi
wait "$agent" || true

# negative: an empty bundle must fail the client-side bundle parse
sock="$sockdir/empty.sock"
"$fake" "$sock" emptybundle & agent=$!
wait_sock "$sock"
if "$fetch" "$sock" >/dev/null 2>&1; then
  echo "demo: empty bundle was accepted"; exit 1
fi
wait "$agent" || true

# env-var form: the client honors SPIFFE_ENDPOINT_SOCKET with unix://
sock="$sockdir/env.sock"
"$fake" "$sock" & agent=$!
wait_sock "$sock"
SPIFFE_ENDPOINT_SOCKET="unix://$sock" "$fetch" >/dev/null
wait "$agent"

echo "demo green"
