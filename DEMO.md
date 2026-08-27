# End-to-end demo (M28)

The demo runs one FetchX509SVID call over a Unix-domain socket and
prints what the typed toolkit certifies: the parsed SPIFFE ID, the
certificate and key byte counts, and the number of roots the bundle
parser accepts. A malformed SPIFFE ID, a malformed response, or a bad
bundle is an error and a nonzero exit, never a warning.

## Self-contained run (no spire-agent required)

```
./demo/demo.sh
```

The script builds two executables and drives them against each other
over a real socket in a fresh directory under /tmp:

- `demo/fake_agent.exe` binds the socket, serves exactly one
  connection, then exits. It holds the client to what a real
  spire-agent requires at the door: the HTTP/2 preface, a HEADERS
  block that decodes through the HPACK decoder and carries the
  `/SpiffeWorkloadAPI/FetchX509SVID` path and the
  `workload.spiffe.io: true` security header, and the request
  half-close. A request that fails any check gets no response.
- `demo/fetch_svid.exe` connects, fetches, and prints the typed
  result.

Expected output:

```
svid: spiffe://example.org/demo
  cert: 129 B  key: 32 B  roots: 1
federated bundles: 0
demo green
```

The script also runs two negative controls: a truncated protobuf body
and an SVID with an empty bundle field. The client must fail on both;
the script goes red if either is accepted. `./gates.sh` runs this
script, so the demo is part of the standing gate.

## Run against a real spire-agent

Start a spire-agent (see the SPIRE quickstart at
https://spiffe.io/docs/latest/try/getting-started-linux-macos-x/) and
register a workload for your user. The agent's Workload API socket is
usually `/tmp/spire-agent/public/api.sock`.

```
dune build demo/fetch_svid.exe
./_build/default/demo/fetch_svid.exe /tmp/spire-agent/public/api.sock
```

The client also honors the standard endpoint variable, with or
without the `unix://` scheme:

```
SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock \
  ./_build/default/demo/fetch_svid.exe
```

The output has the same shape as the self-contained run, with your
registered SPIFFE ID and your trust bundle's root count. The exit
code is 0 only when the response decodes and every bundle parses.
