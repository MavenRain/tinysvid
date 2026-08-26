# tinysvid design

A SPIFFE workload-identity toolkit for constrained edge nodes. The core is
OCaml. The attestation and validation kernel also compiles with ZxCaml
(omlz) to static SBF artifacts in the single-digit-KB range. The design is
model-driven: a CTLK model, encoded in the internal logic of a topos, is
checked first. The code is then shaped until it is a faithful image of the
model. The repository carries the model, the checker, and the
correspondence gate that keeps code and model aligned.

## Problem

Workload identity on disconnected, embedded, edge hardware. Kubernetes
patterns assume a live control plane. An edge node loses its link, keeps
serving, and must still validate peers soundly. The classic failure is the
rotated-but-stale trust bundle: the authority has rotated its roots, the
node still validates against the old bundle, and nothing in the types
stops it. tinysvid makes that state inexpressible.

## Why ZxCaml

Measured on this machine (2026-08-24 benchmark, `zxcaml-bench`): ZxCaml
emits 2.7 to 7.2 KB static `.so` artifacts where equivalent Rust emits 18
to 23 KB, and cold builds are 3.5x faster. A validation core in the
ZxCaml dialect fits the tiniest node. The OCaml library is the portable
superset; the ZxCaml artifacts are the same logic in its smallest form.
The `zx/zx_core.so` artifact in this repo is 4,312 bytes.

## Model-driven method

The model lives in `model/` and is checked before the code is trusted.

Encoding. Take the finite set W of reachable protocol states as a discrete
category. The presheaf topos Set^W has Sub(1) isomorphic to the powerset
of W: a complete (Boolean, hence Heyting) algebra. `model/sub.ml` is that
lattice. Propositions are subobjects of 1. Satisfaction is Kripke-Joyal
forcing, which is pointwise membership here.

Modalities are adjoints along relations, in the quantifiers-as-adjoints
sense. For the transition relation R with projections p1, p2 out of
R into W x W, EX is the inverse image p1-exists after p2-pullback, and AX
is its universal (right-adjoint) dual. `model/modal.ml` implements both.
For an agent i, the observation map q_i : W -> W/~_i induces a geometric
morphism Set^W -> Set^(W/~_i); knowledge K_i is the comonad (q_i)* after
forall along q_i, which is S5 necessity for that agent. Temporal operators
are Knaster-Tarski fixpoints of monotone maps on Sub(1): EF, AF, EG, AG,
EU in `model/ctlk.ml`. The lattice is finite, so naive iteration reaches
the fixpoint.

The frame. One authority, one workload. State components:

- `auth`: authority epoch, E0 | E1 | E2 (bounded; gaps 0, 1, 2 are
  expressible, and gap 2 is the hazard)
- `bundle`: Held (Fresh | Grace, epoch) | Void, the workload's bundle
- `svid`: No_svid | Svid epoch
- `link`: Up | Down

Transitions: rotate, tick (TTL degrade), sync (link Up), renew (link Up
and usable bundle), expire, link-flip. The shipped design is the Coupled
frame: rotation degrades every held bundle one step, because one rotation
period is an upper bound for bundle TTL. The Uncoupled frame is the
negative control: rotation leaves bundles untouched.

Observations: the workload sees (bundle, svid, link) and never `auth`.
The authority sees (auth, link).

Checked properties (`model/check.ml`, exit code is the gate):

| id | property | expectation |
|----|----------|-------------|
| A1 | AG (usable -> gap <= 1) | valid |
| A2 | AG EX true (no deadlock) | valid |
| A3 | AG EF fresh (recovery stays possible) | valid |
| A4 | AG (fresh -> K_workload gap = 0) | valid |
| A5 | AG (grace -> K_workload gap <= 1) | valid |
| A6 | EF (grace and not K gap=0 and not K gap=1) | satisfiable |
| A7 | AG (renew enabled -> usable bundle) | valid |
| A8 | EF (usable and not K_authority usable) | satisfiable |
| N1 | Uncoupled frame reaches usable and gap >= 2 | satisfiable |

A4 is the disconnection theorem: a fresh bundle is knowledge of the
current epoch, with no connectivity required. A6 shows grace is sound but
epistemically uncertain. N1 is the rotated-but-stale hazard, reachable
only in the rejected design.

From model to types. `lib/bundle.ml` is the code image of the Coupled
frame. Freshness is a phantom type parameter: `fresh held` and
`grace held` are distinct types, `Void` carries no roots, and
`Svid.validate_leaf` takes `Bundle.usable`, so a stale bundle cannot reach
validation at compile time. `refresh` is the only Fresh constructor and
stamps the current epoch. `degrade` is the only downgrade path.
`test/test_correspondence.ml` re-checks, on every reachable model world,
that lift and observe commute with degrade. Model drift or code drift
breaks the gate.

The ZxCaml artifact `zx/zx_core.ml` is the same A1 invariant as an
inductive-step check over the int-encoded bundle projection, compiled to
a static SBF object. It returns the violation count; the expected value
is 0.

## Layout

```
model/   CTLK model: sub.ml (Sub(1)), modal.ml (adjoint modalities),
         ctlk.ml (fixpoints), frame.ml, props.ml, check.ml (gate)
lib/     tinysvid library: trust_domain, spiffe_id, bundle, svid
test/    vectors, behavior tests, model-code correspondence gate
zx/      ZxCaml dialect artifacts + build script (omlz)
gates.sh full local gate
```

## Milestones

Phase A: model first.

- [x] M1 repo scaffold: dune project, licenses, gate script
- [x] M2 Sub(1) lattice with Knaster-Tarski fixpoints
- [x] M3 frame: coupled and uncoupled transition structures, BFS reachability
- [x] M4 adjoint modalities EX/AX, epistemic K_i, CTL fixpoint operators
- [x] M5 property suite A1..A8 plus negative control N1, exit-code gate
- [x] M6 model-to-code correspondence gate over all reachable worlds

Phase B: typed core.

- [x] M7 trust-domain parser (spec section 2.1, total, error values)
- [x] M8 SPIFFE ID parser (sections 2.2-2.3, dot-segment and charset rejects)
- [x] M9 bundle state machine with phantom Fresh/Grace and rootless Void
- [x] M10 X.509-SVID leaf checks (URI SAN, flags, window, trust domain)
- [x] M11 DER tag-length-value walker, total, over string input
- [x] M12 X.509 field extraction (SAN URI, validity, basicConstraints, keyUsage)
- [x] M13 signature backend as a module type (Ed25519, P-256 provided outside the core)
- [x] M14 chain validation: path build to bundle roots plus epoch-gap rule

Phase C: ZxCaml artifacts.

- [x] M15 zx dialect audit and A1 inductive-invariant artifact (4,312 B .so)
- [ ] M16 zx SPIFFE ID charset validator artifact
- [ ] M17 zx bundle-step artifact (degrade/sync over the int encoding)
- [ ] M18 zx SVID window-plus-gap check artifact
- [ ] M19 size table: each zx artifact against its Rust equivalent
- [ ] M20 differential conformance: host OCaml against zx semantics on shared vectors

Phase D: Workload API.

- [ ] M21 Unix-domain-socket transport, stdlib only
- [ ] M22 minimal HTTP/2 framing for one client-streaming RPC
- [ ] M23 protobuf codec for X509SVIDRequest/Response
- [ ] M24 client: fetch and watch X509 SVIDs and bundles into typed state
- [ ] M25 file-based bundle source for fully disconnected nodes
- [ ] M26 rotation loop wired through Bundle.degrade (the path A1/A7 certify)

Phase E: hardening.

- [ ] M27 negative corpus for both parsers; every malformed vector must reject
- [ ] M28 end-to-end demo against a spire-agent socket, documented
- [ ] M29 footprint report: artifact sizes, static footprint, comparison table
- [ ] M30 gates.sh covers model, tests, zx build, and size regression

## Gates

`./gates.sh` runs the model checker and all test suites. `./gates.sh --zx`
also rebuilds the ZxCaml artifact. Every milestone lands only with the
full gate green.
