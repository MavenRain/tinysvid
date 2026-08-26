# tinysvid

SPIFFE workload identity for constrained edge nodes. Typed OCaml core.
Validation kernel small enough for the tiniest node: the ZxCaml build of
the invariant checker is a 4.3 KB static artifact.

The trust-bundle lifecycle is encoded in the types. A bundle is Fresh,
Grace, or Void. Void holds no roots and validation only accepts Fresh or
Grace, so a rotated-but-stale bundle is not expressible. The design was
model-checked first: a CTLK model in the internal logic of a presheaf
topos, with temporal operators as lattice fixpoints and per-agent
knowledge as a comonad. See DESIGN.md for the model, the nine checked
properties, and the 30-milestone plan.

## Build

```
dune build
dune runtest      # model check + vectors + correspondence gate
./gates.sh        # the same, as one gate
./gates.sh --zx   # also rebuild the ZxCaml artifact (needs omlz + zig)
```

## Status

Milestones M1..M10 and M15 are done: model green (9/9 properties),
library green (34 checks), ZxCaml artifact builds at 4,312 bytes.

## License

MIT OR Apache-2.0.
