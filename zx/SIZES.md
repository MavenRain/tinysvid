# M19 size table: ZxCaml artifacts against Rust equivalents

Same SBF machine on both sides. ZxCaml: omlz (zig 0.16.0,
solana-zig v1.53.0, OCaml 5.2.1), `zx/build-zx.sh`. Rust:
cargo-build-sbf 2.3.13 (platform-tools v1.48, rustc 1.84.1),
`zx/rust/build-rust.sh`, crates with no dependencies. Sizes from the
2026-08-27 build; regenerate the table with `zx/rust/size-table.sh`.

| artifact   | zxcaml (B) | rust (B) | rust/zxcaml |
|------------|-----------:|---------:|------------:|
| zx_core    |      4,936 |    3,600 |        0.73 |
| zx_step    |      3,544 |    3,192 |        0.90 |
| zx_window  |      3,464 |    2,592 |        0.75 |
| zx_charset |      5,520 |   16,608 |        3.01 |
| total      |     17,464 |   25,992 |        1.49 |

Method notes, in honesty order:

- The first Rust build produced four identical 904 B artifacts:
  LLVM constant-folds each whole check to `return 0` at compile
  time (verified by disassembly: `mov64 r0, 0x0; exit`), because
  every input is a literal. A table over those artifacts would
  compare the ZxCaml checkers against empty stubs. Each enumerated
  coordinate and probe input therefore goes through `opaque`
  (`core::hint::black_box`), identity at runtime, so the artifact
  keeps the computation the zx artifact performs. Disassembly
  confirms live compare-and-branch code in all four.
- The pins are not free: each costs a stack spill and reload.
  zx_charset carries the most pins (47, one per probe input), which
  is why it is the one artifact where Rust comes out larger. The
  three sweep-style artifacts pin only the 3-9 enumerated
  coordinates, and there Rust is 10-27 percent smaller.
- The host gate `zx/rust/test-rust.sh` holds each crate to
  `entrypoint() == 0` (plus fmt and clippy `-D warnings`), the same
  standard `test/test_zx.ml` holds the zx sources to; one behavioral
  mutant per crate was confirmed killed against that gate.
- The zx sizes are the checked-in `zx/size-budget.txt` values, which
  the M30 gate holds the build to.
- A review pass caught one fold that survived the pins: `sync_k`
  returned a bare constant 1, so the two sync-law comparisons in
  zx_step folded out of the artifact. It now returns `opaque(1)`,
  which puts that checking work back into the measured .so.
