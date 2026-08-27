//! Rust equivalent of zx/zx_window.ml for the M19 size table.
//!
//! The SVID validity window and the A4/A5 epoch-gap rule over ints.
//! window_ok mirrors Svid.check_window: valid while not_before <=
//! now < not_after. gap_limit mirrors Chain.epoch_rule over the k
//! encoding: fresh (1) allows gap 0, grace (2) allows gap at most 1,
//! void (0) allows nothing; a negative gap always rejects. check is
//! the conjunction, as at the chain validation boundary. entrypoint
//! probes the window boundaries, the empty window, the full gap
//! table, and the conjunction, and returns the violation count; the
//! expected return is 0. The function set mirrors the zx source one
//! for one so both artifacts compute the same sum.
#![cfg_attr(target_os = "solana", no_std)]

fn ge(x: i64, lo: i64) -> i64 {
    i64::from(x >= lo)
}

fn lt(x: i64, hi: i64) -> i64 {
    i64::from(x < hi)
}

fn le(x: i64, hi: i64) -> i64 {
    i64::from(x <= hi)
}

fn eq(x: i64, v: i64) -> i64 {
    i64::from(x == v)
}

fn ne(x: i64, v: i64) -> i64 {
    1 - eq(x, v)
}

fn window_ok(now: i64, nb: i64, na: i64) -> i64 {
    ge(now, nb) * lt(now, na)
}

fn gap_limit(k: i64) -> i64 {
    match () {
        () if k == 1 => 0,
        () if k == 2 => 1,
        () => -1,
    }
}

fn gap_ok(k: i64, g: i64) -> i64 {
    ge(g, 0) * le(g, gap_limit(k))
}

fn check(k: i64, g: i64, now: i64, nb: i64, na: i64) -> i64 {
    gap_ok(k, g) * window_ok(now, nb, na)
}

fn win_probes(_d: i64) -> i64 {
    ne(window_ok(opaque(9), 10, 20), 0)
        + ne(window_ok(opaque(10), 10, 20), 1)
        + ne(window_ok(opaque(19), 10, 20), 1)
        + ne(window_ok(opaque(20), 10, 20), 0)
        + ne(window_ok(opaque(10), 10, 10), 0)
        + ne(window_ok(opaque(0), 10, 20), 0)
        + ne(window_ok(opaque(30), 10, 20), 0)
}

fn gap_probes(_d: i64) -> i64 {
    ne(gap_ok(opaque(1), 0), 1)
        + ne(gap_ok(opaque(1), 1), 0)
        + ne(gap_ok(opaque(1), -1), 0)
        + ne(gap_ok(opaque(2), 0), 1)
        + ne(gap_ok(opaque(2), 1), 1)
        + ne(gap_ok(opaque(2), 2), 0)
        + ne(gap_ok(opaque(2), -1), 0)
        + ne(gap_ok(opaque(0), 0), 0)
        + ne(gap_ok(opaque(0), 1), 0)
}

fn combine_probes(_d: i64) -> i64 {
    ne(check(opaque(1), 0, 10, 10, 20), 1)
        + ne(check(opaque(1), 0, 9, 10, 20), 0)
        + ne(check(opaque(1), 1, 15, 10, 20), 0)
        + ne(check(opaque(2), 1, 15, 10, 20), 1)
        + ne(check(opaque(0), 0, 15, 10, 20), 0)
}

/// Identity at runtime, opaque to the constant folder: without it
/// LLVM folds the whole sweep to `return 0` at compile time and the
/// artifact no longer contains the check the size table measures
/// (the folded .so is 904 B of `mov r0, 0; exit`). The host gate
/// result is unchanged.
fn opaque(x: i64) -> i64 {
    core::hint::black_box(x)
}

#[no_mangle]
pub extern "C" fn entrypoint(_input: *mut u8) -> u64 {
    u64::try_from(win_probes(0) + gap_probes(0) + combine_probes(0)).unwrap_or(u64::MAX)
}

/// The one `unsafe` in this crate, sanctioned: on the stable no_std
/// SBF target the only diverging terminators are `loop {}` (a banned
/// keyword) and the SBF `abort` syscall, which is FFI. The handler is
/// unreachable in practice: the arithmetic above cannot panic (no
/// indexing, no division, and release-profile overflow wraps).
#[cfg(target_os = "solana")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { abort() }
}

#[cfg(target_os = "solana")]
extern "C" {
    fn abort() -> !;
}
