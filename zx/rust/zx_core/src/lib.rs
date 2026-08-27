//! Rust equivalent of zx/zx_core.ml for the M19 size table.
//!
//! The strengthened invariant inv -- void, or fresh with gap exactly
//! 0, or grace with gap 0 or 1, which is the A4/A5 epoch-gap rule --
//! is checked inductive under rotate, tick, and sync over all 27
//! int-encoded bundle states, and shown to imply A1 (usable ->
//! auth - held <= 1). Encoding: k in {0=void, 1=fresh, 2=grace},
//! b = held epoch, a = authority epoch, each in {0, 1, 2}.
//! entrypoint returns the violation count across all 27 states; the
//! expected return is 0. The function set mirrors the zx source one
//! for one so both artifacts compute the same sum.
#![cfg_attr(target_os = "solana", no_std)]

fn eq(x: i64, v: i64) -> i64 {
    i64::from(x == v)
}

fn ge(x: i64, lo: i64) -> i64 {
    i64::from(x >= lo)
}

fn le(x: i64, hi: i64) -> i64 {
    i64::from(x <= hi)
}

fn degrade(k: i64) -> i64 {
    if k == 1 {
        2
    } else {
        0
    }
}

fn gap01(a: i64, b: i64) -> i64 {
    ge(a - b, 0) * le(a - b, 1)
}

fn inv(a: i64, k: i64, b: i64) -> i64 {
    eq(k, 0) + eq(k, 1) * eq(a, b) + eq(k, 2) * gap01(a, b)
}

fn a1(a: i64, k: i64, b: i64) -> i64 {
    eq(k, 0) + (1 - eq(k, 0)) * le(a - b, 1)
}

fn step_check(a: i64, k: i64, b: i64) -> i64 {
    let live = inv(a, k, b);
    let (ra, rk) = if a < 2 { (a + 1, degrade(k)) } else { (a, k) };
    let bad_rotate = 1 - inv(ra, rk, b);
    let bad_tick = 1 - inv(a, degrade(k), b);
    let bad_sync = 1 - inv(a, 1, a);
    let bad_a1 = 1 - a1(a, k, b);
    live * (bad_rotate + bad_tick + bad_sync + bad_a1)
}

fn row(a: i64, k: i64) -> i64 {
    step_check(a, k, opaque(0)) + step_check(a, k, opaque(1)) + step_check(a, k, opaque(2))
}

fn plane(a: i64) -> i64 {
    row(a, opaque(0)) + row(a, opaque(1)) + row(a, opaque(2))
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
    u64::try_from(plane(opaque(0)) + plane(opaque(1)) + plane(opaque(2))).unwrap_or(u64::MAX)
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
