//! Rust equivalent of zx/zx_charset.ml for the M19 size table.
//!
//! SPIFFE charset predicates over byte codes 0..255. td_char accepts
//! [a-z0-9._-] (SPIFFE-ID spec section 2.1); seg_char accepts
//! [a-zA-Z0-9._-] (section 2.2). entrypoint probes every range
//! boundary, each singleton, and the td-subset-of-seg law, and
//! returns the violation count; the expected return is 0. The
//! function set mirrors the zx source one for one so both artifacts
//! compute the same sum.
#![cfg_attr(target_os = "solana", no_std)]

fn ge(x: i64, lo: i64) -> i64 {
    i64::from(x >= lo)
}

fn le(x: i64, hi: i64) -> i64 {
    i64::from(x <= hi)
}

fn eq(x: i64, v: i64) -> i64 {
    i64::from(x == v)
}

fn in_range(b: i64, lo: i64, hi: i64) -> i64 {
    ge(b, lo) * le(b, hi)
}

fn td_char(b: i64) -> i64 {
    in_range(b, 97, 122) + in_range(b, 48, 57) + eq(b, 45) + eq(b, 46) + eq(b, 95)
}

fn seg_char(b: i64) -> i64 {
    td_char(b) + in_range(b, 65, 90)
}

fn ne(x: i64, v: i64) -> i64 {
    1 - eq(x, v)
}

fn td_probe(b: i64, want: i64) -> i64 {
    ne(td_char(b), want)
}

fn seg_probe(b: i64, want: i64) -> i64 {
    ne(seg_char(b), want)
}

fn sub_probe(b: i64) -> i64 {
    1 - ge(seg_char(b), td_char(b))
}

fn bounds_td(_d: i64) -> i64 {
    td_probe(opaque(44), 0)
        + td_probe(opaque(45), 1)
        + td_probe(opaque(46), 1)
        + td_probe(opaque(47), 0)
        + td_probe(opaque(48), 1)
        + td_probe(opaque(57), 1)
        + td_probe(opaque(58), 0)
        + td_probe(opaque(64), 0)
        + td_probe(opaque(65), 0)
        + td_probe(opaque(90), 0)
        + td_probe(opaque(91), 0)
        + td_probe(opaque(94), 0)
        + td_probe(opaque(95), 1)
        + td_probe(opaque(96), 0)
        + td_probe(opaque(97), 1)
        + td_probe(opaque(122), 1)
        + td_probe(opaque(123), 0)
        + td_probe(opaque(0), 0)
        + td_probe(opaque(255), 0)
}

fn bounds_seg(_d: i64) -> i64 {
    seg_probe(opaque(44), 0)
        + seg_probe(opaque(45), 1)
        + seg_probe(opaque(46), 1)
        + seg_probe(opaque(47), 0)
        + seg_probe(opaque(48), 1)
        + seg_probe(opaque(57), 1)
        + seg_probe(opaque(58), 0)
        + seg_probe(opaque(64), 0)
        + seg_probe(opaque(65), 1)
        + seg_probe(opaque(90), 1)
        + seg_probe(opaque(91), 0)
        + seg_probe(opaque(94), 0)
        + seg_probe(opaque(95), 1)
        + seg_probe(opaque(96), 0)
        + seg_probe(opaque(97), 1)
        + seg_probe(opaque(122), 1)
        + seg_probe(opaque(123), 0)
        + seg_probe(opaque(0), 0)
        + seg_probe(opaque(255), 0)
}

fn bounds_sub(_d: i64) -> i64 {
    sub_probe(opaque(44))
        + sub_probe(opaque(45))
        + sub_probe(opaque(48))
        + sub_probe(opaque(65))
        + sub_probe(opaque(90))
        + sub_probe(opaque(95))
        + sub_probe(opaque(97))
        + sub_probe(opaque(122))
        + sub_probe(opaque(255))
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
    u64::try_from(bounds_td(0) + bounds_seg(0) + bounds_sub(0)).unwrap_or(u64::MAX)
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
