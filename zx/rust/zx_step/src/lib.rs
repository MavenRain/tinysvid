//! Rust equivalent of zx/zx_step.ml for the M19 size table.
//!
//! The Coupled-frame bundle step over the int encoding from zx_core:
//! k in {0=void, 1=fresh, 2=grace}, a = authority epoch and b = held
//! epoch, each in {0, 1, 2}. rotate advances the authority and
//! degrades the held bundle one step while a < 2; tick degrades the
//! held bundle; sync re-fetches a fresh bundle stamped with the
//! current authority epoch (the caller owes link-up). entrypoint
//! checks domain closure, the degrade chain, the rotate laws at and
//! below the epoch ceiling, and the sync laws over all 27 states, and
//! returns the violation count; the expected return is 0. The
//! function set mirrors the zx source one for one so both artifacts
//! compute the same sum.
#![cfg_attr(target_os = "solana", no_std)]

fn degrade(k: i64) -> i64 {
    if k == 1 {
        2
    } else {
        0
    }
}

fn rotate_a(a: i64) -> i64 {
    if a < 2 {
        a + 1
    } else {
        a
    }
}

fn rotate_k(a: i64, k: i64) -> i64 {
    if a < 2 {
        degrade(k)
    } else {
        k
    }
}

fn tick_k(k: i64) -> i64 {
    degrade(k)
}

/// Constant 1, matching the OCaml `1 + (a * 0)`; routed through
/// `opaque` so the two sync-law comparisons stay in the artifact
/// instead of folding to constants -- the zx artifact performs them
/// at runtime, and the size table should measure the same work.
fn sync_k(_b: i64) -> i64 {
    opaque(1)
}

fn sync_b(a: i64) -> i64 {
    a
}

fn ge(x: i64, lo: i64) -> i64 {
    i64::from(x >= lo)
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

fn in_dom(x: i64) -> i64 {
    ge(x, 0) * le(x, 2)
}

fn dom_bad(x: i64) -> i64 {
    1 - in_dom(x)
}

fn cell(a: i64, k: i64, b: i64) -> i64 {
    dom_bad(rotate_a(a))
        + dom_bad(rotate_k(a, k))
        + dom_bad(tick_k(k))
        + dom_bad(sync_k(b))
        + dom_bad(sync_b(a))
        + ne(degrade(degrade(degrade(k))), 0)
        + eq(a, 2) * (ne(rotate_a(a), a) + ne(rotate_k(a, k), k))
        + le(a, 1) * (ne(rotate_a(a), a + 1) + ne(rotate_k(a, k), degrade(k)))
        + ne(sync_k(b), 1)
        + ne(sync_b(a), a)
}

fn row(a: i64, k: i64) -> i64 {
    cell(a, k, opaque(0)) + cell(a, k, opaque(1)) + cell(a, k, opaque(2))
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
