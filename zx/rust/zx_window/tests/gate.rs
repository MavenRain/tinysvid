//! Host gate: recompiles lib.rs for the host and requires entrypoint
//! to return 0, its own violation count -- the same standard
//! test/test_zx.ml holds the zx sources to.

#[test]
fn entrypoint_reports_zero_violations() -> Result<(), u64> {
    let got = zx_window::entrypoint(core::ptr::null_mut());
    if got == 0 {
        Ok(())
    } else {
        Err(got)
    }
}
