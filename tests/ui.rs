//! Compile-fail (UI) tests asserting borrow-checker guarantees.
//!
//! These are gated behind the `ui-tests` feature because the expected
//! `.stderr` snapshots are tied to the exact rustc version pinned in
//! `rust-toolchain.toml`.
//!
//! # Regenerating snapshots after a toolchain bump
//!
//! 1. Bump `channel` in `rust-toolchain.toml`.
//! 2. Run `TRYBUILD=overwrite cargo test --features ui-tests --test ui`.
//! 3. Review the `tests/ui/*.stderr` diff: the error codes (e.g. `E0597`)
//!    must not change. Only wording, spans, and note formatting may drift.
//!    A changed or missing error code means the guarantee regressed.
//! 4. Commit the regenerated snapshots alongside the toolchain bump.

#![cfg(feature = "ui-tests")]

#[test]
fn security_context_lifetimes() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
