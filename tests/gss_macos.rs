//! Opt-in tests requiring live macOS Kerberos and EPA infrastructure.
//!
//! These tests are `#[ignore]`d by default because they need a real KDC, a
//! real service principal, and (for channel bindings) a real EPA-capable
//! endpoint. Nothing here runs in ordinary CI; the deterministic parts of the
//! same behavior are covered by the in-crate unit and property tests.
//!
//! # Environment variables
//!
//! | Variable | Required by | Meaning |
//! |----------|-------------|---------|
//! | `GSS_TEST_SPN` | all | Target service principal, e.g. `HTTP/host.example.com` |
//! | `GSS_TEST_EXPECT_MECH` | mechanism test | Dotted OID the negotiation must select, e.g. `1.2.840.113554.1.2.2` |
//! | `GSS_TEST_REQUIRE_DELEGATION` | delegation test | Set to `1` to require that GSS actually delegated |
//! | `GSS_TEST_CB_HEX` | EPA test | `tls-server-end-point` channel-binding bytes, hex-encoded |
//!
//! # Running
//!
//! ```sh
//! GSS_TEST_SPN=HTTP/host.example.com \
//!   cargo test --test gss_macos -- --ignored --nocapture
//! ```

use gss_token_helper::gss::{self, DelegationMode, InitSecContextOpts, SecurityRequirements};
use gss_token_helper::input::decode_hex;

/// Read a required variable or skip the body by returning `None`.
fn var(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!("skipping: {name} is not set");
            None
        }
    }
}

/// Drive a full negotiation to completion against the live target.
fn negotiate(opts: &InitSecContextOpts<'_>) -> Option<gss::ContextStep> {
    let spn = var("GSS_TEST_SPN")?;
    let name = gss::import_name(&spn).expect("import_name failed for GSS_TEST_SPN");
    let mut ctx = gss::SecurityContext::new(&name, opts);
    let result = ctx.start().expect("start failed");
    // A live acceptor is not available in-process, so a single leg is all we
    // can drive; SPNEGO against a real KDC completes or asks to continue.
    if let gss::InitSecContextResult::ContinueNeeded(_) = result {
        eprintln!("negotiation requested another leg; no acceptor available");
    }
    ctx.last_step().cloned()
}

#[test]
#[ignore = "requires explicitly configured live Kerberos credentials"]
fn live_gss_interoperability() {
    let opts = InitSecContextOpts::default();
    let Some(step) = negotiate(&opts) else { return };
    assert!(
        step.time_rec > 0 || step.continue_needed,
        "a completed context should report a lifetime"
    );
    eprintln!(
        "ret_flags={:#x} time_rec={} mech={:?}",
        step.ret_flags, step.time_rec, step.actual_mech
    );
}

#[test]
#[ignore = "requires GSS_TEST_EXPECT_MECH and live Kerberos credentials"]
fn live_mechanism_matches_the_expected_oid() {
    let Some(expected) = var("GSS_TEST_EXPECT_MECH") else {
        return;
    };
    let opts = InitSecContextOpts::default();
    let Some(step) = negotiate(&opts) else { return };
    assert_eq!(
        step.actual_mech.as_deref(),
        Some(expected.as_str()),
        "negotiated mechanism differs from GSS_TEST_EXPECT_MECH"
    );
}

#[test]
#[ignore = "requires live Kerberos credentials"]
fn live_returned_flags_satisfy_requested_properties() {
    let require_deleg = std::env::var("GSS_TEST_REQUIRE_DELEGATION").as_deref() == Ok("1");
    let opts = InitSecContextOpts {
        delegation: if require_deleg {
            DelegationMode::Required
        } else {
            DelegationMode::Disabled
        },
        channel_bindings: None,
    };
    let Some(step) = negotiate(&opts) else { return };
    let req = SecurityRequirements {
        mutual_auth: true,
        delegation: require_deleg,
        mech: None,
    };
    step.verify(&req).expect("required properties not granted");
}

#[test]
#[ignore = "requires GSS_TEST_CB_HEX and a live EPA-capable endpoint"]
fn live_epa_channel_bindings_interoperate() {
    let Some(hex) = var("GSS_TEST_CB_HEX") else {
        return;
    };
    let cb = decode_hex(&hex).expect("GSS_TEST_CB_HEX is not valid hex");
    let opts = InitSecContextOpts {
        delegation: DelegationMode::Disabled,
        channel_bindings: Some(&cb),
    };
    let Some(step) = negotiate(&opts) else { return };
    eprintln!(
        "EPA negotiation returned ret_flags={:#x} mech={:?}",
        step.ret_flags, step.actual_mech
    );
}
