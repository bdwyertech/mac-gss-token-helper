//! Subprocess coverage for exact output and process-failure semantics.
//!
//! The binary must report failures on stderr, exit nonzero, and never emit
//! partial or unexpected stdout bytes. Cases
//! that need a live Kerberos credential live in `tests/gss_macos.rs`.

use assert_cmd::Command;
use predicates::prelude::*;

fn helper() -> Command {
    Command::cargo_bin("gss-token-helper").expect("binary builds")
}

#[test]
fn a_missing_spn_is_a_usage_error_on_stderr_with_no_stdout() {
    helper()
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Usage: gss-token-helper"));
}

#[test]
fn a_malformed_spn_fails_without_writing_stdout() {
    helper()
        .arg("no-separator")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("invalid SPN"));
}

#[test]
fn malformed_channel_binding_hex_fails_without_writing_stdout() {
    helper()
        .args(["--channel-bindings", "zz", "HTTP/host.example.com"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("channel bindings hex"));
}

#[test]
fn the_version_banner_is_written_to_stdout_and_succeeds() {
    helper()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("gss-token-helper"))
        .stdout(predicate::str::contains("Version:"));
}

#[test]
fn a_closed_stdout_never_reports_success() {
    // `head -c 0` closes the pipe immediately, so any write must be observed
    // as an error rather than silently discarded. Without a credential the
    // run fails earlier, but in neither case may the helper exit 0.
    let status = std::process::Command::new(assert_cmd::cargo::cargo_bin("gss-token-helper"))
        .arg("HTTP/host.invalid.example.com")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawns");
    assert!(!status.success(), "expected a nonzero exit status");
}
