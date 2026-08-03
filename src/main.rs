//! gss-token-helper — macOS SPNEGO token helper.
//!
//! Acquires a SPNEGO init token via macOS GSS.framework and prints it
//! base64-encoded to stdout. Designed to be called by applications that
//! cannot access KCM (Mach IPC) directly.

use gss_token_helper::app::{self, AppError};
use gss_token_helper::gss;
use gss_token_helper::input::{ServicePrincipalName, decode_hex};

use clap::Parser;
use gss_token_helper::protocol;
use std::io::{self, BufRead, Write};
use std::process;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Parser)]
#[command(name = "gss-token-helper")]
#[command(about = "macOS SPNEGO token helper using GSS.framework")]
struct Cli {
    #[arg(short, long)]
    version: bool,

    /// Enable multi-leg negotiation mode. Reads base64-encoded server
    /// response tokens from stdin (one per line) and writes output tokens
    /// to stdout. An empty line or EOF signals the end of negotiation.
    #[arg(short, long)]
    negotiate: bool,

    /// Request credential delegation (forward TGT to the service).
    #[arg(short, long)]
    delegate: bool,

    /// TLS channel bindings hash (hex-encoded tls-server-end-point value,
    /// RFC 5929). Used for Extended Protection for Authentication (EPA).
    #[arg(short, long, value_name = "HEX")]
    channel_bindings: Option<String>,

    /// Service principal name (e.g. HTTP/proxy.corp.example.com)
    spn: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if cli.version {
        let git_commit = built_info::GIT_COMMIT_HASH_SHORT;
        let release_ver = option_env!("BUILD_VERSION").unwrap_or(built_info::PKG_VERSION);
        let release_date = built_info::BUILT_TIME_UTC;

        println!("gss-token-helper");
        println!("Version: {}", release_ver);
        println!("Git Commit: {}", git_commit.unwrap_or("unknown"));
        println!("Release Date: {}", release_date);
        return;
    }

    let raw_spn = match cli.spn {
        Some(s) if !s.is_empty() => s,
        _ => {
            eprintln!("Usage: gss-token-helper [OPTIONS] <service/hostname>");
            eprintln!("  e.g. gss-token-helper HTTP/proxy.corp.example.com");
            eprintln!("  e.g. gss-token-helper --negotiate --delegate HTTP/proxy.corp.example.com");
            process::exit(1);
        }
    };

    // Validate structure before anything reaches the GSS FFI layer.
    let spn = match ServicePrincipalName::parse(&raw_spn) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gss-token-helper: invalid SPN \"{raw_spn}\": {e}");
            process::exit(1);
        }
    };

    let name = match gss::import_name(spn.as_str()) {
        Ok(n) => n,
        Err(e) => die_gss_error(&format!("failed to import name \"{spn}\""), &e),
    };

    // Parse channel bindings from hex string.
    let cb_bytes = cli.channel_bindings.as_ref().map(|hex_str| {
        decode_hex(hex_str).unwrap_or_else(|e| {
            eprintln!("Error: invalid channel bindings hex: {e}");
            process::exit(1);
        })
    });

    let delegation = if cli.delegate {
        gss::DelegationMode::Required
    } else {
        gss::DelegationMode::Disabled
    };
    let opts = gss::InitSecContextOpts {
        delegation,
        channel_bindings: cb_bytes.as_deref(),
    };

    let outcome = if cli.negotiate {
        let stdin = io::stdin();
        let stdout = io::stdout();
        run_negotiate_mode(&name, &opts, &mut stdin.lock(), &mut stdout.lock())
    } else {
        let stdout = io::stdout();
        run_single_shot(&name, &opts, &mut stdout.lock())
    };

    // The single place that reports a failure and picks the exit status.
    if let Err(e) = outcome {
        report(&e);
        process::exit(1);
    }
}

/// Print a fatal error to stderr, adding GSS hints when available.
fn report(e: &AppError) {
    eprintln!("Error: {e}");
    if let AppError::Context(_, gss::ContextError::Gss(g)) = e
        && let Some(hint) = g.hint()
    {
        eprintln!("{hint}");
    }
}

/// Print a GSS error with contextual hints to stderr, then exit.
fn die_gss_error(context: &str, e: &gss::GssError) -> ! {
    eprintln!("Error: {context}: {e}");
    if let Some(hint) = e.hint() {
        eprintln!("{hint}");
    }
    process::exit(1);
}

/// Single-shot mode: acquire one token and write it to `out`.
fn run_single_shot<W: Write>(
    name: &gss::GssName,
    opts: &gss::InitSecContextOpts<'_>,
    out: &mut W,
) -> Result<(), AppError> {
    let mut ctx = gss::SecurityContext::new(name, opts);

    let token = match ctx.start() {
        Ok(gss::InitSecContextResult::Complete(t))
        | Ok(gss::InitSecContextResult::ContinueNeeded(t)) => t,
        Err(e) => return Err(AppError::Context("gss_init_sec_context failed".into(), e)),
    };

    // The base64-encoded SPNEGO token on a single line, no trailing newline.
    app::write_single_shot(out, &token)
}

/// Multi-leg negotiation mode.
///
/// Protocol (see [`protocol`]):
///   1. Writes one `CONTINUE`/`COMPLETE` record per step, newline-terminated
///   2. Reads one peer record per leg from stdin under a hard byte bound
///   3. Feeds the decoded token to gss_init_sec_context
///   4. Repeats until a `COMPLETE` record is written, then exits 0
///   5. Aborts nonzero on a malformed record, a limit breach, or early EOF
fn run_negotiate_mode<R: BufRead, W: Write>(
    name: &gss::GssName,
    opts: &gss::InitSecContextOpts<'_>,
    reader: &mut R,
    out: &mut W,
) -> Result<(), AppError> {
    let mut ctx = gss::SecurityContext::new(name, opts);

    // First leg: no input token.
    let result = ctx
        .start()
        .map_err(|e| AppError::Context("gss_init_sec_context failed (leg 1)".into(), e))?;
    if emit(out, result)? {
        return Ok(());
    }

    // Subsequent legs: read peer records from stdin under a hard byte bound.
    let mut buf = Vec::new();
    for leg in 1..protocol::MAX_LEGS {
        match protocol::read_bounded_line(reader, protocol::MAX_ENCODED_LINE, &mut buf)? {
            Some(()) => {}
            None => break,
        }
        let line = String::from_utf8_lossy(&buf).trim().to_string();
        let record = protocol::decode(&line)?;
        let result = ctx.continue_with(record.token()).map_err(|e| {
            AppError::Context(format!("gss_init_sec_context failed (leg {leg})"), e)
        })?;
        if emit(out, result)? {
            return Ok(());
        }
    }

    // Either stdin closed early or the leg budget ran out.
    Err(AppError::Incomplete {
        legs: protocol::MAX_LEGS,
    })
}

/// Write one protocol record for a step result; returns true when final.
fn emit<W: Write>(out: &mut W, result: gss::InitSecContextResult) -> Result<bool, AppError> {
    let record = match result {
        gss::InitSecContextResult::Complete(t) => protocol::Record::Complete(t),
        gss::InitSecContextResult::ContinueNeeded(t) => protocol::Record::Continue(t),
    };
    app::write_record(out, &record)?;
    Ok(record.is_final())
}
