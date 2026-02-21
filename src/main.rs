//! gss-token-helper — macOS SPNEGO token helper.
//!
//! Acquires a SPNEGO init token via macOS GSS.framework and prints it
//! base64-encoded to stdout. Designed to be called by applications that
//! cannot access KCM (Mach IPC) directly.

mod gss;
mod gss_ffi;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::Parser;
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

    let spn = match cli.spn {
        Some(s) if !s.is_empty() => s,
        _ => {
            eprintln!("Usage: gss-token-helper [OPTIONS] <service/hostname>");
            eprintln!("  e.g. gss-token-helper HTTP/proxy.corp.example.com");
            eprintln!("  e.g. gss-token-helper --negotiate --delegate HTTP/proxy.corp.example.com");
            process::exit(1);
        }
    };

    let name = match gss::import_name(&spn) {
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

    let opts = gss::InitSecContextOpts {
        delegate: cli.delegate,
        channel_bindings: cb_bytes.as_deref(),
    };

    if cli.negotiate {
        run_negotiate_mode(&name, &opts);
    } else {
        run_single_shot(&name, &opts);
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

/// Single-shot mode: acquire one token and print it.
fn run_single_shot(name: &gss::GssName, opts: &gss::InitSecContextOpts<'_>) {
    let mut ctx = gss::SecurityContext::new(name, opts);

    let token = match ctx.step(None) {
        Ok(gss::InitSecContextResult::Complete(t))
        | Ok(gss::InitSecContextResult::ContinueNeeded(t)) => t,
        Err(e) => die_gss_error("gss_init_sec_context failed", &e),
    };

    if token.is_empty() {
        eprintln!("Error: GSS returned an empty token");
        process::exit(1);
    }

    // Output the base64-encoded SPNEGO token on a single line, no trailing newline.
    print!("{}", STANDARD.encode(&token));
}

/// Multi-leg negotiation mode.
///
/// Protocol:
///   1. Writes the initial base64 token to stdout (one line, newline-terminated)
///   2. Reads a base64-encoded server response token from stdin (one line)
///   3. Feeds it to gss_init_sec_context, writes the next token to stdout
///   4. Repeats until GSS_S_COMPLETE
///   5. On completion, writes "OK" to stdout and exits 0
///   6. An empty line from stdin aborts negotiation
fn run_negotiate_mode(name: &gss::GssName, opts: &gss::InitSecContextOpts<'_>) {
    let mut ctx = gss::SecurityContext::new(name, opts);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    // First leg: no input token.
    let result = match ctx.step(None) {
        Ok(r) => r,
        Err(e) => die_gss_error("gss_init_sec_context failed (leg 1)", &e),
    };

    match result {
        gss::InitSecContextResult::Complete(token) => {
            // Single-leg negotiation completed immediately.
            if !token.is_empty() {
                let _ = writeln!(stdout, "{}", STANDARD.encode(&token));
            }
            let _ = writeln!(stdout, "OK");
            return;
        }
        gss::InitSecContextResult::ContinueNeeded(token) => {
            if token.is_empty() {
                eprintln!("Error: GSS returned an empty token on leg 1");
                process::exit(1);
            }
            let _ = writeln!(stdout, "{}", STANDARD.encode(&token));
            let _ = stdout.flush();
        }
    }

    // Subsequent legs: read response tokens from stdin.
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error: failed to read from stdin: {e}");
                process::exit(1);
            }
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            eprintln!("Error: negotiation aborted (empty input)");
            process::exit(1);
        }

        let response_bytes = match STANDARD.decode(&line) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error: invalid base64 input: {e}");
                process::exit(1);
            }
        };

        let result = match ctx.step(Some(&response_bytes)) {
            Ok(r) => r,
            Err(e) => die_gss_error("gss_init_sec_context failed", &e),
        };

        match result {
            gss::InitSecContextResult::Complete(token) => {
                if !token.is_empty() {
                    let _ = writeln!(stdout, "{}", STANDARD.encode(&token));
                }
                let _ = writeln!(stdout, "OK");
                return;
            }
            gss::InitSecContextResult::ContinueNeeded(token) => {
                if !token.is_empty() {
                    let _ = writeln!(stdout, "{}", STANDARD.encode(&token));
                    let _ = stdout.flush();
                }
            }
        }
    }

    // EOF on stdin before negotiation completed.
    eprintln!("Error: stdin closed before negotiation completed");
    process::exit(1);
}

/// Decode a hex string into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    // Strip optional "0x" prefix.
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s = s.strip_prefix("0X").unwrap_or(s);

    if s.len() % 2 != 0 {
        return Err("odd number of hex digits".to_string());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}
