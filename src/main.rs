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
            eprintln!("Usage: gss-token-helper <service/hostname>");
            eprintln!("  e.g. gss-token-helper HTTP/proxy.corp.example.com");
            process::exit(1);
        }
    };

    let name = match gss::import_name(&spn) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Error: failed to import name \"{spn}\": {e}");
            process::exit(1);
        }
    };

    let token = match gss::acquire_token(&name) {
        Ok(t) if t.is_empty() => {
            eprintln!("Error: GSS returned an empty token for \"{spn}\"");
            process::exit(1);
        }
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: gss_init_sec_context failed: {e}");
            process::exit(1);
        }
    };

    // Output the base64-encoded SPNEGO token on a single line, no trailing newline.
    print!("{}", STANDARD.encode(&token));
}
