use std::env;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "macos" {
        panic!("This crate only supports macOS");
    }

    if let Ok(version) = env::var("BUILD_VERSION") {
        let clean_version = version
            .strip_prefix('v')
            .or_else(|| version.strip_prefix('V'))
            .unwrap_or(&version);
        println!("cargo:rustc-env=BUILD_VERSION={}", clean_version);
    }

    built::write_built_file().expect("Failed to acquire build-time information");

    // Bind to GSS framework
    println!("cargo:rustc-link-lib=framework=GSS");
}
