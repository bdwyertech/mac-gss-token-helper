//! Library surface for `gss-token-helper`.
//!
//! The binary is a thin CLI over these modules. Exposing them as a library
//! lets integration tests, `trybuild` UI tests, and doc tests exercise the
//! same code the binary uses.

pub mod app;
pub mod gss;
pub mod gss_ffi;
pub mod input;
pub mod protocol;
