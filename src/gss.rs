//! Safe Rust wrappers around the raw GSS FFI bindings.
//!
//! Provides RAII types that automatically release GSS resources on drop,
//! and converts GSS error codes into idiomatic `Result` types.

use crate::gss_ffi::{
    self, gss_buffer_desc, gss_channel_bindings_struct, gss_ctx_id_t, gss_name_t, OM_uint32,
};
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Well-known GSS major status codes for error classification.
const GSS_S_BAD_MECH: OM_uint32 = 0x0001_0000;
const GSS_S_BAD_NAME: OM_uint32 = 0x0002_0000;
const GSS_S_BAD_NAMETYPE: OM_uint32 = 0x0003_0000;
const GSS_S_NO_CRED: OM_uint32 = 0x000D_0000;
const GSS_S_NO_CONTEXT: OM_uint32 = 0x000C_0000;
const GSS_S_DEFECTIVE_TOKEN: OM_uint32 = 0x0009_0000;
const GSS_S_CREDENTIALS_EXPIRED: OM_uint32 = 0x000B_0000;

/// A GSS-API error carrying both major and minor status codes.
#[derive(Debug)]
pub struct GssError {
    pub major: OM_uint32,
    pub minor: OM_uint32,
}

impl GssError {
    /// Returns a human-friendly hint explaining likely causes of this error.
    pub fn hint(&self) -> Option<&'static str> {
        // Extract the routine error (bits 16-23) for matching.
        let routine_bits = self.major & 0x00FF_0000;
        match routine_bits {
            x if x == GSS_S_BAD_MECH => Some(
                "Hint: This usually means no Kerberos credentials are available for the target \
                 realm, or the hostname could not be mapped to a Kerberos realm.\n  \
                 - Check that you have a valid ticket: run 'klist'\n  \
                 - If no ticket, run 'kinit user@REALM'\n  \
                 - Verify the hostname resolves: run 'host <hostname>'",
            ),
            x if x == GSS_S_NO_CRED => Some(
                "Hint: No Kerberos credentials found in the credential cache.\n  \
                 - Run 'klist' to check your tickets\n  \
                 - Run 'kinit user@REALM' to acquire a ticket",
            ),
            x if x == GSS_S_CREDENTIALS_EXPIRED => Some(
                "Hint: Your Kerberos ticket has expired.\n  \
                 - Run 'kinit user@REALM' to get a fresh ticket\n  \
                 - Or 'kinit -R' if your ticket is renewable",
            ),
            x if x == GSS_S_BAD_NAME || x == GSS_S_BAD_NAMETYPE => Some(
                "Hint: The service principal name format is invalid.\n  \
                 - Use the format: HTTP/hostname (e.g. HTTP/proxy.example.com)",
            ),
            x if x == GSS_S_DEFECTIVE_TOKEN => Some(
                "Hint: The server sent a malformed token. This may indicate a \
                 protocol mismatch or network issue.",
            ),
            x if x == GSS_S_NO_CONTEXT => Some(
                "Hint: The security context is invalid. If using --negotiate mode, \
                 ensure tokens are being exchanged in the correct order.",
            ),
            _ => None,
        }
    }
}

impl fmt::Display for GssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = format_gss_status(self.major, self.minor);
        write!(
            f,
            "{msg} (major={:#010x}, minor={:#010x})",
            self.major, self.minor
        )
    }
}

impl std::error::Error for GssError {}

/// Formats a GSS major/minor status pair into a human-readable string.
///
/// Mirrors the error-display loop in Heimdal's `gss_mk_err()`.
fn format_gss_status(major: OM_uint32, minor: OM_uint32) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Collect major status messages (unless it's the generic GSS_S_FAILURE).
    if major != gss_ffi::GSS_S_FAILURE {
        collect_status_messages(major, gss_ffi::GSS_C_GSS_CODE, &mut parts);
    }

    // Collect mechanism-specific (minor) status messages.
    if minor != 0 {
        collect_status_messages(minor, gss_ffi::GSS_C_MECH_CODE, &mut parts);
    }

    if parts.is_empty() {
        format!("GSS error: major={major:#010x}, minor={minor:#010x}")
    } else {
        parts.join(": ")
    }
}

fn collect_status_messages(status: OM_uint32, status_type: i32, out: &mut Vec<String>) {
    let mut msg_ctx: OM_uint32 = 0;
    loop {
        let mut minor: OM_uint32 = 0;
        let mut buf = gss_buffer_desc::default();

        let ret = unsafe {
            gss_ffi::gss_display_status(
                &mut minor,
                status,
                status_type,
                gss_ffi::GSS_C_NO_OID,
                &mut msg_ctx,
                &mut buf,
            )
        };

        if gss_ffi::gss_error(ret) {
            break;
        }

        if buf.length > 0 && !buf.value.is_null() {
            let slice = unsafe { std::slice::from_raw_parts(buf.value.cast::<u8>(), buf.length) };
            if let Ok(s) = std::str::from_utf8(slice) {
                out.push(s.to_owned());
            }
        }

        unsafe {
            gss_ffi::gss_release_buffer(&mut minor, &mut buf);
        }

        if msg_ctx == 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// RAII wrapper: GssName
// ---------------------------------------------------------------------------

/// Owns a `gss_name_t` and releases it on drop.
pub struct GssName {
    inner: gss_name_t,
}

impl Drop for GssName {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            let mut minor: OM_uint32 = 0;
            unsafe {
                gss_ffi::gss_release_name(&mut minor, &mut self.inner);
            }
        }
    }
}

/// Import a service principal name as a GSS name.
///
/// Accepts either `service@host` or `service/host` format.
/// macOS GSS.framework requires `service@host` for `GSS_C_NT_HOSTBASED_SERVICE`,
/// so `service/host` is automatically converted.
pub fn import_name(spn: &str) -> Result<GssName, GssError> {
    let mut minor: OM_uint32 = 0;
    let mut name: gss_name_t = gss_ffi::GSS_C_NO_NAME;

    // macOS GSS.framework expects "service@host" for GSS_C_NT_HOSTBASED_SERVICE.
    // Convert "service/host" to "service@host" if needed.
    let canonical = if !spn.contains('@') {
        spn.replacen('/', "@", 1)
    } else {
        spn.to_owned()
    };

    let buf = gss_buffer_desc {
        length: canonical.len(),
        value: canonical.as_ptr() as *mut _,
    };

    let major = unsafe {
        gss_ffi::gss_import_name(
            &mut minor,
            &buf,
            gss_ffi::hostbased_service_oid(),
            &mut name,
        )
    };

    if gss_ffi::gss_error(major) {
        return Err(GssError { major, minor });
    }

    Ok(GssName { inner: name })
}

// ---------------------------------------------------------------------------
// Options for token acquisition
// ---------------------------------------------------------------------------

/// Options controlling how `gss_init_sec_context` is called.
pub struct InitSecContextOpts<'a> {
    /// Request credential delegation (forward TGT to the service).
    pub delegate: bool,
    /// TLS channel bindings hash (tls-server-end-point, RFC 5929).
    /// When set, constructs a `gss_channel_bindings_struct` with this
    /// as the `application_data` field.
    pub channel_bindings: Option<&'a [u8]>,
}

impl Default for InitSecContextOpts<'_> {
    fn default() -> Self {
        Self {
            delegate: false,
            channel_bindings: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Security context (supports multi-leg negotiation)
// ---------------------------------------------------------------------------

/// Result of a single `gss_init_sec_context` call.
pub enum InitSecContextResult {
    /// Negotiation complete. Contains the final output token (may be empty).
    Complete(Vec<u8>),
    /// Server sent a challenge; more legs needed. Contains the output token
    /// to send to the server.
    ContinueNeeded(Vec<u8>),
}

/// Owns a GSS security context handle across multiple negotiation legs.
///
/// For single-shot token acquisition, call `step(None)` once.
/// For multi-leg negotiation, call `step(None)` for the first leg,
/// then `step(Some(response_token))` for each subsequent server response.
pub struct SecurityContext {
    ctx: gss_ctx_id_t,
    target: gss_name_t,
    req_flags: OM_uint32,
    // Owned channel bindings data kept alive for the context lifetime.
    _cb_data: Option<Vec<u8>>,
    cb: Option<gss_channel_bindings_struct>,
}

impl SecurityContext {
    /// Create a new security context for the given target name.
    pub fn new(target: &GssName, opts: &InitSecContextOpts<'_>) -> Self {
        let mut req_flags = gss_ffi::GSS_C_MUTUAL_FLAG | gss_ffi::GSS_C_SEQUENCE_FLAG;
        if opts.delegate {
            req_flags |= gss_ffi::GSS_C_DELEG_FLAG | gss_ffi::GSS_C_DELEG_POLICY_FLAG;
        }

        let (cb_data, cb) = if let Some(hash) = opts.channel_bindings {
            let owned = hash.to_vec();
            let bindings = gss_channel_bindings_struct {
                initiator_addrtype: gss_ffi::GSS_C_AF_UNSPECIFIED,
                initiator_address: gss_buffer_desc::default(),
                acceptor_addrtype: gss_ffi::GSS_C_AF_UNSPECIFIED,
                acceptor_address: gss_buffer_desc::default(),
                application_data: gss_buffer_desc {
                    length: owned.len(),
                    value: owned.as_ptr() as *mut _,
                },
            };
            (Some(owned), Some(bindings))
        } else {
            (None, None)
        };

        Self {
            ctx: gss_ffi::GSS_C_NO_CONTEXT,
            target: target.inner,
            req_flags,
            _cb_data: cb_data,
            cb,
        }
    }

    /// Perform one leg of the GSS negotiation.
    ///
    /// - First call: pass `input_token = None`
    /// - Subsequent calls: pass the server's response token
    ///
    /// Returns `Complete` when negotiation is done, or `ContinueNeeded`
    /// if the server needs to respond with another token.
    pub fn step(&mut self, input_token: Option<&[u8]>) -> Result<InitSecContextResult, GssError> {
        let mut minor: OM_uint32 = 0;
        let mut output_token = gss_buffer_desc::default();
        let mut ret_flags: OM_uint32 = 0;
        let mut time_rec: OM_uint32 = 0;

        let in_tok = match input_token {
            Some(data) => gss_buffer_desc {
                length: data.len(),
                value: data.as_ptr() as *mut _,
            },
            None => gss_buffer_desc::default(),
        };

        let cb_ptr = match self.cb {
            Some(ref mut cb) => cb as gss_ffi::gss_channel_bindings_t,
            None => gss_ffi::GSS_C_NO_CHANNEL_BINDINGS,
        };

        let major = unsafe {
            gss_ffi::gss_init_sec_context(
                &mut minor,
                gss_ffi::GSS_C_NO_CREDENTIAL,
                &mut self.ctx,
                self.target,
                gss_ffi::spnego_mech_oid(),
                self.req_flags,
                0,
                cb_ptr,
                &in_tok,
                std::ptr::null_mut(),
                &mut output_token,
                &mut ret_flags,
                &mut time_rec,
            )
        };

        if gss_ffi::gss_error(major) {
            if !output_token.value.is_null() {
                unsafe {
                    let mut m: OM_uint32 = 0;
                    gss_ffi::gss_release_buffer(&mut m, &mut output_token);
                }
            }
            return Err(GssError { major, minor });
        }

        let token = extract_and_release_buffer(&mut output_token);

        if major == gss_ffi::GSS_S_CONTINUE_NEEDED {
            Ok(InitSecContextResult::ContinueNeeded(token))
        } else {
            Ok(InitSecContextResult::Complete(token))
        }
    }
}

impl Drop for SecurityContext {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            let mut minor: OM_uint32 = 0;
            unsafe {
                gss_ffi::gss_delete_sec_context(&mut minor, &mut self.ctx, std::ptr::null_mut());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy single-shot API (kept for backward compatibility)
// ---------------------------------------------------------------------------

/// Acquires a single SPNEGO init token for the given service name.
///
/// Uses default credentials (`GSS_C_NO_CREDENTIAL`) so the OS picks up
/// whatever is in KCM / the keychain.
///
/// Returns the raw SPNEGO token bytes on success.
#[allow(dead_code)]
pub fn acquire_token(target: &GssName) -> Result<Vec<u8>, GssError> {
    let opts = InitSecContextOpts::default();
    let mut sec_ctx = SecurityContext::new(target, &opts);
    match sec_ctx.step(None)? {
        InitSecContextResult::Complete(tok) | InitSecContextResult::ContinueNeeded(tok) => Ok(tok),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Copy bytes out of a GSS buffer and release it.
fn extract_and_release_buffer(buf: &mut gss_buffer_desc) -> Vec<u8> {
    let token = if buf.length > 0 && !buf.value.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(buf.value.cast::<u8>(), buf.length) };
        slice.to_vec()
    } else {
        Vec::new()
    };

    unsafe {
        let mut m: OM_uint32 = 0;
        gss_ffi::gss_release_buffer(&mut m, buf);
    }

    token
}
