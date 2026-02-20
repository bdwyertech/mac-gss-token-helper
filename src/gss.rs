//! Safe Rust wrappers around the raw GSS FFI bindings.
//!
//! Provides RAII types that automatically release GSS resources on drop,
//! and converts GSS error codes into idiomatic `Result` types.

use crate::gss_ffi::{self, gss_buffer_desc, gss_ctx_id_t, gss_name_t, OM_uint32};
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// A GSS-API error carrying both major and minor status codes.
#[derive(Debug)]
pub struct GssError {
    pub major: OM_uint32,
    pub minor: OM_uint32,
}

impl fmt::Display for GssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = format_gss_status(self.major, self.minor);
        write!(f, "{msg}")
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
// Token acquisition
// ---------------------------------------------------------------------------

/// Acquires a single SPNEGO init token for the given service name.
///
/// Uses default credentials (`GSS_C_NO_CREDENTIAL`) so the OS picks up
/// whatever is in KCM / the keychain.
///
/// Returns the raw SPNEGO token bytes on success.
pub fn acquire_token(target: &GssName) -> Result<Vec<u8>, GssError> {
    let mut minor: OM_uint32 = 0;
    let mut ctx: gss_ctx_id_t = gss_ffi::GSS_C_NO_CONTEXT;
    let mut output_token = gss_buffer_desc::default();
    let input_token = gss_buffer_desc::default();
    let mut ret_flags: OM_uint32 = 0;
    let mut time_rec: OM_uint32 = 0;

    let req_flags = gss_ffi::GSS_C_MUTUAL_FLAG | gss_ffi::GSS_C_SEQUENCE_FLAG;

    let major = unsafe {
        gss_ffi::gss_init_sec_context(
            &mut minor,
            gss_ffi::GSS_C_NO_CREDENTIAL,
            &mut ctx,
            target.inner,
            gss_ffi::spnego_mech_oid(),
            req_flags,
            0, // default time
            gss_ffi::GSS_C_NO_CHANNEL_BINDINGS,
            &input_token,
            std::ptr::null_mut(), // actual_mech_type
            &mut output_token,
            &mut ret_flags,
            &mut time_rec,
        )
    };

    // Even on error we must clean up any partial context.
    let _ctx_guard = ContextGuard(ctx);

    if gss_ffi::gss_error(major) {
        // Release any partial output token.
        if !output_token.value.is_null() {
            unsafe {
                let mut m: OM_uint32 = 0;
                gss_ffi::gss_release_buffer(&mut m, &mut output_token);
            }
        }
        return Err(GssError { major, minor });
    }

    // Copy the token bytes into a Vec before releasing the GSS buffer.
    let token = if output_token.length > 0 && !output_token.value.is_null() {
        let slice = unsafe {
            std::slice::from_raw_parts(output_token.value.cast::<u8>(), output_token.length)
        };
        slice.to_vec()
    } else {
        Vec::new()
    };

    unsafe {
        let mut m: OM_uint32 = 0;
        gss_ffi::gss_release_buffer(&mut m, &mut output_token);
    }

    Ok(token)
}

// ---------------------------------------------------------------------------
// RAII guard for gss_ctx_id_t
// ---------------------------------------------------------------------------

struct ContextGuard(gss_ctx_id_t);

impl Drop for ContextGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut minor: OM_uint32 = 0;
            unsafe {
                gss_ffi::gss_delete_sec_context(&mut minor, &mut self.0, std::ptr::null_mut());
            }
        }
    }
}
