//! Raw FFI bindings to macOS GSS.framework.
//!
//! Only the subset of functions needed for SPNEGO token acquisition is declared here.

#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use std::os::raw::c_void;

// --- Primitive GSS types ---

pub type OM_uint32 = u32;
pub type gss_qop_t = OM_uint32;

/// Opaque pointer types used by GSS.framework.
pub type gss_name_t = *mut c_void;
pub type gss_cred_id_t = *mut c_void;
pub type gss_ctx_id_t = *mut c_void;

/// GSS buffer descriptor — carries length + pointer pairs across the C boundary.
#[repr(C)]
pub struct gss_buffer_desc {
    pub length: usize,
    pub value: *mut c_void,
}

impl Default for gss_buffer_desc {
    fn default() -> Self {
        Self {
            length: 0,
            value: std::ptr::null_mut(),
        }
    }
}

/// GSS OID descriptor — identifies mechanisms and name types.
#[repr(C)]
pub struct gss_OID_desc {
    pub length: OM_uint32,
    pub elements: *mut c_void,
}

pub type gss_OID = *mut gss_OID_desc;

/// GSS OID set descriptor.
#[repr(C)]
pub struct gss_OID_set_desc {
    pub count: usize,
    pub elements: gss_OID,
}

pub type gss_OID_set = *mut gss_OID_set_desc;

/// Channel bindings structure for TLS endpoint binding (RFC 5929).
#[repr(C)]
pub struct gss_channel_bindings_struct {
    pub initiator_addrtype: OM_uint32,
    pub initiator_address: gss_buffer_desc,
    pub acceptor_addrtype: OM_uint32,
    pub acceptor_address: gss_buffer_desc,
    pub application_data: gss_buffer_desc,
}

pub type gss_channel_bindings_t = *mut gss_channel_bindings_struct;

pub const GSS_C_NO_CHANNEL_BINDINGS_P: gss_channel_bindings_t = std::ptr::null_mut();

// --- Well-known constants ---

pub const GSS_C_NO_NAME: gss_name_t = std::ptr::null_mut();
pub const GSS_C_NO_CREDENTIAL: gss_cred_id_t = std::ptr::null_mut();
pub const GSS_C_NO_CONTEXT: gss_ctx_id_t = std::ptr::null_mut();
pub const GSS_C_NO_OID: gss_OID = std::ptr::null_mut();
pub const GSS_C_NO_OID_SET: gss_OID_set = std::ptr::null_mut();
pub const GSS_C_NO_CHANNEL_BINDINGS: gss_channel_bindings_t = std::ptr::null_mut();
pub const GSS_C_INDEFINITE: OM_uint32 = 0xFFFFFFFF;
pub const GSS_C_AF_UNSPECIFIED: OM_uint32 = 0;

// --- Request flags ---

// Context request/return flags, per `GSS.framework/Headers/gssapi.h`.
// Values are the bit positions fixed by RFC 2744 §1.2.

/// `GSS_C_DELEG_FLAG` (bit 0) — unconditionally delegate credentials.
pub const GSS_C_DELEG_FLAG: OM_uint32 = 1;
/// `GSS_C_MUTUAL_FLAG` (bit 1) — the acceptor must authenticate to us.
pub const GSS_C_MUTUAL_FLAG: OM_uint32 = 2;
/// `GSS_C_REPLAY_FLAG` (bit 2) — detect replayed per-message tokens.
pub const GSS_C_REPLAY_FLAG: OM_uint32 = 4;
/// `GSS_C_SEQUENCE_FLAG` (bit 3) — detect out-of-sequence per-message tokens.
pub const GSS_C_SEQUENCE_FLAG: OM_uint32 = 8;
/// `GSS_C_CONF_FLAG` (bit 4) — per-message confidentiality is available.
pub const GSS_C_CONF_FLAG: OM_uint32 = 16;
/// `GSS_C_INTEG_FLAG` (bit 5) — per-message integrity is available.
pub const GSS_C_INTEG_FLAG: OM_uint32 = 32;
/// `GSS_C_DELEG_POLICY_FLAG` (bit 15) — delegate only if policy permits.
pub const GSS_C_DELEG_POLICY_FLAG: OM_uint32 = 32768;

// --- Status code classification ---

pub const GSS_C_GSS_CODE: i32 = 1;
pub const GSS_C_MECH_CODE: i32 = 2;

// --- Major status bit fields (gssapi.h) ---
//
// A major status packs three independent fields: bits 31-24 calling error,
// bits 23-16 routine error, bits 15-0 supplementary information.

/// `GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET`.
pub const GSS_C_CALLING_ERROR_FIELD: OM_uint32 = 0xFF00_0000;
/// `GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET`.
pub const GSS_C_ROUTINE_ERROR_FIELD: OM_uint32 = 0x00FF_0000;
/// `GSS_C_SUPPLEMENTARY_MASK << GSS_C_SUPPLEMENTARY_OFFSET`.
pub const GSS_C_SUPPLEMENTARY_FIELD: OM_uint32 = 0x0000_FFFF;

pub const GSS_S_COMPLETE: OM_uint32 = 0;

// Supplementary bits: `1 << (GSS_C_SUPPLEMENTARY_OFFSET + n)`.
pub const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
pub const GSS_S_DUPLICATE_TOKEN: OM_uint32 = 2;
pub const GSS_S_OLD_TOKEN: OM_uint32 = 4;
pub const GSS_S_UNSEQ_TOKEN: OM_uint32 = 8;
pub const GSS_S_GAP_TOKEN: OM_uint32 = 16;

// Routine errors: `n << GSS_C_ROUTINE_ERROR_OFFSET` (offset 16).
pub const GSS_S_BAD_MECH: OM_uint32 = 1 << 16;
pub const GSS_S_BAD_NAME: OM_uint32 = 2 << 16;
pub const GSS_S_BAD_NAMETYPE: OM_uint32 = 3 << 16;
pub const GSS_S_NO_CRED: OM_uint32 = 7 << 16;
pub const GSS_S_NO_CONTEXT: OM_uint32 = 8 << 16;
pub const GSS_S_DEFECTIVE_TOKEN: OM_uint32 = 9 << 16;
pub const GSS_S_CREDENTIALS_EXPIRED: OM_uint32 = 11 << 16;
pub const GSS_S_FAILURE: OM_uint32 = 13 << 16;

/// Isolated calling-error field, per `GSS_CALLING_ERROR`.
#[inline]
pub fn calling_error(major: OM_uint32) -> OM_uint32 {
    major & GSS_C_CALLING_ERROR_FIELD
}

/// Isolated routine-error field, per `GSS_ROUTINE_ERROR`.
#[inline]
pub fn routine_error(major: OM_uint32) -> OM_uint32 {
    major & GSS_C_ROUTINE_ERROR_FIELD
}

/// Isolated supplementary field, per `GSS_SUPPLEMENTARY_INFO`.
#[inline]
pub fn supplementary_info(major: OM_uint32) -> OM_uint32 {
    major & GSS_C_SUPPLEMENTARY_FIELD
}

/// True when either error field is set, per `GSS_ERROR`.
#[inline]
pub fn is_error(major: OM_uint32) -> bool {
    (calling_error(major) | routine_error(major)) != 0
}

/// True when another negotiation leg is required and no error is present.
#[inline]
pub fn continue_needed(major: OM_uint32) -> bool {
    !is_error(major) && (supplementary_info(major) & GSS_S_CONTINUE_NEEDED) != 0
}

/// Returns true if the major status indicates an error.
#[inline]
pub fn gss_error(major: OM_uint32) -> bool {
    is_error(major)
}

#[cfg(test)]
mod status_tests {
    use super::*;

    const ROUTINE_ERRORS: &[OM_uint32] = &[
        GSS_S_BAD_MECH,
        GSS_S_BAD_NAME,
        GSS_S_BAD_NAMETYPE,
        GSS_S_NO_CRED,
        GSS_S_NO_CONTEXT,
        GSS_S_DEFECTIVE_TOKEN,
        GSS_S_CREDENTIALS_EXPIRED,
        GSS_S_FAILURE,
    ];

    #[test]
    fn routine_errors_occupy_only_the_routine_field() {
        for &err in ROUTINE_ERRORS {
            assert_eq!(routine_error(err), err);
            assert_eq!(calling_error(err), 0);
            assert_eq!(supplementary_info(err), 0);
            assert!(is_error(err));
            assert!(!continue_needed(err));
        }
    }

    #[test]
    fn continuation_survives_other_supplementary_bits() {
        let major = GSS_S_CONTINUE_NEEDED | GSS_S_OLD_TOKEN | GSS_S_UNSEQ_TOKEN;
        assert!(continue_needed(major));
        assert!(!is_error(major));
    }

    #[test]
    fn errors_win_over_supplementary_bits() {
        for &err in ROUTINE_ERRORS {
            let major = err | GSS_S_CONTINUE_NEEDED;
            assert!(is_error(major));
            assert!(!continue_needed(major));
        }

        let calling = 1u32 << 24;
        assert!(is_error(calling | GSS_S_CONTINUE_NEEDED));
    }

    #[test]
    fn complete_is_neither_error_nor_continuation() {
        assert!(!is_error(GSS_S_COMPLETE));
        assert!(!continue_needed(GSS_S_COMPLETE));
    }
}

/// Status bit-field classification.
#[cfg(test)]
mod status_properties {
    use super::*;
    use proptest::prelude::*;

    /// Reference model derived directly from the SDK macros.
    fn model(major: OM_uint32) -> (bool, bool) {
        let calling = (major >> 24) & 0xFF;
        let routine = (major >> 16) & 0xFF;
        let supplementary = major & 0xFFFF;
        let error = calling != 0 || routine != 0;
        (error, !error && (supplementary & 1) != 0)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn classification_matches_model(major in any::<u32>()) {
            let (expected_error, expected_continue) = model(major);
            prop_assert_eq!(is_error(major), expected_error);
            prop_assert_eq!(continue_needed(major), expected_continue);
        }

        #[test]
        fn fields_partition_the_status(major in any::<u32>()) {
            prop_assert_eq!(
                calling_error(major) | routine_error(major) | supplementary_info(major),
                major
            );
            prop_assert_eq!(calling_error(major) & routine_error(major), 0);
            prop_assert_eq!(routine_error(major) & supplementary_info(major), 0);
        }
    }
}

// --- Framework-exported OID descriptors ---
//
// macOS GSS.framework exports these as global symbols. Using the framework's
// own descriptors is required — the mechanism dispatch relies on them.

unsafe extern "C" {
    /// SPNEGO mechanism OID (1.3.6.1.5.5.2).
    pub static __gss_spnego_mechanism_oid_desc: gss_OID_desc;

    /// Name-type OID for host-based service names ("service@host").
    pub static __gss_c_nt_hostbased_service_oid_desc: gss_OID_desc;
}

/// Returns a pointer to the framework's SPNEGO mechanism OID.
pub fn spnego_mech_oid() -> gss_OID {
    (&raw const __gss_spnego_mechanism_oid_desc) as gss_OID
}

/// Returns a pointer to the GSS_C_NT_HOSTBASED_SERVICE OID.
pub fn hostbased_service_oid() -> gss_OID {
    // The extern static is immutable; cast to *mut is required by the GSS API
    // but the callee does not mutate through this pointer.
    (&raw const __gss_c_nt_hostbased_service_oid_desc) as gss_OID
}

// --- GSS API functions ---

unsafe extern "C" {
    pub fn gss_import_name(
        minor_status: *mut OM_uint32,
        input_name_buffer: *const gss_buffer_desc,
        input_name_type: gss_OID,
        output_name: *mut gss_name_t,
    ) -> OM_uint32;

    pub fn gss_init_sec_context(
        minor_status: *mut OM_uint32,
        initiator_cred_handle: gss_cred_id_t,
        context_handle: *mut gss_ctx_id_t,
        target_name: gss_name_t,
        mech_type: gss_OID,
        req_flags: OM_uint32,
        time_req: OM_uint32,
        input_chan_bindings: gss_channel_bindings_t,
        input_token: *const gss_buffer_desc,
        actual_mech_type: *mut gss_OID,
        output_token: *mut gss_buffer_desc,
        ret_flags: *mut OM_uint32,
        time_rec: *mut OM_uint32,
    ) -> OM_uint32;

    pub fn gss_display_status(
        minor_status: *mut OM_uint32,
        status_value: OM_uint32,
        status_type: i32,
        mech_type: gss_OID,
        message_context: *mut OM_uint32,
        status_string: *mut gss_buffer_desc,
    ) -> OM_uint32;

    pub fn gss_release_name(minor_status: *mut OM_uint32, name: *mut gss_name_t) -> OM_uint32;

    pub fn gss_release_buffer(
        minor_status: *mut OM_uint32,
        buffer: *mut gss_buffer_desc,
    ) -> OM_uint32;

    pub fn gss_delete_sec_context(
        minor_status: *mut OM_uint32,
        context_handle: *mut gss_ctx_id_t,
        output_token: *mut gss_buffer_desc,
    ) -> OM_uint32;
}
