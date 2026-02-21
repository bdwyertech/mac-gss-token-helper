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

pub const GSS_C_DELEG_FLAG: OM_uint32 = 1;
pub const GSS_C_MUTUAL_FLAG: OM_uint32 = 2;
pub const GSS_C_SEQUENCE_FLAG: OM_uint32 = 8;
pub const GSS_C_DELEG_POLICY_FLAG: OM_uint32 = 32768;

// --- Status code classification ---

pub const GSS_C_GSS_CODE: i32 = 1;
pub const GSS_C_MECH_CODE: i32 = 2;

// --- Major status macros ---

pub const GSS_S_COMPLETE: OM_uint32 = 0;
pub const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
pub const GSS_S_FAILURE: OM_uint32 = 0x000D_0000;

/// Returns true if the major status indicates an error.
#[inline]
pub fn gss_error(major: OM_uint32) -> bool {
    (major & 0xFFFF_0000) != 0
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
