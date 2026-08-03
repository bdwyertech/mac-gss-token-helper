//! Safe Rust wrappers around the raw GSS FFI bindings.
//!
//! Provides RAII types that automatically release GSS resources on drop,
//! and converts GSS error codes into idiomatic `Result` types.

use crate::gss_ffi::{
    self, OM_uint32, gss_buffer_desc, gss_channel_bindings_struct, gss_ctx_id_t, gss_name_t,
};
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

// Routine-error constants come from `gss_ffi`, which transcribes them from the
// macOS SDK. Previously duplicated here, `GSS_S_NO_CRED` and `GSS_S_NO_CONTEXT`
// held the values of `GSS_S_FAILURE` and `GSS_S_CREDENTIALS_EXPIRED`.
use std::marker::PhantomData;

use gss_ffi::{
    GSS_S_BAD_MECH, GSS_S_BAD_NAME, GSS_S_BAD_NAMETYPE, GSS_S_CREDENTIALS_EXPIRED,
    GSS_S_DEFECTIVE_TOKEN, GSS_S_NO_CONTEXT, GSS_S_NO_CRED,
};

/// A GSS-API error carrying both major and minor status codes.
#[derive(Debug)]
pub struct GssError {
    pub major: OM_uint32,
    pub minor: OM_uint32,
}

impl GssError {
    /// Returns a human-friendly hint explaining likely causes of this error.
    pub fn hint(&self) -> Option<&'static str> {
        // Classify on the isolated routine-error field.
        let routine_bits = gss_ffi::routine_error(self.major);
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
        let mut buf = unsafe { OwnedGssBuffer::new(gss_buffer_desc::default(), &RealGss) };

        let ret = unsafe {
            gss_ffi::gss_display_status(
                &mut minor,
                status,
                status_type,
                gss_ffi::GSS_C_NO_OID,
                &mut msg_ctx,
                buf.as_mut_ptr(),
            )
        };

        if gss_ffi::gss_error(ret) {
            break;
        }

        if let Some(s) = buf.to_utf8() {
            out.push(s);
        }
        drop(buf);

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

/// How credential delegation should be requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DelegationMode {
    /// Request no delegation. Maps to no delegation flags.
    #[default]
    Disabled,
    /// Delegate only when KDC/service policy permits (OK-AS-DELEGATE).
    /// Maps to `GSS_C_DELEG_POLICY_FLAG` only.
    Policy,
    /// Delegate unconditionally. Maps to `GSS_C_DELEG_FLAG` only.
    Required,
}

impl DelegationMode {
    /// The GSS request flags this mode contributes — and nothing else.
    pub fn request_flags(self) -> OM_uint32 {
        match self {
            Self::Disabled => 0,
            Self::Policy => gss_ffi::GSS_C_DELEG_POLICY_FLAG,
            Self::Required => gss_ffi::GSS_C_DELEG_FLAG,
        }
    }
}

/// Security properties requested for every context, independent of
/// delegation: mutual authentication, replay and sequence detection, and
/// per-message integrity and confidentiality.
pub const BASE_REQUEST_FLAGS: OM_uint32 = gss_ffi::GSS_C_MUTUAL_FLAG
    | gss_ffi::GSS_C_REPLAY_FLAG
    | gss_ffi::GSS_C_SEQUENCE_FLAG
    | gss_ffi::GSS_C_INTEG_FLAG
    | gss_ffi::GSS_C_CONF_FLAG;

/// Options controlling how `gss_init_sec_context` is called.
#[derive(Default)]
pub struct InitSecContextOpts<'a> {
    /// How credential delegation should be requested.
    pub delegation: DelegationMode,
    /// TLS channel bindings hash (tls-server-end-point, RFC 5929).
    /// When set, constructs a `gss_channel_bindings_struct` with this
    /// as the `application_data` field.
    pub channel_bindings: Option<&'a [u8]>,
}

// ---------------------------------------------------------------------------
// Security context (supports multi-leg negotiation)
// ---------------------------------------------------------------------------

/// Negotiation state of a [`SecurityContext`].
///
/// Private by design: callers observe state only through the operations that
/// are legal for it and through [`InvalidTransition`] diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextState {
    /// No GSS call has been made yet.
    New,
    /// GSS reported continuation; a peer response token is required next.
    AwaitingPeer,
    /// Terminal: negotiation finished successfully.
    Complete,
    /// Terminal: a GSS call failed.
    Failed,
}

/// The two operations a caller can attempt on a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextOp {
    /// Begin the negotiation (no peer token).
    Start,
    /// Continue the negotiation with a peer response token.
    ContinueWith,
}

impl ContextState {
    /// Pure guard: is `op` legal in this state? This is the single source of
    /// truth for the state machine and is called before any GSS invocation.
    fn check(self, op: ContextOp) -> Result<(), InvalidTransition> {
        match (self, op) {
            (Self::New, ContextOp::Start) => Ok(()),
            (Self::New, ContextOp::ContinueWith) => Err(InvalidTransition::ContinueBeforeStart),
            (Self::AwaitingPeer, ContextOp::ContinueWith) => Ok(()),
            (Self::AwaitingPeer, ContextOp::Start) => Err(InvalidTransition::StartAfterStart),
            (Self::Complete, _) => Err(InvalidTransition::AlreadyComplete),
            (Self::Failed, _) => Err(InvalidTransition::AlreadyFailed),
        }
    }

    /// Is this a terminal state from which no operation can succeed?
    ///
    /// Used by the state-machine tests as an independent terminality oracle.
    #[allow(dead_code)]
    fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }

    /// State after a successful GSS call. Continuation keeps the negotiation
    /// open; any non-continuation success is terminal success.
    fn after_success(continue_needed: bool) -> Self {
        if continue_needed {
            Self::AwaitingPeer
        } else {
            Self::Complete
        }
    }

    /// State after a failed GSS call: always terminal failure.
    fn after_failure() -> Self {
        Self::Failed
    }
}

/// Render DER-encoded OID contents (no tag/length) as a dotted string.
///
/// Returns `None` for empty or malformed input rather than panicking.
fn der_oid_to_dotted(bytes: &[u8]) -> Option<String> {
    let (&first, rest) = bytes.split_first()?;
    // The first byte packs arcs 1 and 2 as 40 * arc1 + arc2.
    let mut out = format!("{}.{}", first / 40, first % 40);
    let mut arc: u64 = 0;
    let mut pending = false;
    for &b in rest {
        arc = arc.checked_mul(128)?.checked_add(u64::from(b & 0x7F))?;
        if b & 0x80 == 0 {
            out.push('.');
            out.push_str(&arc.to_string());
            arc = 0;
            pending = false;
        } else {
            pending = true;
        }
    }
    // A trailing continuation byte means the encoding was truncated.
    if pending { None } else { Some(out) }
}

/// Read a GSS-owned mechanism OID into a dotted string.
///
/// # Safety
/// `oid` must be null or point to a valid `gss_OID_desc` whose `elements`
/// buffer holds `length` readable bytes for the duration of the call.
unsafe fn oid_to_string(oid: gss_ffi::gss_OID) -> Option<String> {
    if oid.is_null() {
        return None;
    }
    let desc = unsafe { &*oid };
    if desc.elements.is_null() || desc.length == 0 {
        return None;
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(desc.elements as *const u8, desc.length as usize) };
    der_oid_to_dotted(bytes)
}

/// Security metadata returned by a successful `gss_init_sec_context` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextStep {
    /// `ret_flags` — the properties GSS actually granted.
    pub ret_flags: OM_uint32,
    /// `time_rec` — remaining context lifetime in seconds.
    pub time_rec: OM_uint32,
    /// Whether GSS asked for another negotiation leg.
    pub continue_needed: bool,
    /// `actual_mech_type` as a dotted OID string, when GSS reported one.
    pub actual_mech: Option<String>,
}

impl ContextStep {
    /// Was `flag` among the granted `ret_flags`?
    pub fn granted(&self, flag: OM_uint32) -> bool {
        self.ret_flags & flag != 0
    }

    /// Did GSS grant mutual authentication?
    pub fn mutual_auth(&self) -> bool {
        self.granted(gss_ffi::GSS_C_MUTUAL_FLAG)
    }

    /// Did GSS delegate credentials?
    pub fn delegated(&self) -> bool {
        self.granted(gss_ffi::GSS_C_DELEG_FLAG)
    }

    /// Verify that GSS actually granted everything the caller requires.
    ///
    /// Returns a controlled failure instead of letting a caller assume a
    /// property that the mechanism never granted.
    pub fn verify(&self, req: &SecurityRequirements) -> Result<(), VerificationError> {
        if req.mutual_auth && !self.mutual_auth() {
            return Err(VerificationError::MissingProperty("mutual authentication"));
        }
        if req.delegation && !self.delegated() {
            return Err(VerificationError::MissingProperty("credential delegation"));
        }
        if let Some(expected) = req.mech
            && self.actual_mech.as_deref() != Some(expected)
        {
            return Err(VerificationError::MechanismMismatch {
                expected: expected.to_string(),
                actual: self.actual_mech.clone(),
            });
        }
        Ok(())
    }
}

/// Security properties a caller insists on before using a context.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityRequirements {
    /// Require that GSS granted mutual authentication.
    pub mutual_auth: bool,
    /// Require that GSS actually delegated credentials.
    pub delegation: bool,
    /// Require this exact dotted mechanism OID, when set.
    pub mech: Option<&'static str>,
}

/// A required security property that GSS did not grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// A required context flag was absent from `ret_flags`.
    MissingProperty(&'static str),
    /// The negotiated mechanism was not the required one.
    MechanismMismatch {
        /// The dotted OID the caller required.
        expected: String,
        /// The dotted OID GSS reported, if any.
        actual: Option<String>,
    },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProperty(name) => {
                write!(f, "GSS did not grant required property: {name}")
            }
            Self::MechanismMismatch { expected, actual } => write!(
                f,
                "GSS negotiated mechanism {} but {expected} was required",
                actual.as_deref().unwrap_or("<none>")
            ),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Context-owned, stable storage for channel-binding application data.
///
/// The bytes live in a `Box<[u8]>` whose heap allocation does not move when
/// the owning `SecurityContext` moves, and the `gss_channel_bindings_struct`
/// is built from that storage at each call rather than cached.
struct ChannelBindings {
    data: Box<[u8]>,
}

impl ChannelBindings {
    fn new(bytes: &[u8]) -> Self {
        Self {
            data: bytes.to_vec().into_boxed_slice(),
        }
    }

    /// Build the descriptor for one GSS call, pointing at stable storage.
    ///
    /// The returned value borrows `self`, so it cannot outlive the storage.
    fn descriptor(&self) -> gss_channel_bindings_struct {
        gss_channel_bindings_struct {
            initiator_addrtype: gss_ffi::GSS_C_AF_UNSPECIFIED,
            initiator_address: gss_buffer_desc::default(),
            acceptor_addrtype: gss_ffi::GSS_C_AF_UNSPECIFIED,
            acceptor_address: gss_buffer_desc::default(),
            application_data: gss_buffer_desc {
                length: self.data.len(),
                value: self.data.as_ptr() as *mut _,
            },
        }
    }

    /// The application-data bytes as handed to GSS.
    ///
    /// Used by the channel-binding tests to compare stored bytes against the
    /// bytes the descriptor exposes.
    #[allow(dead_code)]
    fn application_data(&self) -> &[u8] {
        &self.data
    }
}

/// A rejected state-machine transition. Raised before any GSS call is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidTransition {
    /// `start` was called with a peer token, which the initial state forbids.
    InputTokenInInitialState,
    /// `continue_with` was called before `start`.
    ContinueBeforeStart,
    /// `start` was called on a context already awaiting a peer response.
    StartAfterStart,
    /// Any operation was attempted after the negotiation completed.
    AlreadyComplete,
    /// Any operation was attempted after the negotiation failed.
    AlreadyFailed,
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InputTokenInInitialState => {
                "an input token was supplied before the negotiation started"
            }
            Self::ContinueBeforeStart => "continuation attempted before the negotiation started",
            Self::StartAfterStart => "the negotiation has already been started",
            Self::AlreadyComplete => "the negotiation is already complete",
            Self::AlreadyFailed => "the negotiation has already failed",
        };
        write!(f, "invalid security-context transition: {msg}")
    }
}

impl std::error::Error for InvalidTransition {}

/// Failure of a context operation: either a rejected transition or a GSS error.
#[derive(Debug)]
pub enum ContextError {
    /// The operation was illegal for the current state; GSS was never called.
    Transition(InvalidTransition),
    /// GSS was called and returned an error; the context is now failed.
    Gss(GssError),
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transition(e) => write!(f, "{e}"),
            Self::Gss(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ContextError {}

impl From<InvalidTransition> for ContextError {
    fn from(e: InvalidTransition) -> Self {
        Self::Transition(e)
    }
}

impl From<GssError> for ContextError {
    fn from(e: GssError) -> Self {
        Self::Gss(e)
    }
}

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
pub struct SecurityContext<'name> {
    ctx: gss_ctx_id_t,
    target: gss_name_t,
    /// Borrow of the `GssName` that owns `target`, so the context can never
    /// outlive the name whose `gss_name_t` it dereferences.
    _target_name: PhantomData<&'name GssName>,
    req_flags: OM_uint32,
    /// Current negotiation state; gates every GSS call.
    state: ContextState,
    /// Stable, context-owned channel-binding storage (never a cached pointer).
    cb: Option<ChannelBindings>,
    /// Metadata from the most recent successful GSS call.
    last_step: Option<ContextStep>,
}

impl<'name> SecurityContext<'name> {
    /// Create a new security context for the given target name.
    pub fn new(target: &'name GssName, opts: &InitSecContextOpts<'_>) -> Self {
        Self {
            ctx: gss_ffi::GSS_C_NO_CONTEXT,
            target: target.inner,
            _target_name: PhantomData,
            req_flags: BASE_REQUEST_FLAGS | opts.delegation.request_flags(),
            state: ContextState::New,
            cb: opts.channel_bindings.map(ChannelBindings::new),
            last_step: None,
        }
    }

    /// The flags requested from GSS for this context.
    pub fn requested_flags(&self) -> OM_uint32 {
        self.req_flags
    }

    /// Metadata from the most recent successful GSS call, if any.
    pub fn last_step(&self) -> Option<&ContextStep> {
        self.last_step.as_ref()
    }

    /// Begin the negotiation. Legal only in the initial state.
    pub fn start(&mut self) -> Result<InitSecContextResult, ContextError> {
        self.state.check(ContextOp::Start)?;
        self.step_checked(None)
    }

    /// Continue the negotiation with the peer's response token. Legal only
    /// while the context is awaiting a peer response.
    pub fn continue_with(&mut self, token: &[u8]) -> Result<InitSecContextResult, ContextError> {
        self.state.check(ContextOp::ContinueWith)?;
        self.step_checked(Some(token))
    }

    /// Perform one leg of the GSS negotiation, updating the state from the
    /// resulting major status. Callers must have validated the transition.
    fn step_checked(
        &mut self,
        input_token: Option<&[u8]>,
    ) -> Result<InitSecContextResult, ContextError> {
        match self.step(input_token) {
            Ok(InitSecContextResult::ContinueNeeded(tok)) => {
                self.state = ContextState::after_success(true);
                Ok(InitSecContextResult::ContinueNeeded(tok))
            }
            Ok(InitSecContextResult::Complete(tok)) => {
                self.state = ContextState::after_success(false);
                Ok(InitSecContextResult::Complete(tok))
            }
            Err(e) => {
                self.state = ContextState::after_failure();
                Err(ContextError::Gss(e))
            }
        }
    }

    /// Raw single leg of the GSS negotiation, without state enforcement.
    fn step(&mut self, input_token: Option<&[u8]>) -> Result<InitSecContextResult, GssError> {
        let mut minor: OM_uint32 = 0;
        let mut output_token = unsafe { OwnedGssBuffer::new(gss_buffer_desc::default(), &RealGss) };
        let mut ret_flags: OM_uint32 = 0;
        let mut time_rec: OM_uint32 = 0;
        let mut actual_mech: gss_ffi::gss_OID = std::ptr::null_mut();

        let in_tok = match input_token {
            Some(data) => gss_buffer_desc {
                length: data.len(),
                value: data.as_ptr() as *mut _,
            },
            None => gss_buffer_desc::default(),
        };

        // Build the bindings descriptor for *this* call from the context-owned
        // storage, so no pointer can outlive or predate a move of the owner.
        let mut cb_desc = self.cb.as_ref().map(ChannelBindings::descriptor);
        let cb_ptr = match cb_desc {
            Some(ref mut desc) => desc as gss_ffi::gss_channel_bindings_t,
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
                &mut actual_mech,
                output_token.as_mut_ptr(),
                &mut ret_flags,
                &mut time_rec,
            )
        };

        if gss_ffi::gss_error(major) {
            return Err(GssError { major, minor });
        }

        let token = output_token.to_vec();
        drop(output_token);

        // Continuation is a supplementary bit and may accompany other bits.
        let continue_needed = gss_ffi::continue_needed(major);
        self.last_step = Some(ContextStep {
            ret_flags,
            time_rec,
            continue_needed,
            // `actual_mech_type` is a read-only mechanism OID owned by GSS;
            // it must not be freed by us.
            actual_mech: unsafe { oid_to_string(actual_mech) },
        });

        if continue_needed {
            Ok(InitSecContextResult::ContinueNeeded(token))
        } else {
            Ok(InitSecContextResult::Complete(token))
        }
    }
}

impl Drop for SecurityContext<'_> {
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
pub fn acquire_token(target: &GssName) -> Result<Vec<u8>, ContextError> {
    let opts = InitSecContextOpts::default();
    let mut sec_ctx = SecurityContext::new(target, &opts);
    match sec_ctx.start()? {
        InitSecContextResult::Complete(tok) | InitSecContextResult::ContinueNeeded(tok) => Ok(tok),
    }
}

// ---------------------------------------------------------------------------
// GSS API abstraction (private)
// ---------------------------------------------------------------------------

/// The subset of GSS calls that own or free resources.
///
/// Kept private so the public API never leaks FFI details; a test fake
/// implements it to count releases per resource.
trait GssApi {
    /// Releases a GSS buffer, returning the minor status reported.
    ///
    /// # Safety
    /// `buf` must describe a buffer allocated by the GSS implementation and
    /// not previously released.
    unsafe fn release_buffer(&self, buf: &mut gss_buffer_desc) -> OM_uint32;
}

/// Adapter that forwards to the real macOS GSS.framework.
struct RealGss;

impl GssApi for RealGss {
    unsafe fn release_buffer(&self, buf: &mut gss_buffer_desc) -> OM_uint32 {
        let mut minor: OM_uint32 = 0;
        unsafe {
            gss_ffi::gss_release_buffer(&mut minor, buf);
        }
        minor
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Single owner of a `gss_buffer_desc`, releasing it exactly once on drop.
struct OwnedGssBuffer<'api, A: GssApi> {
    buf: gss_buffer_desc,
    api: &'api A,
    released: bool,
}

impl<'api, A: GssApi> OwnedGssBuffer<'api, A> {
    /// Takes ownership of `buf`.
    ///
    /// # Safety
    /// `buf` must have been produced by a GSS call through `api` and must not
    /// be released or aliased elsewhere.
    unsafe fn new(buf: gss_buffer_desc, api: &'api A) -> Self {
        Self {
            buf,
            api,
            released: false,
        }
    }

    /// Returns a mutable pointer for passing to GSS output parameters.
    fn as_mut_ptr(&mut self) -> *mut gss_buffer_desc {
        &raw mut self.buf
    }

    /// Copies the buffer contents into an owned vector.
    fn to_vec(&self) -> Vec<u8> {
        if self.buf.length == 0 || self.buf.value.is_null() {
            return Vec::new();
        }
        let slice =
            unsafe { std::slice::from_raw_parts(self.buf.value.cast::<u8>(), self.buf.length) };
        slice.to_vec()
    }

    /// Copies the buffer contents as UTF-8, if valid.
    fn to_utf8(&self) -> Option<String> {
        String::from_utf8(self.to_vec()).ok()
    }
}

impl<A: GssApi> Drop for OwnedGssBuffer<'_, A> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        unsafe {
            self.api.release_buffer(&mut self.buf);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: resource ownership
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use std::cell::RefCell;

    /// Fake adapter recording one release event per buffer address.
    #[derive(Default)]
    pub(super) struct FakeGss {
        pub releases: RefCell<Vec<usize>>,
    }

    impl FakeGss {
        pub fn count_for(&self, addr: usize) -> usize {
            self.releases
                .borrow()
                .iter()
                .filter(|a| **a == addr)
                .count()
        }

        pub fn total(&self) -> usize {
            self.releases.borrow().len()
        }
    }

    impl GssApi for FakeGss {
        unsafe fn release_buffer(&self, buf: &mut gss_buffer_desc) -> OM_uint32 {
            self.releases.borrow_mut().push(buf.value as usize);
            buf.length = 0;
            buf.value = std::ptr::null_mut();
            0
        }
    }

    fn buffer_from(bytes: &mut [u8]) -> gss_buffer_desc {
        gss_buffer_desc {
            length: bytes.len(),
            value: bytes.as_mut_ptr().cast(),
        }
    }

    #[test]
    fn guard_releases_exactly_once_on_drop() {
        let api = FakeGss::default();
        let mut bytes = *b"token";
        let raw = buffer_from(&mut bytes);
        let addr = raw.value as usize;

        let guard = unsafe { OwnedGssBuffer::new(raw, &api) };
        assert_eq!(api.total(), 0, "no release before drop");
        drop(guard);

        assert_eq!(api.count_for(addr), 1, "released exactly once");
    }

    #[test]
    fn copying_out_does_not_release_early_or_twice() {
        let api = FakeGss::default();
        let mut bytes = *b"token";
        let raw = buffer_from(&mut bytes);
        let addr = raw.value as usize;

        let guard = unsafe { OwnedGssBuffer::new(raw, &api) };
        assert_eq!(guard.to_vec(), b"token".to_vec());
        assert_eq!(guard.to_utf8().as_deref(), Some("token"));
        assert_eq!(api.total(), 0, "accessors never release");
        drop(guard);

        assert_eq!(api.count_for(addr), 1);
    }

    #[test]
    fn empty_and_null_buffers_are_still_released_once() {
        let api = FakeGss::default();
        let guard = unsafe { OwnedGssBuffer::new(gss_buffer_desc::default(), &api) };
        assert_eq!(guard.to_vec(), Vec::<u8>::new());
        drop(guard);

        assert_eq!(api.total(), 1, "null buffer released once");
    }

    #[test]
    fn every_guard_releases_its_own_buffer() {
        let api = FakeGss::default();
        let mut a = *b"aaaa";
        let mut b = *b"bb";
        let (ra, rb) = (buffer_from(&mut a), buffer_from(&mut b));
        let (addr_a, addr_b) = (ra.value as usize, rb.value as usize);

        {
            let _ga = unsafe { OwnedGssBuffer::new(ra, &api) };
            let _gb = unsafe { OwnedGssBuffer::new(rb, &api) };
        }

        assert_eq!(api.count_for(addr_a), 1);
        assert_eq!(api.count_for(addr_b), 1);
        assert_eq!(api.count_for(addr_b), 1);
        assert_eq!(api.total(), 2, "no extra releases");
    }
}

// ---------------------------------------------------------------------------
// Resource release conservation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ownership_properties {
    use super::ownership_tests::FakeGss;
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Every guard created releases its buffer exactly once, regardless of
        /// how many accessor calls happen first.
        #[test]
        fn releases_equal_guards_created(
            payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..32), 0..16),
            reads in 0usize..4,
        ) {
            let api = FakeGss::default();
            let mut owned: Vec<Vec<u8>> = payloads.clone();

            {
                let mut guards = Vec::new();
                for bytes in &mut owned {
                    let raw = gss_buffer_desc {
                        length: bytes.len(),
                        value: if bytes.is_empty() {
                            std::ptr::null_mut()
                        } else {
                            bytes.as_mut_ptr().cast()
                        },
                    };
                    guards.push(unsafe { OwnedGssBuffer::new(raw, &api) });
                }

                for guard in &guards {
                    for _ in 0..reads {
                        let _ = guard.to_vec();
                    }
                }

                prop_assert_eq!(api.total(), 0, "nothing released while guards live");
            }

            prop_assert_eq!(api.total(), payloads.len());
        }
    }
}

// ---------------------------------------------------------------------------
// State-machine tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod state_machine_tests {
    use super::*;
    use std::cell::RefCell;

    /// Outcome the fake GSS layer should report for the next call.
    #[derive(Debug, Clone, Copy)]
    enum FakeOutcome {
        Continue,
        Complete,
        Error,
    }

    /// A context driver that shares `ContextState` with the real code but
    /// records GSS invocations instead of performing them. This lets the tests
    /// assert that rejected transitions never reach GSS.
    struct FakeContext {
        state: ContextState,
        calls: RefCell<Vec<Option<Vec<u8>>>>,
        outcomes: RefCell<Vec<FakeOutcome>>,
    }

    impl FakeContext {
        fn new(outcomes: Vec<FakeOutcome>) -> Self {
            Self {
                state: ContextState::New,
                calls: RefCell::new(Vec::new()),
                outcomes: RefCell::new(outcomes),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.borrow().len()
        }

        /// Mirrors `SecurityContext::step_checked`: guard, then "call GSS",
        /// then apply the post-call transition.
        fn drive(
            &mut self,
            op: ContextOp,
            input: Option<&[u8]>,
        ) -> Result<InitSecContextResult, ContextError> {
            self.state.check(op)?;
            self.calls.borrow_mut().push(input.map(<[u8]>::to_vec));
            let outcome = self
                .outcomes
                .borrow_mut()
                .pop()
                .unwrap_or(FakeOutcome::Complete);
            match outcome {
                FakeOutcome::Continue => {
                    self.state = ContextState::after_success(true);
                    Ok(InitSecContextResult::ContinueNeeded(Vec::new()))
                }
                FakeOutcome::Complete => {
                    self.state = ContextState::after_success(false);
                    Ok(InitSecContextResult::Complete(Vec::new()))
                }
                FakeOutcome::Error => {
                    self.state = ContextState::after_failure();
                    Err(ContextError::Gss(GssError {
                        major: gss_ffi::GSS_S_FAILURE,
                        minor: 0,
                    }))
                }
            }
        }

        fn start(&mut self) -> Result<InitSecContextResult, ContextError> {
            self.drive(ContextOp::Start, None)
        }

        fn continue_with(&mut self, tok: &[u8]) -> Result<InitSecContextResult, ContextError> {
            self.drive(ContextOp::ContinueWith, Some(tok))
        }
    }

    fn transition_err(r: Result<InitSecContextResult, ContextError>) -> InvalidTransition {
        match r {
            Err(ContextError::Transition(t)) => t,
            _ => panic!("expected a rejected transition"),
        }
    }

    #[test]
    fn first_step_without_a_peer_token_is_allowed() {
        let mut ctx = FakeContext::new(vec![FakeOutcome::Continue]);
        assert!(ctx.start().is_ok());
        assert_eq!(ctx.call_count(), 1);
        assert_eq!(ctx.state, ContextState::AwaitingPeer);
        assert_eq!(
            ctx.calls.borrow()[0],
            None,
            "no input token on the first leg"
        );
    }

    #[test]
    fn continuation_with_a_peer_token_is_allowed() {
        let mut ctx = FakeContext::new(vec![FakeOutcome::Complete, FakeOutcome::Continue]);
        ctx.start().expect("start");
        assert!(ctx.continue_with(b"peer").is_ok());
        assert_eq!(ctx.call_count(), 2);
        assert_eq!(ctx.state, ContextState::Complete);
        assert_eq!(ctx.calls.borrow()[1].as_deref(), Some(&b"peer"[..]));
    }

    /// A token supplied before starting is rejected pre-GSS.
    #[test]
    fn continuation_before_start_never_reaches_gss() {
        let mut ctx = FakeContext::new(vec![FakeOutcome::Complete]);
        let err = transition_err(ctx.continue_with(b"early"));
        assert_eq!(err, InvalidTransition::ContinueBeforeStart);
        assert_eq!(ctx.call_count(), 0, "GSS must not be called");
        assert_eq!(ctx.state, ContextState::New, "state is unchanged");
    }

    /// Re-starting an in-flight negotiation is rejected.
    #[test]
    fn restarting_an_awaiting_context_never_reaches_gss() {
        let mut ctx = FakeContext::new(vec![FakeOutcome::Continue]);
        ctx.start().expect("start");
        let err = transition_err(ctx.start());
        assert_eq!(err, InvalidTransition::StartAfterStart);
        assert_eq!(ctx.call_count(), 1, "no second GSS call");
        assert_eq!(ctx.state, ContextState::AwaitingPeer);
    }

    /// Nothing is legal after completion.
    #[test]
    fn stepping_after_completion_never_reaches_gss() {
        let mut ctx = FakeContext::new(vec![FakeOutcome::Complete]);
        ctx.start().expect("start");
        assert_eq!(ctx.state, ContextState::Complete);

        for err in [
            transition_err(ctx.start()),
            transition_err(ctx.continue_with(b"late")),
        ] {
            assert_eq!(err, InvalidTransition::AlreadyComplete);
        }
        assert_eq!(ctx.call_count(), 1, "only the original GSS call");
    }

    /// A GSS error is terminal and latches.
    #[test]
    fn gss_failure_is_terminal_and_blocks_further_steps() {
        let mut ctx = FakeContext::new(vec![FakeOutcome::Error]);
        assert!(matches!(ctx.start(), Err(ContextError::Gss(_))));
        assert_eq!(ctx.state, ContextState::Failed);
        assert!(ctx.state.is_terminal());

        for err in [
            transition_err(ctx.start()),
            transition_err(ctx.continue_with(b"retry")),
        ] {
            assert_eq!(err, InvalidTransition::AlreadyFailed);
        }
        assert_eq!(ctx.call_count(), 1, "no retry reaches GSS");
    }

    /// Failure mid-negotiation is equally terminal.
    #[test]
    fn failure_during_continuation_is_terminal() {
        let mut ctx = FakeContext::new(vec![FakeOutcome::Error, FakeOutcome::Continue]);
        ctx.start().expect("start");
        assert!(matches!(
            ctx.continue_with(b"peer"),
            Err(ContextError::Gss(_))
        ));
        assert_eq!(ctx.state, ContextState::Failed);
        assert_eq!(
            transition_err(ctx.continue_with(b"more")),
            InvalidTransition::AlreadyFailed
        );
        assert_eq!(ctx.call_count(), 2);
    }

    // -----------------------------------------------------------------------
    // Context transition model
    // -----------------------------------------------------------------------

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// Reference model, written independently of `ContextState::check`.
        ///
        /// States are named by string so the model shares no code with the
        /// implementation under test.
        fn model_step(state: &str, is_start: bool, outcome: FakeOutcome) -> (bool, &'static str) {
            let accepted = matches!((state, is_start), ("new", true) | ("awaiting", false));
            if !accepted {
                let unchanged = match state {
                    "new" => "new",
                    "awaiting" => "awaiting",
                    "complete" => "complete",
                    _ => "failed",
                };
                return (false, unchanged);
            }
            let next = match outcome {
                FakeOutcome::Continue => "awaiting",
                FakeOutcome::Complete => "complete",
                FakeOutcome::Error => "failed",
            };
            (true, next)
        }

        fn state_name(state: ContextState) -> &'static str {
            match state {
                ContextState::New => "new",
                ContextState::AwaitingPeer => "awaiting",
                ContextState::Complete => "complete",
                ContextState::Failed => "failed",
            }
        }

        /// (is_start, outcome) events; 0..=5 encodes both dimensions.
        fn event() -> impl Strategy<Value = (bool, FakeOutcome)> {
            (0u8..6).prop_map(|n| {
                let outcome = match n % 3 {
                    0 => FakeOutcome::Continue,
                    1 => FakeOutcome::Complete,
                    _ => FakeOutcome::Error,
                };
                (n < 3, outcome)
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            /// GSS is invoked exactly for model-accepted transitions and never
            /// after a terminal state is reached.
            #[test]
            fn transitions_follow_the_reference_model(
                events in prop::collection::vec(event(), 1..12)
            ) {
                let mut ctx = FakeContext::new(Vec::new());
                let mut model = "new";
                let mut expected_calls = 0usize;
                let mut terminal_reached = false;

                for (is_start, outcome) in events {
                    let calls_before = ctx.call_count();
                    // Feed this leg's outcome to the fake GSS layer.
                    ctx.outcomes.borrow_mut().push(outcome);

                    let (accepted, next) = model_step(model, is_start, outcome);
                    let result = if is_start {
                        ctx.start()
                    } else {
                        ctx.continue_with(b"peer")
                    };

                    // A transition error means the guard rejected the operation
                    // before GSS; a GSS error still counts as accepted.
                    let rejected = matches!(result, Err(ContextError::Transition(_)));
                    prop_assert_eq!(
                        !rejected,
                        accepted,
                        "acceptance disagrees with the model in state {}",
                        model
                    );

                    if accepted {
                        expected_calls += 1;
                    } else {
                        // Rejected transitions consume no outcome and no call.
                        ctx.outcomes.borrow_mut().pop();
                        prop_assert_eq!(
                            ctx.call_count(),
                            calls_before,
                            "GSS was called for a rejected transition"
                        );
                    }

                    if terminal_reached {
                        prop_assert_eq!(
                            ctx.call_count(),
                            calls_before,
                            "GSS was called after a terminal state"
                        );
                    }

                    model = next;
                    prop_assert_eq!(state_name(ctx.state), model, "state diverged from the model");
                    terminal_reached |= ctx.state.is_terminal();
                    prop_assert_eq!(ctx.call_count(), expected_calls);
                }
            }
        }
    }
}

#[cfg(test)]
mod security_request_tests {
    use super::*;

    fn step(ret_flags: OM_uint32, mech: Option<&str>) -> ContextStep {
        ContextStep {
            ret_flags,
            time_rec: 300,
            continue_needed: false,
            actual_mech: mech.map(str::to_string),
        }
    }

    #[test]
    fn each_delegation_mode_maps_only_its_own_flag() {
        assert_eq!(DelegationMode::Disabled.request_flags(), 0);
        assert_eq!(
            DelegationMode::Policy.request_flags(),
            gss_ffi::GSS_C_DELEG_POLICY_FLAG
        );
        assert_eq!(
            DelegationMode::Required.request_flags(),
            gss_ffi::GSS_C_DELEG_FLAG
        );
    }

    #[test]
    fn the_documented_base_flag_set_is_requested() {
        for flag in [
            gss_ffi::GSS_C_MUTUAL_FLAG,
            gss_ffi::GSS_C_REPLAY_FLAG,
            gss_ffi::GSS_C_SEQUENCE_FLAG,
            gss_ffi::GSS_C_INTEG_FLAG,
            gss_ffi::GSS_C_CONF_FLAG,
        ] {
            assert_ne!(BASE_REQUEST_FLAGS & flag, 0, "missing flag {flag:#x}");
        }
        assert_eq!(BASE_REQUEST_FLAGS & gss_ffi::GSS_C_DELEG_FLAG, 0);
    }

    #[test]
    fn ungranted_required_properties_fail_verification() {
        let s = step(gss_ffi::GSS_C_INTEG_FLAG, None);
        let need_mutual = SecurityRequirements {
            mutual_auth: true,
            ..Default::default()
        };
        assert_eq!(
            s.verify(&need_mutual),
            Err(VerificationError::MissingProperty("mutual authentication"))
        );
        let need_deleg = SecurityRequirements {
            delegation: true,
            ..Default::default()
        };
        assert_eq!(
            s.verify(&need_deleg),
            Err(VerificationError::MissingProperty("credential delegation"))
        );
    }

    #[test]
    fn mechanism_mismatch_is_reported_with_both_oids() {
        let s = step(gss_ffi::GSS_C_MUTUAL_FLAG, Some("1.2.840.113554.1.2.2"));
        let req = SecurityRequirements {
            mech: Some("1.3.6.1.5.5.2"),
            ..Default::default()
        };
        assert_eq!(
            s.verify(&req),
            Err(VerificationError::MechanismMismatch {
                expected: "1.3.6.1.5.5.2".to_string(),
                actual: Some("1.2.840.113554.1.2.2".to_string()),
            })
        );
    }

    #[test]
    fn fully_granted_requirements_verify() {
        let s = step(
            gss_ffi::GSS_C_MUTUAL_FLAG | gss_ffi::GSS_C_DELEG_FLAG,
            Some("1.3.6.1.5.5.2"),
        );
        let req = SecurityRequirements {
            mutual_auth: true,
            delegation: true,
            mech: Some("1.3.6.1.5.5.2"),
        };
        assert_eq!(s.verify(&req), Ok(()));
    }

    /// Delegation flag mapping.
    mod properties {
        use super::*;
        use proptest::prelude::*;

        const MODES: [DelegationMode; 3] = [
            DelegationMode::Disabled,
            DelegationMode::Policy,
            DelegationMode::Required,
        ];

        /// Independent reference model: the exact bit each mode owns.
        fn model(mode: DelegationMode) -> OM_uint32 {
            match mode {
                DelegationMode::Disabled => 0,
                DelegationMode::Policy => 32768,
                DelegationMode::Required => 1,
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Every mode contributes exactly its own documented bit, and the
            /// full request set is that bit plus the fixed base set.
            #[test]
            fn delegation_maps_only_its_documented_flag(i in 0usize..3) {
                let mode = MODES[i];
                let flags = mode.request_flags();
                prop_assert_eq!(flags, model(mode));
                let full = BASE_REQUEST_FLAGS | flags;
                prop_assert_eq!(full & !BASE_REQUEST_FLAGS, model(mode));
            }
        }
    }
}

#[cfg(test)]
mod channel_binding_tests {
    use super::*;

    /// Read back the bytes a descriptor points at, as GSS would.
    fn observed(desc: &gss_channel_bindings_struct) -> Vec<u8> {
        let ad = &desc.application_data;
        if ad.value.is_null() || ad.length == 0 {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(ad.value as *const u8, ad.length).to_vec() }
    }

    #[test]
    fn epa_application_data_equals_the_supplied_bytes() {
        let bytes = b"tls-server-end-point:hash".to_vec();
        let cb = ChannelBindings::new(&bytes);
        assert_eq!(cb.application_data(), &bytes[..]);
        assert_eq!(observed(&cb.descriptor()), bytes);
    }

    #[test]
    fn descriptors_use_unspecified_addresses_and_empty_address_buffers() {
        let cb = ChannelBindings::new(b"x");
        let d = cb.descriptor();
        assert_eq!(d.initiator_addrtype, gss_ffi::GSS_C_AF_UNSPECIFIED);
        assert_eq!(d.acceptor_addrtype, gss_ffi::GSS_C_AF_UNSPECIFIED);
        assert_eq!(d.initiator_address.length, 0);
        assert_eq!(d.acceptor_address.length, 0);
    }

    /// Channel-binding storage stability.
    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// Move the owner through a box and back, defeating any cached pointer.
        fn shuffle(cb: ChannelBindings) -> ChannelBindings {
            let boxed = Box::new(cb);
            let moved = *boxed;
            let mut v = vec![moved];
            v.pop().unwrap()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// For any nonempty bytes and any number of moves and steps, the
            /// descriptor always addresses the stored bytes.
            #[test]
            fn descriptors_always_address_the_stored_bytes(
                bytes in proptest::collection::vec(any::<u8>(), 1..64),
                moves in 0usize..4,
                steps in 1usize..5,
            ) {
                let mut cb = ChannelBindings::new(&bytes);
                for _ in 0..moves {
                    cb = shuffle(cb);
                    for _ in 0..steps {
                        prop_assert_eq!(observed(&cb.descriptor()), bytes.clone());
                        prop_assert_eq!(cb.application_data(), &bytes[..]);
                    }
                }
                prop_assert_eq!(observed(&cb.descriptor()), bytes);
            }
        }
    }
}
