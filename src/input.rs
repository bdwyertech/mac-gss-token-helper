//! Validated caller inputs.
//!
//! Both the channel-binding hash and the service principal name arrive as
//! untrusted CLI strings. Parsing them into dedicated types here keeps the
//! failure modes total (no panics) and prevents malformed values from ever
//! reaching the GSS FFI layer.

use std::fmt;

// ---------------------------------------------------------------------------
// Channel bindings
// ---------------------------------------------------------------------------

/// Why a channel-binding hex string was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// The value had an odd number of hex digits, so a byte pair is incomplete.
    OddLength { digits: usize },
    /// A byte that is not an ASCII hex digit appeared at `index`.
    InvalidDigit { index: usize, byte: u8 },
    /// The value contained no digits at all.
    Empty,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength { digits } => write!(
                f,
                "hex value must have an even number of digits, found {digits}"
            ),
            Self::InvalidDigit { index, byte } => write!(
                f,
                "invalid hex digit {:?} at byte offset {index}",
                *byte as char
            ),
            Self::Empty => write!(f, "hex value is empty"),
        }
    }
}

impl std::error::Error for HexError {}

/// Decodes one ASCII hex digit, accepting either case.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parses a hex string into bytes, tolerating an optional `0x` / `0X` prefix.
///
/// Operates on raw ASCII bytes, so multi-byte UTF-8 input is rejected with an
/// `InvalidDigit` error rather than panicking on a char-boundary slice.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, HexError> {
    let bytes = s.as_bytes();
    let (digits, offset) = match bytes {
        [b'0', b'x' | b'X', rest @ ..] => (rest, 2),
        _ => (bytes, 0),
    };

    if digits.is_empty() {
        return Err(HexError::Empty);
    }
    if digits.len() % 2 != 0 {
        return Err(HexError::OddLength {
            digits: digits.len(),
        });
    }

    let mut out = Vec::with_capacity(digits.len() / 2);
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        let hi = hex_digit(pair[0]).ok_or(HexError::InvalidDigit {
            index: offset + i * 2,
            byte: pair[0],
        })?;
        let lo = hex_digit(pair[1]).ok_or(HexError::InvalidDigit {
            index: offset + i * 2 + 1,
            byte: pair[1],
        })?;
        out.push((hi << 4) | lo);
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Service principal name
// ---------------------------------------------------------------------------

/// Why an SPN was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpnError {
    /// No `service/host` or `service@host` separator was present.
    MissingSeparator,
    /// More than one separator was present, so the structure is ambiguous.
    TooManySeparators,
    /// The service component was empty.
    EmptyService,
    /// The host component was empty.
    EmptyHost,
    /// A component contained a character GSS host-based names disallow.
    InvalidCharacter { component: &'static str, ch: char },
}

impl fmt::Display for SpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator => {
                write!(f, "expected 'service/host' or 'service@host'")
            }
            Self::TooManySeparators => {
                write!(f, "expected exactly one '/' or '@' separator")
            }
            Self::EmptyService => write!(f, "service component is empty"),
            Self::EmptyHost => write!(f, "host component is empty"),
            Self::InvalidCharacter { component, ch } => {
                write!(f, "invalid character {ch:?} in {component}")
            }
        }
    }
}

impl std::error::Error for SpnError {}

/// A structurally valid, canonical host-based service name.
///
/// Both `HTTP/host` and `HTTP@host` normalize to the single canonical
/// `service@host` form that `GSS_C_NT_HOSTBASED_SERVICE` expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePrincipalName {
    service: String,
    host: String,
    canonical: String,
}

impl ServicePrincipalName {
    /// Parses `service/host` or `service@host` into canonical form.
    pub fn parse(raw: &str) -> Result<Self, SpnError> {
        let seps = raw.chars().filter(|c| *c == '/' || *c == '@').count();
        match seps {
            0 => return Err(SpnError::MissingSeparator),
            1 => {}
            _ => return Err(SpnError::TooManySeparators),
        }

        let (service, host) = raw
            .split_once(['/', '@'])
            .ok_or(SpnError::MissingSeparator)?;

        if service.is_empty() {
            return Err(SpnError::EmptyService);
        }
        if host.is_empty() {
            return Err(SpnError::EmptyHost);
        }

        validate_component("service", service)?;
        validate_component("host", host)?;

        // GSS host-based names are case-insensitive; lowercase the host so
        // equivalent inputs produce one canonical, idempotent form.
        let host = host.to_ascii_lowercase();
        let canonical = format!("{service}@{host}");

        Ok(Self {
            service: service.to_owned(),
            host,
            canonical,
        })
    }

    /// The canonical `service@host` form to hand to `gss_import_name`.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The service component, preserved as supplied.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The lowercased host component.
    pub fn host(&self) -> &str {
        &self.host
    }
}

impl fmt::Display for ServicePrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

/// Rejects characters that cannot appear in a host-based service name.
fn validate_component(component: &'static str, value: &str) -> Result<(), SpnError> {
    for ch in value.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':');
        if !ok {
            return Err(SpnError::InvalidCharacter { component, ch });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ascii_hex_is_rejected_without_panicking() {
        // Multi-byte chars used to be sliced on a non-char boundary.
        // "éé" is four bytes, so it reaches the digit check rather than the
        // length check — exercising the byte-pair path directly.
        let err = decode_hex("éé").unwrap_err();
        assert!(matches!(err, HexError::InvalidDigit { .. }), "{err:?}");
        assert!(decode_hex("é0").is_err());
        assert!(decode_hex("00é0").is_err());
        assert!(decode_hex("ß").is_err());
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert_eq!(decode_hex(""), Err(HexError::Empty));
        assert_eq!(decode_hex("0x"), Err(HexError::Empty));
        assert_eq!(decode_hex("abc"), Err(HexError::OddLength { digits: 3 }));
        assert!(matches!(
            decode_hex("0g"),
            Err(HexError::InvalidDigit { index: 1, .. })
        ));
        assert!(matches!(
            decode_hex("0x0g"),
            Err(HexError::InvalidDigit { index: 3, .. })
        ));
    }

    #[test]
    fn well_formed_hex_decodes_in_any_case() {
        assert_eq!(decode_hex("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(decode_hex("00FF").unwrap(), vec![0x00, 0xff]);
        assert_eq!(decode_hex("0xDeAd").unwrap(), vec![0xde, 0xad]);
        assert_eq!(decode_hex("0XBEEF").unwrap(), vec![0xbe, 0xef]);
    }

    #[test]
    fn malformed_spns_are_rejected() {
        assert_eq!(
            ServicePrincipalName::parse("HTTP"),
            Err(SpnError::MissingSeparator)
        );
        assert_eq!(
            ServicePrincipalName::parse("HTTP/a/b"),
            Err(SpnError::TooManySeparators)
        );
        assert_eq!(
            ServicePrincipalName::parse("/host"),
            Err(SpnError::EmptyService)
        );
        assert_eq!(
            ServicePrincipalName::parse("HTTP@"),
            Err(SpnError::EmptyHost)
        );
        assert!(matches!(
            ServicePrincipalName::parse("HTTP/hö.st"),
            Err(SpnError::InvalidCharacter { .. })
        ));
    }

    #[test]
    fn both_separator_forms_normalize_identically() {
        let slash = ServicePrincipalName::parse("HTTP/Web.Example.COM").unwrap();
        let at = ServicePrincipalName::parse("HTTP@web.example.com").unwrap();
        assert_eq!(slash.as_str(), "HTTP@web.example.com");
        assert_eq!(slash, at);
        assert_eq!(slash.service(), "HTTP");
        assert_eq!(slash.host(), "web.example.com");
    }
}

// ---------------------------------------------------------------------------
// Hex parser totality and round trip; SPN normalization and idempotence
// ---------------------------------------------------------------------------

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    /// Encodes bytes as hex in the requested case, optionally prefixed.
    fn encode(bytes: &[u8], mode: u8, prefix: bool) -> String {
        let mut s = if prefix {
            "0x".to_owned()
        } else {
            String::new()
        };
        for (i, b) in bytes.iter().enumerate() {
            let upper = match mode {
                0 => false,
                1 => true,
                _ => i % 2 == 0,
            };
            if upper {
                s.push_str(&format!("{b:02X}"));
            } else {
                s.push_str(&format!("{b:02x}"));
            }
        }
        s
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// The parser never panics on arbitrary input.
        #[test]
        fn hex_parser_is_total(s in ".{0,64}") {
            let _ = decode_hex(&s);
        }

        /// Any encoding of a non-empty byte string round trips, in any case
        /// and with or without the `0x` prefix.
        #[test]
        fn hex_round_trips_in_any_case(
            bytes in prop::collection::vec(any::<u8>(), 1..24),
            mode in 0u8..3,
            prefix in any::<bool>(),
        ) {
            let encoded = encode(&bytes, mode, prefix);
            prop_assert_eq!(decode_hex(&encoded).unwrap(), bytes);
        }

        /// The SPN parser never panics on arbitrary input.
        #[test]
        fn spn_parser_is_total(s in ".{0,64}") {
            let _ = ServicePrincipalName::parse(&s);
        }

        /// Accepted SPNs are canonical, and re-parsing is a no-op.
        #[test]
        fn spn_normalization_is_valid_and_idempotent(
            service in "[A-Za-z][A-Za-z0-9]{0,8}",
            host in "[a-zA-Z0-9][a-zA-Z0-9.-]{0,20}",
            at in any::<bool>(),
        ) {
            let sep = if at { '@' } else { '/' };
            let raw = format!("{service}{sep}{host}");

            let spn = ServicePrincipalName::parse(&raw)
                .expect("well-formed SPN must parse");

            // Valid: exactly one '@', lowercase host, no separator leakage.
            prop_assert_eq!(spn.as_str().matches('@').count(), 1);
            prop_assert!(!spn.as_str().contains('/'));
            prop_assert_eq!(spn.host(), host.to_ascii_lowercase());

            // Idempotent: re-parsing the canonical form is a fixed point.
            let again = ServicePrincipalName::parse(spn.as_str())
                .expect("canonical form must re-parse");
            prop_assert_eq!(&again, &spn);
            prop_assert_eq!(again.as_str(), spn.as_str());
        }
    }
}
