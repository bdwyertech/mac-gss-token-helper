//! Bounded multi-leg protocol parsing and framing.
//!
//! This is *this helper's own* stdin/stdout line protocol between the parent
//! process and the helper. It is unrelated to SPNEGO, GSS, or Kerberos
//! versioning: the token bytes carried inside a record are opaque here.
//!
//! There is exactly one wire format and no version negotiation. Every step is
//! framed as a `CONTINUE` / `COMPLETE` record so an empty token is
//! unambiguous.
//!
//! This module is deliberately free of GSS and global stdin/stdout
//! dependencies so every record decision is a pure, testable function.
//! Errors are the caller's to report on stderr; stdout carries data records
//! only.
//!
//! The parent process remains responsible for a wall-clock timeout: network
//! and KDC blocking happens inside GSS and cannot be safely interrupted by
//! any input limit enforced here.

use std::fmt;

/// Maximum bytes accepted in one encoded input line, excluding the newline.
///
/// Bounds allocation before decoding; an oversized line is rejected rather
/// than buffered without limit.
pub const MAX_ENCODED_LINE: usize = 64 * 1024;

/// Maximum bytes accepted in one decoded token.
pub const MAX_DECODED_TOKEN: usize = 48 * 1024;

/// Maximum negotiation legs before the exchange is abandoned.
pub const MAX_LEGS: usize = 16;

/// An outbound record describing one accepted negotiation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// Another peer exchange is required. The token may be empty.
    Continue(Vec<u8>),
    /// The negotiation finished. The final token may be empty.
    Complete(Vec<u8>),
}

impl Record {
    /// The token this record carries.
    pub fn token(&self) -> &[u8] {
        match self {
            Self::Continue(t) | Self::Complete(t) => t,
        }
    }

    /// Does this record end the exchange?
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Complete(_))
    }
}

/// A bounded read failure: either the transport failed or the protocol limit
/// was exceeded.
#[derive(Debug)]
pub enum BoundedReadError {
    /// The underlying reader failed.
    Io(std::io::Error),
    /// The input violated a protocol limit.
    Protocol(ProtocolError),
}

impl fmt::Display for BoundedReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Protocol(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BoundedReadError {}

/// A protocol-level failure. Always reported on stderr, never on stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// An input line exceeded [`MAX_ENCODED_LINE`] bytes.
    LineTooLong { limit: usize },
    /// A decoded token exceeded [`MAX_DECODED_TOKEN`] bytes.
    TokenTooLong { limit: usize },
    /// The exchange used more than [`MAX_LEGS`] legs.
    TooManyLegs { limit: usize },
    /// An input line was not valid base64.
    MalformedBase64,
    /// An input line did not begin with `CONTINUE` or `COMPLETE`.
    UnknownKeyword,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLong { limit } => {
                write!(f, "input line exceeds the {limit}-byte limit")
            }
            Self::TokenTooLong { limit } => {
                write!(f, "decoded token exceeds the {limit}-byte limit")
            }
            Self::TooManyLegs { limit } => {
                write!(f, "negotiation exceeded the {limit}-leg limit")
            }
            Self::MalformedBase64 => write!(f, "input line is not valid base64"),
            Self::UnknownKeyword => {
                write!(f, "input line must begin with CONTINUE or COMPLETE")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Encode a record as a protocol line, without the trailing newline.
///
/// A record with a token becomes `KEYWORD <base64>`; a record without one
/// becomes the bare keyword, so an empty-token continuation is unambiguous.
pub fn encode(record: &Record) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let keyword = if record.is_final() {
        "COMPLETE"
    } else {
        "CONTINUE"
    };
    let token = record.token();
    if token.is_empty() {
        keyword.to_string()
    } else {
        format!("{keyword} {}", STANDARD.encode(token))
    }
}

/// Decode a protocol line back into a record.
///
/// Total: every input yields a record or a `ProtocolError`, never a panic.
pub fn decode(line: &str) -> Result<Record, ProtocolError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    if line.len() > MAX_ENCODED_LINE {
        return Err(ProtocolError::LineTooLong {
            limit: MAX_ENCODED_LINE,
        });
    }
    let (keyword, rest) = match line.split_once(' ') {
        Some((k, r)) => (k, Some(r)),
        None => (line, None),
    };
    let token = match rest {
        None => Vec::new(),
        Some(encoded) => {
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| ProtocolError::MalformedBase64)?;
            if bytes.len() > MAX_DECODED_TOKEN {
                return Err(ProtocolError::TokenTooLong {
                    limit: MAX_DECODED_TOKEN,
                });
            }
            bytes
        }
    };
    match keyword {
        "CONTINUE" => Ok(Record::Continue(token)),
        "COMPLETE" => Ok(Record::Complete(token)),
        _ => Err(ProtocolError::UnknownKeyword),
    }
}

/// Read one newline-terminated line with a hard byte bound.
///
/// Unlike `BufRead::lines`, this never grows the buffer past the limit: the
/// oversized line is rejected before allocating without bound. Returns
/// `Ok(None)` at end of input.
pub fn read_bounded_line<R: std::io::BufRead>(
    reader: &mut R,
    limit: usize,
    buf: &mut Vec<u8>,
) -> Result<Option<()>, BoundedReadError> {
    buf.clear();
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => return Ok(if buf.is_empty() { None } else { Some(()) }),
            Ok(_) => {
                if byte[0] == b'\n' {
                    if buf.last() == Some(&b'\r') {
                        buf.pop();
                    }
                    return Ok(Some(()));
                }
                if buf.len() == limit {
                    return Err(BoundedReadError::Protocol(ProtocolError::LineTooLong {
                        limit,
                    }));
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err(BoundedReadError::Io(e)),
        }
    }
}

/// Record framing and decoding behavior.
#[cfg(test)]
mod record_tests {
    use super::*;

    #[test]
    fn continuation_with_a_token_carries_it_base64_encoded() {
        let line = encode(&Record::Continue(b"leg".to_vec()));
        assert_eq!(line, "CONTINUE bGVn");
        assert_eq!(decode(&line), Ok(Record::Continue(b"leg".to_vec())));
    }

    #[test]
    fn empty_token_continuation_is_a_bare_keyword_on_every_leg() {
        let line = encode(&Record::Continue(Vec::new()));
        assert_eq!(line, "CONTINUE");
        // The encoding is leg-independent, so leg 1 and leg N agree.
        assert_eq!(decode(&line), Ok(Record::Continue(Vec::new())));
    }

    #[test]
    fn completion_is_one_record_with_or_without_a_final_token() {
        let with = encode(&Record::Complete(b"fin".to_vec()));
        let without = encode(&Record::Complete(Vec::new()));
        assert_eq!(with, "COMPLETE Zmlu");
        assert_eq!(without, "COMPLETE");
        assert!(decode(&with).unwrap().is_final());
        assert!(decode(&without).unwrap().is_final());
    }

    #[test]
    fn unknown_keywords_and_bad_base64_are_distinct_errors() {
        assert_eq!(decode("OK"), Err(ProtocolError::UnknownKeyword));
        assert_eq!(decode("CONTINUE !!!"), Err(ProtocolError::MalformedBase64));
    }

    /// Protocol framing round trip.
    #[cfg(test)]
    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn decoding_an_encoded_record_recovers_it(
                bytes in prop::collection::vec(any::<u8>(), 0..1024),
                final_leg in any::<bool>(),
            ) {
                let record = if final_leg {
                    Record::Complete(bytes)
                } else {
                    Record::Continue(bytes)
                };
                let line = encode(&record);
                prop_assert!(!line.contains('\n'));
                prop_assert_eq!(decode(&line), Ok(record));
            }
        }
    }
}

/// Bounded-input behavior.
#[cfg(test)]
mod bounds_tests {
    use super::*;
    use std::io::BufReader;

    fn read(input: &str, limit: usize) -> Result<Option<String>, BoundedReadError> {
        let mut reader = BufReader::new(input.as_bytes());
        let mut buf = Vec::new();
        read_bounded_line(&mut reader, limit, &mut buf)
            .map(|got| got.map(|()| String::from_utf8_lossy(&buf).into_owned()))
    }

    #[test]
    fn a_line_at_the_limit_is_accepted_and_newlines_are_stripped() {
        assert_eq!(read("abcd\n", 4).unwrap(), Some("abcd".to_string()));
        // CR is buffered before being stripped, so it counts toward the limit.
        assert_eq!(read("abcd\r\n", 5).unwrap(), Some("abcd".to_string()));
        assert_eq!(read("", 4).unwrap(), None);
    }

    #[test]
    fn an_oversized_line_is_rejected_before_unbounded_buffering() {
        match read("abcde\n", 4).unwrap_err() {
            BoundedReadError::Protocol(e) => {
                assert_eq!(e, ProtocolError::LineTooLong { limit: 4 });
            }
            other => panic!("expected a protocol limit error, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_token_is_rejected_by_a_configured_bound() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let big = STANDARD.encode(vec![0u8; MAX_DECODED_TOKEN + 1]);
        let err = decode(&format!("CONTINUE {big}")).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::LineTooLong { .. } | ProtocolError::TokenTooLong { .. }
            ),
            "unexpected error {err:?}"
        );
    }

    /// Protocol resource bounds.
    #[cfg(test)]
    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn reads_never_buffer_past_the_limit(
                len in 0usize..64,
                limit in 1usize..32,
            ) {
                let input = format!("{}\n", "a".repeat(len));
                let mut reader = std::io::BufReader::new(input.as_bytes());
                let mut buf = Vec::new();
                let got = read_bounded_line(&mut reader, limit, &mut buf);
                prop_assert!(buf.len() <= limit);
                prop_assert_eq!(got.is_err(), len > limit);
            }
        }
    }
}
