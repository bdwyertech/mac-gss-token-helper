//! CLI orchestration with explicit I/O error propagation.
//!
//! Every function here returns [`AppError`] instead of printing and exiting,
//! so the top-level `main` is the only place that reports an error and picks
//! an exit status. All input and output is injected, which lets tests drive
//! orchestration with in-memory and deliberately failing streams.

use crate::gss;
use crate::protocol;
use std::fmt;
use std::io;

/// A fatal condition that ends the process.
#[derive(Debug)]
pub enum AppError {
    /// Writing to or reading from a process stream failed.
    Io(io::Error),
    /// A peer record was malformed or breached a bound.
    Protocol(protocol::ProtocolError),
    /// A GSS call or an illegal context transition failed.
    Context(String, gss::ContextError),
    /// GSS produced no token where one was required.
    EmptyToken,
    /// Negotiation ended before the context completed.
    Incomplete { legs: usize },
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "i/o error: {e}"),
            AppError::Protocol(e) => write!(f, "{e}"),
            AppError::Context(ctx, e) => write!(f, "{ctx}: {e}"),
            AppError::EmptyToken => write!(f, "GSS returned an empty token"),
            AppError::Incomplete { legs } => {
                write!(f, "negotiation ended before completion (limit {legs} legs)")
            }
        }
    }
}

impl std::error::Error for AppError {}

impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<protocol::ProtocolError> for AppError {
    fn from(e: protocol::ProtocolError) -> Self {
        AppError::Protocol(e)
    }
}

impl From<protocol::BoundedReadError> for AppError {
    fn from(e: protocol::BoundedReadError) -> Self {
        match e {
            protocol::BoundedReadError::Io(e) => AppError::Io(e),
            protocol::BoundedReadError::Protocol(e) => AppError::Protocol(e),
        }
    }
}

/// Writes the base64 single-shot token with no trailing newline.
pub fn write_single_shot<W: io::Write>(out: &mut W, token: &[u8]) -> Result<(), AppError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    if token.is_empty() {
        return Err(AppError::EmptyToken);
    }
    out.write_all(STANDARD.encode(token).as_bytes())?;
    out.flush()?;
    Ok(())
}

/// Writes one framed record and flushes, surfacing every I/O failure.
pub fn write_record<W: io::Write>(out: &mut W, record: &protocol::Record) -> Result<(), AppError> {
    let line = protocol::encode(record);
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Output-error propagation.
#[cfg(test)]
mod output_tests {
    use super::*;

    /// Fails on the nth write, mimicking a closed downstream pipe.
    struct FailingWriter {
        writes_before_failure: usize,
    }

    impl io::Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.writes_before_failure == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
            }
            self.writes_before_failure -= 1;
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.writes_before_failure == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
            }
            Ok(())
        }
    }

    fn broken_pipe(e: AppError) -> io::ErrorKind {
        match e {
            AppError::Io(e) => e.kind(),
            other => panic!("expected an i/o error, got {other:?}"),
        }
    }

    #[test]
    fn a_failing_writer_makes_single_shot_output_an_error() {
        let mut out = FailingWriter {
            writes_before_failure: 0,
        };
        let err = write_single_shot(&mut out, b"tok").unwrap_err();
        assert_eq!(broken_pipe(err), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn a_failing_flush_after_a_record_is_still_an_error() {
        let record = protocol::Record::Continue(b"leg".to_vec());
        // Both body writes succeed; only the flush fails.
        let mut out = FailingWriter {
            writes_before_failure: 2,
        };
        let err = write_record(&mut out, &record).unwrap_err();
        assert_eq!(broken_pipe(err), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn successful_writes_produce_exact_bytes() {
        let mut single = Vec::new();
        write_single_shot(&mut single, b"tok").unwrap();
        assert_eq!(single, b"dG9r");

        let mut framed = Vec::new();
        write_record(&mut framed, &protocol::Record::Complete(Vec::new())).unwrap();
        assert_eq!(framed, b"COMPLETE\n");
    }

    #[test]
    fn an_empty_token_is_rejected_before_any_output() {
        let mut out = Vec::new();
        assert!(matches!(
            write_single_shot(&mut out, b"").unwrap_err(),
            AppError::EmptyToken
        ));
        assert!(out.is_empty());
    }
}
