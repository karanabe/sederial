//! Structural protocol errors, kept separate from DNS rejection response codes.

use std::{error::Error, fmt};

/// Failure to decode a bounded message or configuration name.
///
/// Display messages describe the failure category without including packet bytes
/// or question names, so callers can log them without exposing client queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseError {
    UnexpectedEnd,
    OversizedMessage,
    InvalidLabel,
    NameTooLong,
    InvalidPointer,
    CompressionLoop,
    CompressionDepth,
    /// Counts cannot fit the message, or exceed the supported question count.
    InvalidCount,
    InvalidRecord,
    InvalidEdns,
    TrailingData,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnexpectedEnd => "truncated DNS field",
            Self::OversizedMessage => "DNS message exceeds 65535 bytes",
            Self::InvalidLabel => "invalid DNS label encoding",
            Self::NameTooLong => "DNS name exceeds 255 wire bytes",
            Self::InvalidPointer => "invalid DNS compression pointer",
            Self::CompressionLoop => "DNS compression pointer cycle",
            Self::CompressionDepth => "DNS compression chain exceeds 128 pointers",
            Self::InvalidCount => "DNS section count cannot fit in message",
            Self::InvalidRecord => "invalid DNS resource record data",
            Self::InvalidEdns => "invalid, misplaced or duplicate OPT record",
            Self::TrailingData => "trailing bytes after DNS sections",
        })
    }
}

impl Error for ParseError {}
