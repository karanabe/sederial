//! Bounded DNS label decoding, presentation and case-insensitive suffix matching.
//!
//! Wire labels may contain arbitrary octets. Configuration names intentionally
//! use a narrower ASCII syntax, while equality preserves DNS label boundaries.

use super::ParseError;
use std::{fmt, str::FromStr};

const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 255;
const POINTER_TAG: u8 = 0xc0;
const LABEL_TAG_MASK: u8 = 0xc0;
const POINTER_OFFSET_MASK: u8 = 0x3f;
const MAX_POINTERS: usize = 128;

/// Absolute DNS name, preserving label octets; equality is ASCII case-insensitive.
#[derive(Debug, Clone)]
pub(crate) struct DomainName(Vec<Vec<u8>>);

impl PartialEq for DomainName {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && self.is_subdomain_of(other)
    }
}
impl Eq for DomainName {}

impl DomainName {
    /// Counts labels excluding the terminating root, which itself has zero labels.
    pub(crate) fn label_count(&self) -> usize {
        self.0.len()
    }

    /// Tests equality or descent by complete labels, ignoring ASCII case.
    ///
    /// Every name matches the root suffix; textual suffixes within a label do not
    /// match (`notexample.test` is not below `example.test`).
    pub(crate) fn is_subdomain_of(&self, suffix: &Self) -> bool {
        self.0.len() >= suffix.0.len()
            && self
                .0
                .iter()
                .rev()
                .zip(suffix.0.iter().rev())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Decodes a name from the full DNS message starting at `cursor`.
    ///
    /// On success, `cursor` points just after this encoded name, including its
    /// first compression pointer when present, not after the pointer's target.
    /// The cursor must be discarded on error; decoding is not transactional.
    ///
    /// # Errors
    /// Rejects invalid labels, missing bytes, names over the expanded length
    /// limit, disallowed pointers, compression cycles and excessive pointer hops.
    pub(super) fn decode(wire: &[u8], cursor: &mut usize) -> Result<Self, ParseError> {
        let mut labels = Vec::new();
        let mut position = *cursor;
        let mut jumped = false;
        let mut expanded = 1;
        let mut visited = [usize::MAX; MAX_POINTERS];
        let mut hops = 0;
        loop {
            let head = *wire.get(position).ok_or(ParseError::UnexpectedEnd)?;
            match head & LABEL_TAG_MASK {
                POINTER_TAG => {
                    let tail = *wire.get(position + 1).ok_or(ParseError::UnexpectedEnd)?;
                    let target =
                        usize::from(u16::from_be_bytes([head & POINTER_OFFSET_MASK, tail]));
                    if visited[..hops].contains(&target) {
                        return Err(ParseError::CompressionLoop);
                    }
                    // RFC 1035 compression points to a prior occurrence, never the header.
                    if target < super::HEADER_LENGTH || target >= position {
                        return Err(ParseError::InvalidPointer);
                    }
                    if hops == MAX_POINTERS {
                        return Err(ParseError::CompressionDepth);
                    }
                    visited[hops] = target;
                    hops += 1;
                    if !jumped {
                        // The first pointer terminates the name at the original
                        // location. Further decoding must not advance that cursor.
                        *cursor = position + 2;
                        jumped = true;
                    }
                    position = target;
                }
                0 => {
                    position += 1;
                    if head == 0 {
                        if !jumped {
                            *cursor = position;
                        }
                        return Ok(Self(labels));
                    }
                    let length = usize::from(head);
                    // Count expanded labels plus the root terminator, even when
                    // compression makes the physical representation much shorter.
                    expanded += length + 1;
                    if expanded > MAX_NAME_LENGTH {
                        return Err(ParseError::NameTooLong);
                    }
                    let label = wire
                        .get(position..position + length)
                        .ok_or(ParseError::UnexpectedEnd)?;
                    labels.push(label.to_vec());
                    position += length;
                }
                _ => return Err(ParseError::InvalidLabel),
            }
        }
    }

    /// Appends an uncompressed absolute name for locally generated replies.
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        for label in &self.0 {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
    }
}

impl FromStr for DomainName {
    type Err = ParseError;
    /// Parses an ASCII configuration name with an optional final dot, or `.`.
    ///
    /// Wildcards, empty labels and presentation escapes are not accepted; this
    /// is intentionally narrower than the binary names supported by decoding.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "." {
            return Ok(Self(Vec::new()));
        }
        let text = text.strip_suffix('.').unwrap_or(text);
        let mut labels = Vec::new();
        let mut length = 1;
        for label in text.split('.') {
            // Configuration uses ASCII presentation names, including service labels.
            if label.is_empty()
                || label.len() > MAX_LABEL_LENGTH
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(ParseError::InvalidLabel);
            }
            length += label.len() + 1;
            if length > MAX_NAME_LENGTH {
                return Err(ParseError::NameTooLong);
            }
            labels.push(label.as_bytes().to_vec());
        }
        Ok(Self(labels))
    }
}

impl fmt::Display for DomainName {
    /// Writes an absolute presentation name, escaping non-label text as decimals.
    ///
    /// Binary wire names need not round-trip through the configuration parser.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str(".");
        }
        for label in &self.0 {
            for byte in label {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
                    write!(f, "{}", char::from(*byte))?;
                } else {
                    write!(f, "\\{byte:03}")?;
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}
