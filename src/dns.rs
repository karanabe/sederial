//! Pure protocol boundary. Opaque record data and original wire bytes stay here.
//!
//! [`Packet::parse`] checks structural validity; [`Packet::validate_query`]
//! produces [`QueryDecision`]. Only [`QueryDecision::Forward`] may be relayed.
//! [`QueryDecision::Ignore`] must not be answered. Parsing a packet alone does
//! not establish that it is a query or a correlated response.
//! Original bytes preserve compression offsets and unknown record data when
//! packets cross the forwarding boundary.
mod cookie;
mod error;
mod message;
mod name;
mod parser;
mod reply;
mod types;

pub(crate) use cookie::ServerCookieRetry;
pub(crate) use error::ParseError;
pub(crate) use message::{Header, Packet, Query, QueryDecision, Response, SentQuery};
pub(crate) use name::DomainName;
pub(crate) use types::{MessageType, ResponseCode, TransactionId};

/// Fixed DNS header size, excluding a TCP frame's two-byte length prefix.
pub(crate) const HEADER_LENGTH: usize = 12;
/// Maximum DNS message length representable by the TCP frame prefix.
pub(crate) const MAX_MESSAGE_LENGTH: usize = u16::MAX as usize;
/// Client UDP response limit when no EDNS OPT record is present.
pub(crate) const CLASSIC_UDP_LENGTH: usize = 512;
// Conservative EDNS size to avoid fragmentation on typical IPv6 paths.
pub(crate) const SERVER_UDP_LENGTH: usize = 1232;

#[cfg(test)]
mod tests;
