//! Parsed message metadata and the transition from a packet to a supported query.
//!
//! Fields remain inside `dns` so external callers cannot make the decoded view
//! disagree with the immutable wire bytes retained for forwarding.

use super::{DomainName, ParseError, types::*};

pub(super) const QR_MASK: u16 = 0x8000;
pub(super) const OPCODE_MASK: u16 = 0x7800;
pub(super) const OPCODE_SHIFT: u32 = 11;
pub(super) const TC_MASK: u16 = 0x0200;
pub(super) const RD_MASK: u16 = 0x0100;
pub(super) const RA_MASK: u16 = 0x0080;
pub(super) const RESERVED_MASK: u16 = 0x0040;
pub(super) const CD_MASK: u16 = 0x0010;
pub(super) const RCODE_MASK: u16 = 0x000f;
pub(super) const DO_MASK: u32 = 0x8000;
pub(super) const EDNS_VERSION_SHIFT: u32 = 16;
pub(super) const EXTENDED_RCODE_SHIFT: u32 = 24;

/// Header section counts, retaining wire order without exposing numeric indexes.
#[derive(Debug, Clone, Copy)]
pub(super) struct SectionCounts {
    pub(super) questions: u16,
    pub(super) answers: u16,
    pub(super) authorities: u16,
    pub(super) additionals: u16,
}

/// Resource-record sections; the question section has its own wire layout.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordSection {
    Answer,
    Authority,
    Additional,
}

impl SectionCounts {
    /// Visits record sections in their physical order in a DNS message.
    pub(super) fn record_sections(self) -> [(RecordSection, u16); 3] {
        [
            (RecordSection::Answer, self.answers),
            (RecordSection::Authority, self.authorities),
            (RecordSection::Additional, self.additionals),
        ]
    }
}

/// Decoded fixed header; query/response semantics are checked separately.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Header {
    pub(super) id: TransactionId,
    pub(super) flags: u16,
    pub(super) counts: SectionCounts,
}

impl Header {
    /// Reads only the fixed header, even if the remaining message is malformed.
    ///
    /// # Errors
    /// Returns [`ParseError::UnexpectedEnd`] when the header is incomplete.
    pub(crate) fn parse(wire: &[u8]) -> Result<Self, ParseError> {
        if wire.len() < super::HEADER_LENGTH {
            return Err(ParseError::UnexpectedEnd);
        }
        let word = |i| u16::from_be_bytes([wire[i], wire[i + 1]]);
        Ok(Self {
            id: TransactionId(word(0)),
            flags: word(2),
            counts: SectionCounts {
                questions: word(4),
                answers: word(6),
                authorities: word(8),
                additionals: word(10),
            },
        })
    }
    pub(crate) fn message_type(self) -> MessageType {
        if self.flags & QR_MASK == 0 {
            MessageType::Query
        } else {
            MessageType::Response
        }
    }
    pub(super) fn opcode(self) -> Opcode {
        Opcode::from_wire(((self.flags & OPCODE_MASK) >> OPCODE_SHIFT) as u8)
    }
    pub(super) fn truncated(self) -> bool {
        self.flags & TC_MASK != 0
    }
    pub(super) fn encode(self, wire: &mut Vec<u8>) {
        for word in [
            self.id.0,
            self.flags,
            self.counts.questions,
            self.counts.answers,
            self.counts.authorities,
            self.counts.additionals,
        ] {
            wire.extend_from_slice(&word.to_be_bytes());
        }
    }
}

/// Query identity: case-insensitive name, record type and class all participate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Question {
    pub(super) name: DomainName,
    pub(super) kind: RecordType,
    pub(super) class: RecordClass,
}
impl Question {
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        self.name.encode(out);
        out.extend_from_slice(&self.kind.wire().to_be_bytes());
        out.extend_from_slice(&self.class.wire().to_be_bytes());
    }
}

/// OPT metadata needed for version checks, reply sizing and generated replies.
///
/// Unknown options stay in the packet's original bytes rather than this view.
#[derive(Debug, Clone, Copy)]
pub(super) struct Edns {
    pub(super) udp_size: u16,
    pub(super) version: u8,
    pub(super) extended_rcode: u8,
    pub(super) dnssec_ok: bool,
}

/// Owns immutable original wire bytes and the decoded fields needed by policy.
/// Resource data is validated within the parser; it is never interpreted by routing.
#[derive(Debug)]
pub(crate) struct Packet {
    pub(super) wire: Vec<u8>,
    pub(super) header: Header,
    pub(super) questions: Vec<Question>,
    pub(super) edns: Option<Edns>,
    pub(super) authenticated: bool,
}
impl Packet {
    /// Validates a complete message and retains an owned copy of its original bytes.
    ///
    /// # Errors
    /// Rejects oversized or truncated messages, unsupported question counts,
    /// malformed names/records/OPT data and trailing bytes. Successful parsing
    /// does not imply that query policy or response correlation has passed.
    pub(crate) fn parse(wire: &[u8]) -> Result<Self, ParseError> {
        super::parser::parse(wire)
    }
    pub(crate) fn wire(&self) -> &[u8] {
        &self.wire
    }
    pub(crate) fn is_truncated(&self) -> bool {
        self.header.truncated()
    }
    /// Copies the original message and rewrites only its two-byte transaction ID.
    ///
    /// Re-encoding records could invalidate compression pointers or alter opaque
    /// extensions, so all bytes after the ID remain at their original offsets.
    pub(crate) fn with_id(&self, id: TransactionId) -> Vec<u8> {
        let mut wire = self.wire.clone();
        wire[..2].copy_from_slice(&id.0.to_be_bytes());
        wire
    }
    /// Combines the header's low four bits with an optional EDNS extended code.
    pub(crate) fn response_code(&self) -> ResponseCode {
        let extended = self
            .edns
            .map_or(0, |opt| u16::from(opt.extended_rcode) << 4);
        ResponseCode::from_wire(extended | (self.header.flags & RCODE_MASK))
    }
    /// Applies the classic lower bound and local EDNS ceiling to client capacity.
    pub(super) fn udp_limit(&self) -> usize {
        self.edns.map_or(super::CLASSIC_UDP_LENGTH, |opt| {
            usize::from(opt.udp_size).clamp(super::CLASSIC_UDP_LENGTH, super::SERVER_UDP_LENGTH)
        })
    }
    /// Borrows a supported single-question query without copying its packet.
    ///
    /// # Errors
    /// Returns the DNS rejection code for invalid flags/sections, unsupported
    /// opcodes or EDNS versions, transfers and transaction authentication.
    /// Response packets are also rejected; client-facing callers must discard
    /// them before deciding to generate an error reply to avoid reflection loops.
    pub(crate) fn validate_query(&self) -> Result<Query<'_>, ResponseCode> {
        if self.header.message_type() != MessageType::Query {
            return Err(ResponseCode::FormatError);
        }
        if self.header.opcode() != Opcode::Query {
            return Err(ResponseCode::NotImplemented);
        }
        if self.questions.len() != 1
            || self.header.truncated()
            || self.header.flags & RESERVED_MASK != 0
            || self.response_code() != ResponseCode::NoError
            || self.header.counts.answers != 0
            || self.header.counts.authorities != 0
        {
            return Err(ResponseCode::FormatError);
        }
        if self.edns.is_some_and(|opt| opt.version != 0) {
            return Err(ResponseCode::BadVersion);
        }
        let question = &self.questions[0];
        if self.authenticated
            || matches!(
                question.kind,
                RecordType::Axfr
                    | RecordType::Ixfr
                    | RecordType::Tkey
                    | RecordType::Tsig
                    | RecordType::Opt
            )
        {
            return Err(ResponseCode::Refused);
        }
        Ok(Query {
            packet: self,
            question,
        })
    }
    /// Checks response identity and supported metadata against one upstream attempt.
    ///
    /// The expected ID is the rewritten upstream ID. Source-endpoint filtering
    /// belongs to the connected socket. TC is checked separately by the transport
    /// policy because UDP truncation may authorize a TCP retry.
    pub(crate) fn corresponds_to(&self, query: &Query<'_>, expected: TransactionId) -> bool {
        let query = query.packet;
        self.header.message_type() == MessageType::Response
            && self.header.id == expected
            && self.header.opcode() == query.header.opcode()
            && self.header.flags & RESERVED_MASK == 0
            && self.questions == query.questions
            && self.edns.is_none_or(|opt| opt.version == 0)
            && (query.edns.is_some() || self.edns.is_none())
            && !self.authenticated
    }
}

/// A supported single-question query borrowed from an immutable parsed packet.
/// Only validation can construct this view, so forwarding cannot skip that step.
#[derive(Debug)]
pub(crate) struct Query<'a> {
    packet: &'a Packet,
    question: &'a Question,
}

impl Query<'_> {
    pub(crate) fn name(&self) -> &DomainName {
        &self.question.name
    }

    /// Returns the original client ID to restore after the upstream exchange.
    pub(crate) fn id(&self) -> TransactionId {
        self.packet.header.id
    }

    pub(crate) fn with_id(&self, id: TransactionId) -> Vec<u8> {
        self.packet.with_id(id)
    }

    pub(crate) fn udp_limit(&self) -> usize {
        self.packet.udp_limit()
    }

    pub(crate) fn error_reply(&self, code: ResponseCode) -> Vec<u8> {
        self.packet.error_reply(code)
    }

    pub(crate) fn truncated_reply(&self, code: ResponseCode) -> Vec<u8> {
        self.packet.truncated_reply(code)
    }

    /// Checks whether a TC response's header and question authorize TCP fallback.
    ///
    /// Record data may be incomplete; this never authorizes forwarding that data.
    pub(crate) fn matches_truncated(&self, wire: &[u8], id: TransactionId) -> bool {
        super::parser::matches_truncated(self.packet, wire, id)
    }
}
