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
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    pub(super) wire: Vec<u8>,
    pub(super) header: Header,
    pub(super) questions: Vec<Question>,
    pub(super) edns: Option<Edns>,
    pub(super) authenticated: bool,
    pub(super) cookie: Option<super::cookie::CookieField>,
}
impl Packet {
    /// Validates a complete message and retains an owned copy of its original bytes.
    ///
    /// # Errors
    /// Rejects oversized or truncated messages, unsupported question counts,
    /// malformed names/records/OPT data and trailing bytes. Successful parsing
    /// does not imply that query policy or response correlation has passed.
    pub(crate) fn parse(wire: &[u8]) -> Result<Self, ParseError> {
        Self::parse_for_reply(wire).map_err(|failure| failure.error)
    }
    pub(crate) fn parse_for_reply(wire: &[u8]) -> Result<Self, super::error::ParseFailure> {
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
    /// Classifies a parsed packet as forwardable, rejectable, or silent.
    ///
    /// [`QueryDecision::Ignore`] is a response, or any other input that must not
    /// produce a reply. Replying to it would reflect unsolicited traffic.
    /// [`QueryDecision::Reject`] carries the DNS code for a malformed or
    /// unsupported query. Only [`QueryDecision::Forward`] can reach an upstream.
    pub(crate) fn validate_query(&self) -> QueryDecision<'_> {
        if self.header.message_type() != MessageType::Query {
            return QueryDecision::Ignore;
        }
        if self.header.opcode() != Opcode::Query {
            return QueryDecision::Reject(ResponseCode::NotImplemented);
        }
        if self.questions.len() != 1
            || self.header.truncated()
            || self.response_code() != ResponseCode::NoError
            || self.header.counts.answers != 0
            || self.header.counts.authorities != 0
        {
            return QueryDecision::Reject(ResponseCode::FormatError);
        }
        if matches!(self.cookie, Some(super::cookie::CookieField::Malformed)) {
            return QueryDecision::Reject(ResponseCode::FormatError);
        }
        if self.edns.is_some_and(|opt| opt.version != 0) {
            return QueryDecision::Reject(ResponseCode::BadVersion);
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
            return QueryDecision::Reject(ResponseCode::Refused);
        }
        QueryDecision::Forward(Query {
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
            && self.questions == query.questions
            && self.edns.is_none_or(|opt| opt.version == 0)
            && (query.edns.is_some() || self.edns.is_none())
            && !self.authenticated
    }
}

/// Outcome of [`Packet::validate_query`].
///
/// The variants separate "send this upstream", "answer with this code", and
/// "do not answer". A bare [`ResponseCode`] cannot express the last one.
#[derive(Debug)]
pub(crate) enum QueryDecision<'a> {
    Forward(Query<'a>),
    Reject(ResponseCode),
    Ignore,
}

/// A supported single-question query borrowed from an immutable parsed packet.
/// Only [`QueryDecision::Forward`] constructs this view, so forwarding cannot
/// skip validation.
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

    pub(crate) fn error_reply(&self, code: ResponseCode) -> Option<Vec<u8>> {
        self.packet.local_error_reply(code)
    }

    pub(crate) fn truncated_reply(&self, response: &Response) -> Vec<u8> {
        self.packet.truncated_reply(response)
    }

    pub(crate) fn sent(&self, id: TransactionId) -> SentQuery {
        let mut packet = self.packet.clone();
        packet.header.id = id;
        packet.wire = self.with_id(id);
        SentQuery {
            packet,
            cookie_required: false,
        }
    }
}

/// The exact outgoing bytes and their metadata travel together, including retries.
#[derive(Debug)]
pub(crate) struct SentQuery {
    packet: Packet,
    cookie_required: bool,
}

impl SentQuery {
    pub(crate) fn wire(&self) -> &[u8] {
        self.packet.wire()
    }

    pub(crate) fn matches_truncated(&self, wire: &[u8]) -> bool {
        super::parser::matches_truncated(&self.packet, wire, self.packet.header.id)
    }

    pub(crate) fn validate_response(&self, response: Packet) -> Option<Response> {
        let QueryDecision::Forward(query) = self.packet.validate_query() else {
            return None;
        };
        if response.is_truncated()
            || !response.corresponds_to(&query, self.packet.header.id)
            || !super::cookie::valid_response(&self.packet, &response, self.cookie_required)
        {
            return None;
        }
        Some(Response(response))
    }

    pub(crate) fn server_cookie_retry(
        &self,
        response: &Response,
    ) -> super::cookie::ServerCookieRetry {
        super::cookie::retry(&self.packet, &response.0)
    }

    /// A retry requires COOKIE after this endpoint has demonstrated support.
    /// Reparse modified bytes here; old offsets cannot accompany the new wire.
    pub(crate) fn retry(&self, mut wire: Vec<u8>, id: TransactionId) -> Result<Self, ParseError> {
        wire[..2].copy_from_slice(&id.0.to_be_bytes());
        let packet = Packet::parse(&wire)?;
        Ok(Self {
            packet,
            cookie_required: true,
        })
    }
}

/// A complete response correlated to the actual outgoing query, including COOKIE.
#[derive(Debug)]
pub(crate) struct Response(pub(super) Packet);
impl Response {
    pub(crate) fn wire(&self) -> &[u8] {
        self.0.wire()
    }
    pub(crate) fn response_code(&self) -> ResponseCode {
        self.0.response_code()
    }
    pub(crate) fn with_id(&self, id: TransactionId) -> Vec<u8> {
        self.0.with_id(id)
    }
}
