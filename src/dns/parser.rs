//! Structural validation of untrusted DNS messages without network or policy I/O.
//!
//! Resource records are visited in place and only routing/reply metadata is kept.
//! Known RDATA layouts are checked; unknown types retain their declared byte range.

use super::{
    DomainName, HEADER_LENGTH, MAX_MESSAGE_LENGTH, ParseError,
    message::{
        DO_MASK, EDNS_VERSION_SHIFT, EXTENDED_RCODE_SHIFT, Edns, Header, Packet, Question,
        RecordSection,
    },
    types::{Opcode, RecordClass, RecordType},
};

const QUESTION_FIXED_LENGTH: usize = 4;
const RECORD_FIXED_LENGTH: usize = 10;

/// A TC datagram may end inside an RR. Only use its complete header/question to
/// authorize a TCP retry; none of its answer data is ever trusted or relayed.
pub(super) fn matches_truncated(query: &Packet, wire: &[u8], id: super::TransactionId) -> bool {
    let Ok(header) = Header::parse(wire) else {
        return false;
    };
    if !header.truncated()
        || header.id != id
        || header.message_type() != super::MessageType::Response
        || header.opcode() != query.header.opcode()
        || header.counts.questions != 1
    {
        return false;
    }
    let mut reader = Reader {
        wire,
        cursor: HEADER_LENGTH,
    };
    reader
        .question()
        .is_ok_and(|question| query.questions.as_slice() == [question])
}

/// A checked cursor into one message; compression offsets use the full message.
struct Reader<'a> {
    wire: &'a [u8],
    cursor: usize,
}
impl Reader<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], ParseError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ParseError::UnexpectedEnd)?;
        let bytes = self
            .wire
            .get(self.cursor..end)
            .ok_or(ParseError::UnexpectedEnd)?;
        self.cursor = end;
        Ok(bytes)
    }
    fn word(&mut self) -> Result<u16, ParseError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn double_word(&mut self) -> Result<u32, ParseError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    fn name(&mut self) -> Result<DomainName, ParseError> {
        DomainName::decode(self.wire, &mut self.cursor)
    }

    fn question(&mut self) -> Result<Question, ParseError> {
        Ok(Question {
            name: self.name()?,
            kind: RecordType::from_wire(self.word()?),
            class: RecordClass::from_wire(self.word()?),
        })
    }

    /// Reads a record envelope and bounds its data; type-specific checks follow.
    fn resource_record(&mut self) -> Result<ResourceRecord, ParseError> {
        let owner = self.name()?;
        let kind = RecordType::from_wire(self.word()?);
        let class_wire = self.word()?;
        // OPT stores the UDP payload size in the CLASS slot. Treating that
        // number as RecordClass would make a size of 1 look like IN.
        let class = if kind == RecordType::Opt {
            ClassField::UdpPayload(class_wire)
        } else {
            ClassField::Dns(RecordClass::from_wire(class_wire))
        };
        let ttl = self.double_word()?;
        let data_length = usize::from(self.word()?);
        let data_start = self.cursor;
        Ok(ResourceRecord {
            owner,
            kind,
            class,
            ttl,
            data: data_start..data_start + data_length,
        })
    }
}

/// CLASS on an ordinary record, or the UDP payload size on OPT.
enum ClassField {
    Dns(RecordClass),
    UdpPayload(u16),
}

// Parsed record metadata exists only while validating the protocol boundary.
struct ResourceRecord {
    owner: DomainName,
    kind: RecordType,
    class: ClassField,
    ttl: u32,
    data: std::ops::Range<usize>,
}

/// Checks section bounds and record structure before retaining the original packet.
pub(super) fn parse(wire: &[u8]) -> Result<Packet, super::error::ParseFailure> {
    let mut context = None;
    parse_inner(wire, &mut context).map_err(|error| {
        // Only an OPT processing failure permits these partial metadata to be
        // used. Other structural failures retain the header-only policy.
        if error != ParseError::InvalidEdns
            && let Some(context) = &mut context
        {
            context.question = None;
            context.edns = None;
        }
        super::error::ParseFailure { error, context }
    })
}

fn parse_inner(
    wire: &[u8],
    context: &mut Option<super::reply::ReplyContext>,
) -> Result<Packet, ParseError> {
    if wire.len() > MAX_MESSAGE_LENGTH {
        return Err(ParseError::OversizedMessage);
    }
    let header = Header::parse(wire)?;
    if header.message_type() == super::MessageType::Query {
        *context = Some(super::reply::ReplyContext {
            header,
            question: None,
            edns: None,
        });
    }
    // Reject impossible counts before allocating, even for compressed root names.
    let question_count = usize::from(header.counts.questions);
    // Standard DNS queries have at most one question (RFC 9619). Reject before
    // allocating names: repeated compressed questions could amplify memory use.
    if question_count > 1 && header.opcode() == Opcode::Query {
        return Err(ParseError::InvalidCount);
    }
    let record_count: usize = header
        .counts
        .record_sections()
        .iter()
        .map(|(_, count)| usize::from(*count))
        .sum();
    if question_count * (QUESTION_FIXED_LENGTH + 1) + record_count * (RECORD_FIXED_LENGTH + 1)
        > wire.len() - HEADER_LENGTH
    {
        return Err(ParseError::InvalidCount);
    }
    let mut reader = Reader {
        wire,
        cursor: HEADER_LENGTH,
    };
    let mut questions = Vec::new();
    for _ in 0..question_count {
        questions.push(reader.question()?);
    }
    if let Some(context) = context {
        context.question = questions.first().cloned();
    }
    let mut edns = None;
    let mut cookie = None;
    let mut authenticated = false;
    for (section, count) in header.counts.record_sections() {
        for _ in 0..count {
            let record = reader.resource_record()?;
            if record.kind == RecordType::Opt {
                if section != RecordSection::Additional
                    || edns.is_some()
                    || record.owner.label_count() != 0
                {
                    return Err(ParseError::InvalidEdns);
                }
                let ClassField::UdpPayload(udp_size) = record.class else {
                    return Err(ParseError::InvalidEdns);
                };
                // OPT reuses TTL for extended RCODE, version and flags.
                edns = Some(Edns {
                    udp_size,
                    version: (record.ttl >> EDNS_VERSION_SHIFT) as u8,
                    extended_rcode: (record.ttl >> EXTENDED_RCODE_SHIFT) as u8,
                    dnssec_ok: record.ttl & DO_MASK != 0,
                });
                if let Some(context) = context {
                    context.edns = edns;
                }
                reader
                    .take(record.data.len())
                    .map_err(|_| ParseError::InvalidEdns)?;
                validate_options(&wire[record.data.clone()])?;
                cookie = super::cookie::locate(wire, record.data.start, record.data.len());
            } else {
                reader.take(record.data.len())?;
                validate_data(wire, &record)?;
            }
            authenticated |= matches!(record.kind, RecordType::Tsig | RecordType::Tkey)
                || (section == RecordSection::Additional && record.kind == RecordType::Sig);
        }
    }
    if reader.cursor != wire.len() {
        return Err(ParseError::TrailingData);
    }
    Ok(Packet {
        wire: wire.to_vec(),
        header,
        questions,
        edns,
        authenticated,
        cookie,
    })
}

/// Checks option framing without assigning semantics to unknown EDNS option codes.
fn validate_options(bytes: &[u8]) -> Result<(), ParseError> {
    let mut reader = Reader {
        wire: bytes,
        cursor: 0,
    };
    while reader.cursor < bytes.len() {
        reader.word().map_err(|_| ParseError::InvalidEdns)?; // Unknown option codes are opaque.
        let length = usize::from(reader.word().map_err(|_| ParseError::InvalidEdns)?);
        reader.take(length).map_err(|_| ParseError::InvalidEdns)?;
    }
    Ok(())
}

/// Checks known RDATA layouts and requires their encoded length to match RDLENGTH.
fn validate_data(wire: &[u8], record: &ResourceRecord) -> Result<(), ParseError> {
    // Keep full-message offsets for compressed names inside RDATA. The final
    // cursor check ensures the physical encoding consumes exactly this record.
    let mut reader = Reader {
        wire,
        cursor: record.data.start,
    };
    let ClassField::Dns(class) = record.class else {
        return Err(ParseError::InvalidRecord);
    };
    match record.kind {
        RecordType::A if class == RecordClass::In => {
            reader.take(4)?;
        }
        RecordType::Aaaa if class == RecordClass::In => {
            reader.take(16)?;
        }
        RecordType::Ns | RecordType::Cname | RecordType::Ptr => {
            reader.name()?;
        }
        RecordType::Mx => {
            reader.word()?;
            reader.name()?;
        }
        RecordType::Soa => {
            reader.name()?;
            reader.name()?;
            reader.take(20)?;
        }
        RecordType::Srv => {
            reader.take(6)?;
            reader.name()?;
        }
        RecordType::Txt => {
            if record.data.start == record.data.end {
                return Err(ParseError::InvalidRecord);
            }
            while reader.cursor < record.data.end {
                let length = usize::from(reader.take(1)?[0]);
                reader.take(length)?;
            }
        }
        _ => {
            // Unknown layouts are opaque; the envelope already checked that
            // their declared bytes fit, so interpreting them would add guesses.
            reader.cursor = record.data.end;
        }
    }
    if reader.cursor != record.data.end {
        return Err(ParseError::InvalidRecord);
    }
    Ok(())
}
