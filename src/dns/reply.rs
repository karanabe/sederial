//! Minimal local replies using validated metadata and freshly encoded questions.
//!
//! Forwarded answers retain their original bytes. Only errors and TC replies
//! are built here, with no copied resource records or compression pointers.

use super::{
    Header, Packet, ResponseCode, SERVER_UDP_LENGTH,
    message::{
        CD_MASK, DO_MASK, EXTENDED_RCODE_SHIFT, Edns, OPCODE_MASK, QR_MASK, Question, RA_MASK,
        RD_MASK, SectionCounts, TC_MASK,
    },
    types::{HeaderResponseCode, RecordType},
};

/// OPT presence on a locally generated reply, including the client's DO bit.
///
/// Absence of OPT and an OPT with DO clear are different messages.
enum GeneratedOpt {
    Absent,
    Present {
        dnssec_ok: bool,
        cookie: Option<Vec<u8>>,
    },
}

fn generated_opt(edns: Option<Edns>) -> GeneratedOpt {
    match edns {
        Some(opt) => GeneratedOpt::Present {
            dnssec_ok: opt.dnssec_ok,
            cookie: None,
        },
        None => GeneratedOpt::Absent,
    }
}

/// Only the DNS parser constructs partial context, from checked fields.
#[derive(Debug)]
pub(super) struct ReplyContext {
    pub(super) header: Header,
    pub(super) question: Option<Question>,
    pub(super) edns: Option<Edns>,
}

impl ReplyContext {
    pub(super) fn format_reply(&self) -> Vec<u8> {
        if self.edns.is_none() {
            return self.header.error_reply(HeaderResponseCode::FORMAT_ERROR);
        }
        make_reply(
            self.header,
            self.question.as_ref(),
            ResponseCode::FormatError,
            false,
            generated_opt(self.edns),
        )
    }
}

impl Header {
    /// Builds a header-only error when the rest of the request cannot be trusted.
    ///
    /// [`HeaderResponseCode`] keeps the RCODE inside the four header bits. An
    /// extended code needs an OPT record, which this reply cannot carry.
    pub(crate) fn error_reply(self, code: HeaderResponseCode) -> Vec<u8> {
        make_reply(self, None, code.as_response(), false, GeneratedOpt::Absent)
    }
}

impl Packet {
    /// No local signing secret exists. A client supplying a Server Cookie may
    /// discard a cookie-less reply; never echo that unverified cookie as proof.
    pub(crate) fn local_error_reply(&self, code: ResponseCode) -> Option<Vec<u8>> {
        if super::cookie::response_cookie(self).is_some_and(|cookie| cookie.len() > 8) {
            return None;
        }
        Some(self.error_reply(code))
    }
    /// Builds an error preserving a parsed question and valid OPT presence/DO bit.
    ///
    /// The generated OPT uses EDNS version zero, including when answering BADVERS.
    pub(crate) fn error_reply(&self, code: ResponseCode) -> Vec<u8> {
        make_reply(
            self.header,
            self.questions.first(),
            code,
            false,
            generated_opt(self.edns),
        )
    }
    /// A complete minimal response with TC, never a byte slice cutting an RR in half.
    pub(crate) fn truncated_reply(&self, response: &super::message::Response) -> Vec<u8> {
        let mut opt = generated_opt(self.edns);
        if let GeneratedOpt::Present { cookie, .. } = &mut opt {
            *cookie = super::cookie::response_cookie(&response.0).map(<[u8]>::to_vec);
        }
        make_reply(
            self.header,
            self.questions.first(),
            response.response_code(),
            true,
            opt,
        )
    }
}

/// Encodes a local response. `edns` carries OPT presence and the client's DO bit.
fn make_reply(
    header: Header,
    question: Option<&Question>,
    code: ResponseCode,
    truncated: bool,
    edns: GeneratedOpt,
) -> Vec<u8> {
    // Echo opcode, RD and CD, but clear authoritative/authenticated claims:
    // locally synthesized replies contain no authoritative or validated answer.
    let flags = (header.flags & (OPCODE_MASK | RD_MASK | CD_MASK))
        | QR_MASK
        | RA_MASK
        | (code.wire() & super::message::RCODE_MASK)
        | if truncated { TC_MASK } else { 0 };
    let mut wire = Vec::new();
    Header {
        id: header.id,
        flags,
        counts: SectionCounts {
            questions: u16::from(question.is_some()),
            answers: 0,
            authorities: 0,
            additionals: u16::from(matches!(edns, GeneratedOpt::Present { .. })),
        },
    }
    .encode(&mut wire);
    if let Some(question) = question {
        question.encode(&mut wire);
    }
    if let GeneratedOpt::Present { dnssec_ok, cookie } = edns {
        wire.push(0); // OPT owner is the root name.
        wire.extend_from_slice(&RecordType::Opt.wire().to_be_bytes());
        wire.extend_from_slice(&(SERVER_UDP_LENGTH as u16).to_be_bytes());
        // The extended RCODE is one octet. Wider values cannot be represented.
        let extended = u32::from((code.wire() >> 4) as u8);
        let ttl = (extended << EXTENDED_RCODE_SHIFT) | if dnssec_ok { DO_MASK } else { 0 };
        wire.extend_from_slice(&ttl.to_be_bytes());
        let length = cookie.as_ref().map_or(0, |cookie| 4 + cookie.len());
        wire.extend_from_slice(&(length as u16).to_be_bytes());
        if let Some(cookie) = cookie {
            wire.extend_from_slice(&10_u16.to_be_bytes());
            wire.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
            wire.extend_from_slice(&cookie);
        }
    }
    wire
}
