use super::types::{HeaderResponseCode, Opcode, RecordClass, RecordType};
use super::*;

fn forward(packet: &Packet) -> bool {
    matches!(packet.validate_query(), QueryDecision::Forward(_))
}

fn forwarded_name(packet: &Packet) -> DomainName {
    match packet.validate_query() {
        QueryDecision::Forward(query) => query.name().clone(),
        other => panic!("expected a forwardable query, got {other:?}"),
    }
}

fn rejected(packet: &Packet) -> ResponseCode {
    match packet.validate_query() {
        QueryDecision::Reject(code) => code,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

// Independent wire vector: ID 0x1234, RD, one A/IN question for www.example.com.
const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01";

#[test]
fn header_and_question_vector() {
    let packet = Packet::parse(QUERY).unwrap();
    assert_eq!(packet.header.id, TransactionId(0x1234));
    assert_eq!(packet.header.message_type(), MessageType::Query);
    assert_eq!(packet.header.opcode(), Opcode::Query);
    assert!(!packet.header.truncated());
    assert_eq!(forwarded_name(&packet), "WWW.EXAMPLE.COM.".parse().unwrap());
    assert_eq!(packet.questions[0].kind, RecordType::A);
    assert_eq!(packet.questions[0].class, RecordClass::In);
    assert_eq!(packet.wire(), QUERY);
}

#[test]
fn responses_cannot_be_used_as_validated_queries() {
    let mut response = QUERY.to_vec();
    response[2] |= 0x80;
    let packet = Packet::parse(&response).unwrap();
    assert!(matches!(packet.validate_query(), QueryDecision::Ignore));
}

#[test]
fn malformed_query_flags_and_missing_question_are_rejected() {
    for (offset, mask) in [(2, 0x02), (3, 0x01)] {
        let mut wire = QUERY.to_vec();
        wire[offset] |= mask;
        let packet = Packet::parse(&wire).unwrap();
        assert_eq!(rejected(&packet), ResponseCode::FormatError);
    }

    let mut wire = QUERY[..HEADER_LENGTH].to_vec();
    wire[5] = 0;
    let packet = Packet::parse(&wire).unwrap();
    assert_eq!(rejected(&packet), ResponseCode::FormatError);
}

#[test]
fn compression_rfc1035_section_4_1_4() {
    // RFC example layout at offsets 20 (F.ISI.ARPA), 32 (FOO + pointer), 38 (pointer).
    let mut bytes = vec![0; 20];
    bytes.extend_from_slice(b"\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x14\xc0\x20");
    for (start, end, expected) in [
        (20, 32, "F.ISI.ARPA"),
        (32, 38, "FOO.F.ISI.ARPA"),
        (38, 40, "FOO.F.ISI.ARPA"),
    ] {
        let mut cursor = start;
        assert_eq!(
            DomainName::decode(&bytes, &mut cursor).unwrap(),
            expected.parse().unwrap()
        );
        assert_eq!(cursor, end);
    }
}

#[test]
fn names_preserve_binary_labels_and_enforce_limits() {
    let mut cursor = 0;
    let name = DomainName::decode(b"\x03\xff.a\x00", &mut cursor).unwrap();
    let mut out = Vec::new();
    name.encode(&mut out);
    assert_eq!(out, b"\x03\xff.a\x00");
    assert_eq!(name.to_string(), "\\255\\046a.");
    let max = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert!(max.parse::<DomainName>().is_ok());
    assert_eq!(
        format!("{max}d").parse::<DomainName>(),
        Err(ParseError::NameTooLong)
    );
    assert!("a".repeat(64).parse::<DomainName>().is_err());
    assert_eq!(".".parse::<DomainName>().unwrap().label_count(), 0);
    for invalid in ["", "a..b", ".a", "é.test", "a b", "*.test"] {
        assert!(invalid.parse::<DomainName>().is_err());
    }
    assert!("123._tcp.test".parse::<DomainName>().is_ok());
}

#[test]
fn hostile_compression_and_labels() {
    for tail in [
        &b"\xc0\x0c"[..],
        &b"\xc0\xff"[..],
        &b"\xc0"[..],
        &b"\xc0\x00"[..],
        &b"\x40"[..],
        &b"\x80"[..],
        &b"\x04abc"[..],
        &b"\xc0\x0e\xc0\x0c"[..],
        &b"\x01a\xc0\x0c"[..],
    ] {
        let mut bytes = vec![0; HEADER_LENGTH];
        bytes.extend_from_slice(tail);
        assert!(
            DomainName::decode(&bytes, &mut { HEADER_LENGTH }).is_err(),
            "{tail:?}"
        );
    }
    let mut bytes = vec![0; HEADER_LENGTH];
    bytes.push(0);
    let mut previous = HEADER_LENGTH;
    for _ in 0..130 {
        let next = bytes.len();
        bytes.extend_from_slice(&(0xc000 | previous as u16).to_be_bytes());
        previous = next;
    }
    assert_eq!(
        DomainName::decode(&bytes, &mut previous),
        Err(ParseError::CompressionDepth)
    );
}

#[test]
fn counts_trailing_data_and_all_truncations() {
    for len in 0..QUERY.len() {
        assert!(Packet::parse(&QUERY[..len]).is_err());
    }
    for field in [4, 6, 8, 10] {
        let mut bytes = QUERY.to_vec();
        bytes[field..field + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(Packet::parse(&bytes).unwrap_err(), ParseError::InvalidCount);
    }
    let mut bytes = QUERY.to_vec();
    bytes.push(0);
    assert_eq!(Packet::parse(&bytes).unwrap_err(), ParseError::TrailingData);
    assert_eq!(
        Packet::parse(&vec![0; MAX_MESSAGE_LENGTH + 1]).unwrap_err(),
        ParseError::OversizedMessage
    );
}

#[test]
fn unknown_types_classes_opcodes_and_records_are_representable() {
    let mut bytes = QUERY.to_vec();
    let length = bytes.len();
    bytes[length - 4..].copy_from_slice(&[0xfd, 0xe8, 0xfd, 0xe9]);
    bytes[2] = 0x79;
    bytes[11] = 1;
    bytes.extend_from_slice(b"\xc0\x0c\xfd\xea\x00\x01\x00\x00\x00\x3c\x00\x02\xff\xc0");
    let packet = Packet::parse(&bytes).unwrap();
    assert_eq!(packet.questions[0].kind, RecordType::Unknown(65000));
    assert_eq!(packet.questions[0].class, RecordClass::Unknown(65001));
    assert_eq!(packet.header.opcode(), Opcode::Unknown(15));
    assert_eq!(rejected(&packet), ResponseCode::NotImplemented);
    assert_eq!(packet.wire(), bytes);
}

fn with_opt(version: u8) -> Vec<u8> {
    let mut bytes = QUERY.to_vec();
    bytes[11] = 1;
    bytes.extend_from_slice(&[
        0, 0, 41, 0x10, 0, 0, version, 0x80, 0, 0, 5, 0xfd, 0xe8, 0, 1, 42,
    ]);
    bytes
}

#[test]
fn edns_size_options_version_and_generated_errors() {
    let packet = Packet::parse(&with_opt(0)).unwrap();
    assert!(forward(&packet));
    assert_eq!(packet.udp_limit(), SERVER_UDP_LENGTH);
    assert_eq!(
        Packet::parse(QUERY).unwrap().udp_limit(),
        CLASSIC_UDP_LENGTH
    );
    let error = Packet::parse(&packet.error_reply(ResponseCode::ServerFailure)).unwrap();
    assert_eq!(error.response_code(), ResponseCode::ServerFailure);
    assert!(error.edns.unwrap().dnssec_ok);
    let bad = Packet::parse(&with_opt(1)).unwrap();
    assert_eq!(rejected(&bad), ResponseCode::BadVersion);
    let error = Packet::parse(&bad.error_reply(ResponseCode::BadVersion)).unwrap();
    assert_eq!(error.response_code(), ResponseCode::BadVersion);
    assert_eq!(error.edns.unwrap().version, 0);
    let mut small = with_opt(0);
    small[QUERY.len() + 3..QUERY.len() + 5].copy_from_slice(&128_u16.to_be_bytes());
    assert_eq!(
        Packet::parse(&small).unwrap().udp_limit(),
        CLASSIC_UDP_LENGTH
    );
    // CLASS wire values 1, 3 and 4 are IN, CH and HS. OPT must keep them as sizes.
    for size in [1_u16, 3, 4] {
        let mut bytes = with_opt(0);
        bytes[QUERY.len() + 3..QUERY.len() + 5].copy_from_slice(&size.to_be_bytes());
        assert_eq!(Packet::parse(&bytes).unwrap().edns.unwrap().udp_size, size);
    }
    assert_eq!(ResponseCode::from_wire(23), ResponseCode::BadCookie);
    assert_eq!(ResponseCode::BadCookie.wire(), 23);
    let header = Header::parse(QUERY).unwrap();
    let reply = Packet::parse(&header.error_reply(HeaderResponseCode::FORMAT_ERROR)).unwrap();
    assert_eq!(reply.response_code(), ResponseCode::FormatError);
    assert!(reply.edns.is_none());
}

#[test]
fn malformed_opt_and_resource_data_rejected() {
    let mut duplicated = with_opt(0);
    duplicated[11] = 2;
    duplicated.extend_from_slice(&with_opt(0)[QUERY.len()..]);
    assert_eq!(
        Packet::parse(&duplicated).unwrap_err(),
        ParseError::InvalidEdns
    );
    let mut misplaced = with_opt(0);
    misplaced[11] = 0;
    misplaced[7] = 1;
    assert_eq!(
        Packet::parse(&misplaced).unwrap_err(),
        ParseError::InvalidEdns
    );
    let mut option = with_opt(0);
    let len = option.len();
    option[len - 2] = 2;
    assert_eq!(Packet::parse(&option).unwrap_err(), ParseError::InvalidEdns);
    for data in [
        &b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x03\x01\x02\x03"[..],
        &b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x00\x00\x02\xc0\xff"[..],
        &b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x00\x00\x02\x05a"[..],
    ] {
        let mut bytes = QUERY.to_vec();
        bytes[7] = 1;
        bytes.extend_from_slice(data);
        assert!(Packet::parse(&bytes).is_err());
    }
}

#[test]
fn response_correlation_and_safe_truncation() {
    let packet = Packet::parse(QUERY).unwrap();
    let QueryDecision::Forward(query) = packet.validate_query() else {
        panic!("expected a forwardable query");
    };
    let response = Packet::parse(&packet.error_reply(ResponseCode::NoError)).unwrap();
    let response = query.sent(query.id()).validate_response(response).unwrap();
    let bytes = query.truncated_reply(&response);
    let reply = Packet::parse(&bytes).unwrap();
    assert!(reply.header.truncated());
    assert!(reply.corresponds_to(&query, query.id()));
    assert!(!reply.corresponds_to(&query, TransactionId(0)));
    assert!(!packet.corresponds_to(&query, query.id()));
    for index in [2, 13, QUERY.len() - 1, QUERY.len() - 3] {
        let mut other = bytes.clone();
        other[index] ^= if index == 2 { 8 } else { 1 };
        assert!(
            !Packet::parse(&other)
                .unwrap()
                .corresponds_to(&query, query.id())
        );
    }
}

#[test]
fn deterministic_hostile_corpus_never_panics() {
    let mut seed = 0x12345678_u32;
    for len in 0..2048 {
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        let _ = Packet::parse(&bytes);
    }
    for index in 0..QUERY.len() {
        for byte in 0..=255 {
            let mut bytes = QUERY.to_vec();
            bytes[index] = byte;
            let _ = Packet::parse(&bytes);
        }
    }
}

#[test]
fn structured_opt_mutations_retain_only_safe_error_context() {
    for length in [0, 1, 4, 5, 6, 255, 65535] {
        let mut wire = with_opt(0);
        let offset = QUERY.len() + 9;
        wire[offset..offset + 2].copy_from_slice(&(length as u16).to_be_bytes());
        if length == 5 {
            assert!(Packet::parse(&wire).is_ok());
            continue;
        }
        let failure = Packet::parse_for_reply(&wire).unwrap_err();
        let reply = failure.format_reply().unwrap();
        assert_eq!(&reply[..2], &QUERY[..2]);
        if length > 5 || (1..5).contains(&length) {
            assert_eq!(&reply[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
            assert_eq!(
                &reply[QUERY.len()..],
                &[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]
            );
        } else {
            assert_eq!(reply.len(), 12);
        }
    }
    // A malformed unsolicited response has no reply context at all.
    let mut response = with_opt(0);
    response[2] |= 0x80;
    response.pop();
    assert!(
        Packet::parse_for_reply(&response)
            .unwrap_err()
            .format_reply()
            .is_none()
    );
    // Unknown operations can structurally contain several questions. Their
    // product policy is NOTIMP; RFC 9619's QUERY limit is not applied globally.
    let mut other = QUERY.to_vec();
    other[2] = 0x79;
    other[5] = 2;
    other.extend_from_slice(&QUERY[12..]);
    assert_eq!(
        rejected(&Packet::parse(&other).unwrap()),
        ResponseCode::NotImplemented
    );
}
