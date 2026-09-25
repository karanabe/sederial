//! DNS COOKIE option location and the RFC 7873 retry query.
//!
//! Only the first COOKIE option is meaningful. Lengths other than 8 or 16–40
//! are malformed; a forwarder still accepts the message, but it cannot retry
//! from that option.

use super::Packet;

const COOKIE_OPTION: u16 = 10;

#[derive(Debug, Clone, Copy)]
pub(super) struct CookieSlot {
    length_at: usize,
    data_at: usize,
    data_len: usize,
    rdlength_at: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum CookieField {
    Present(CookieSlot),
    Malformed,
}

/// How a BADCOOKIE response relates to the COOKIE option that was sent.
pub(crate) enum ServerCookieRetry {
    /// No COOKIE option was sent, so the §5.3 retry does not apply.
    Absent,
    /// The response cookie is unusable. RFC 7873 requires discarding it.
    Discard,
    /// The server cookie in the response is already the one that was sent.
    Current,
    /// Query bytes using the server cookie from the response.
    Rewrite(Vec<u8>),
    /// The server cookie would move later bytes. Compression pointers are
    /// absolute offsets, so the original BADCOOKIE is returned instead.
    Leave,
}

pub(super) fn locate(wire: &[u8], rdata_at: usize, rdata_len: usize) -> Option<CookieField> {
    let end = rdata_at.saturating_add(rdata_len);
    let mut cursor = rdata_at;
    while cursor + 4 <= end && cursor + 4 <= wire.len() {
        let code = u16::from_be_bytes([wire[cursor], wire[cursor + 1]]);
        let len = usize::from(u16::from_be_bytes([wire[cursor + 2], wire[cursor + 3]]));
        let data_at = cursor + 4;
        let Some(data_end) = data_at.checked_add(len) else {
            return Some(CookieField::Malformed);
        };
        if data_end > end || data_end > wire.len() {
            return Some(CookieField::Malformed);
        }
        if code == COOKIE_OPTION {
            if len == 8 || (16..=40).contains(&len) {
                return Some(CookieField::Present(CookieSlot {
                    length_at: cursor + 2,
                    data_at,
                    data_len: len,
                    rdlength_at: rdata_at.saturating_sub(2),
                }));
            }
            return Some(CookieField::Malformed);
        }
        cursor = data_end;
    }
    None
}

pub(super) fn retry(query: &Packet, sent: &[u8], response: &Packet) -> ServerCookieRetry {
    let Some(query_field) = query.cookie else {
        return ServerCookieRetry::Absent;
    };
    let CookieField::Present(query_cookie) = query_field else {
        return ServerCookieRetry::Discard;
    };
    let Some(CookieField::Present(response_cookie)) = response.cookie else {
        return ServerCookieRetry::Discard;
    };
    let Some(query_data) =
        sent.get(query_cookie.data_at..query_cookie.data_at + query_cookie.data_len)
    else {
        return ServerCookieRetry::Discard;
    };
    let Some(response_data) = response
        .wire
        .get(response_cookie.data_at..response_cookie.data_at + response_cookie.data_len)
    else {
        return ServerCookieRetry::Discard;
    };
    if query_data.len() < 8 || response_data.len() < 16 || query_data[..8] != response_data[..8] {
        return ServerCookieRetry::Discard;
    }
    let server = &response_data[8..];
    if query_data.len() > 8 && &query_data[8..] == server {
        return ServerCookieRetry::Current;
    }
    // A pointer after this option names a byte offset. Growing or shrinking
    // the option moves those bytes, and opaque RDATA can hide further pointers.
    let data_end = query_cookie.data_at + query_cookie.data_len;
    let new_len = 8 + server.len();
    if new_len != query_cookie.data_len && data_end != sent.len() {
        return ServerCookieRetry::Leave;
    }
    rewrite(sent, query_cookie, &query_data[..8], server)
        .map_or(ServerCookieRetry::Discard, ServerCookieRetry::Rewrite)
}

fn rewrite(query: &[u8], slot: CookieSlot, client: &[u8], server: &[u8]) -> Option<Vec<u8>> {
    if server.len() < 8 || server.len() > 32 || slot.rdlength_at + 2 > slot.data_at {
        return None;
    }
    let data_end = slot.data_at + slot.data_len;
    if data_end > query.len() {
        return None;
    }
    let new_len = 8 + server.len();
    let delta = new_len as i32 - slot.data_len as i32;
    let mut out = Vec::with_capacity((query.len() as i32 + delta) as usize);
    out.extend_from_slice(&query[..slot.data_at]);
    out.extend_from_slice(client);
    out.extend_from_slice(server);
    out.extend_from_slice(&query[data_end..]);
    if out.len() > super::MAX_MESSAGE_LENGTH {
        return None;
    }
    out[slot.length_at..slot.length_at + 2].copy_from_slice(&(new_len as u16).to_be_bytes());
    let rdlength = u16::from_be_bytes([out[slot.rdlength_at], out[slot.rdlength_at + 1]]);
    let rdlength = u16::try_from(i32::from(rdlength) + delta).ok()?;
    out[slot.rdlength_at..slot.rdlength_at + 2].copy_from_slice(&rdlength.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::{Packet, QueryDecision};
    use super::*;

    fn query_with_cookie(server: Option<&[u8]>) -> Vec<u8> {
        let mut wire = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\
            \x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00"
            .to_vec();
        let server_len = server.map_or(0, <[u8]>::len);
        let data_len = (8 + server_len) as u16;
        wire.extend_from_slice(&(4 + data_len).to_be_bytes());
        wire.extend_from_slice(&COOKIE_OPTION.to_be_bytes());
        wire.extend_from_slice(&data_len.to_be_bytes());
        wire.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        if let Some(server) = server {
            wire.extend_from_slice(server);
        }
        wire
    }

    fn as_badcookie(mut wire: Vec<u8>) -> Vec<u8> {
        wire[2] |= 0x80;
        wire[3] = 0x87;
        let opt = 12 + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01".len();
        wire[opt + 5] = 1;
        wire
    }

    #[test]
    fn retry_inserts_the_server_cookie_and_rejects_a_mismatch() {
        let sent = query_with_cookie(None);
        let parsed = Packet::parse(&sent).unwrap();
        let QueryDecision::Forward(query) = parsed.validate_query() else {
            panic!("expected a forwardable query");
        };
        let server = [0x11; 8];
        let response = Packet::parse(&as_badcookie(query_with_cookie(Some(&server)))).unwrap();
        let ServerCookieRetry::Rewrite(rewritten) = query.server_cookie_retry(&sent, &response)
        else {
            panic!("expected a rewritten query");
        };
        let rewritten_packet = Packet::parse(&rewritten).unwrap();
        let CookieField::Present(slot) = rewritten_packet.cookie.unwrap() else {
            panic!("cookie missing");
        };
        assert_eq!(
            &rewritten[slot.data_at..slot.data_at + 8],
            &[1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(
            &rewritten[slot.data_at + 8..slot.data_at + slot.data_len],
            &server
        );
        let QueryDecision::Forward(rewritten_query) = rewritten_packet.validate_query() else {
            panic!("rewritten query should still be forwardable");
        };
        assert!(matches!(
            rewritten_query.server_cookie_retry(&rewritten, &response),
            ServerCookieRetry::Current
        ));

        let mut mismatched = as_badcookie(query_with_cookie(Some(&server)));
        let CookieField::Present(slot) = Packet::parse(&mismatched).unwrap().cookie.unwrap() else {
            panic!("cookie missing");
        };
        mismatched[slot.data_at] ^= 0xff;
        let mismatched = Packet::parse(&mismatched).unwrap();
        assert!(matches!(
            query.server_cookie_retry(&sent, &mismatched),
            ServerCookieRetry::Discard
        ));
    }

    #[test]
    fn growing_a_cookie_before_later_bytes_is_not_rewritten() {
        let mut sent = query_with_cookie(None);
        // Another EDNS option after COOKIE. Its bytes would move, and a name
        // compressed against a later offset would keep the old pointer.
        let rdlen_at = sent.len() - 4 - 8 - 2;
        let rdlen = u16::from_be_bytes([sent[rdlen_at], sent[rdlen_at + 1]]) + 4;
        sent[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
        sent.extend_from_slice(&[0, 1, 0, 0]);
        let parsed = Packet::parse(&sent).unwrap();
        let QueryDecision::Forward(query) = parsed.validate_query() else {
            panic!("expected a forwardable query");
        };
        let response = Packet::parse(&as_badcookie(query_with_cookie(Some(&[0x11; 8])))).unwrap();
        assert!(matches!(
            query.server_cookie_retry(&sent, &response),
            ServerCookieRetry::Leave
        ));
    }
}
