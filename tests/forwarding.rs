mod support;
use std::{io::Write, sync::atomic::Ordering, time::Instant};
use support::*;

#[test]
fn split_dns_routes_ad_srv_reverse_and_default_over_both_transports() {
    let public = Mock::new(|q, _| vec![response(q, 1)]);
    let parent = Mock::new(|q, _| vec![response(q, 2)]);
    let ad = Mock::new(|q, _| vec![response(q, 3)]);
    let daemon = Daemon::start(
        &[public.address],
        &[
            ("exceeds.test", parent.address),
            ("ad.lab.exceeds.test", ad.address),
            ("100.168.192.in-addr.arpa", ad.address),
        ],
    );
    for (name, kind, marker) in [
        ("dc01.ad.lab.exceeds.test", 1, 3),
        ("AD.LAB.EXCEEDS.TEST", 28, 3),
        ("_ldap._tcp.dc._msdcs.ad.lab.exceeds.test", 33, 3),
        ("1.100.168.192.in-addr.arpa", 12, 3),
        ("example.com", 1, 1),
        ("github.com", 1, 1),
        ("host.exceeds.test", 1, 2),
        ("badexceeds.test", 1, 1),
    ] {
        let query = query(name, kind, 0x4567);
        assert_eq!(udp(daemon.address, &query), response(&query, marker));
        let mut stream = tcp(daemon.address);
        stream.write_all(&frame(&query)).unwrap();
        assert_eq!(read_frame(&mut stream), response(&query, marker));
    }
    assert_eq!(ad.seen.lock().unwrap().len(), 8);
}

#[test]
fn tcp_fragmentation_pipelining_and_upstream_connection_reuse() {
    let mock = Mock::new(|q, tcp| {
        assert!(tcp);
        vec![response(q, 9)]
    });
    let daemon = Daemon::start(&[mock.address], &[]);
    let mut stream = tcp(daemon.address);
    let queries = [
        query("one.test", 1, 1),
        query("two.test", 1, 2),
        query("three.test", 1, 3),
    ];
    let bytes: Vec<_> = queries.iter().flat_map(|q| frame(q)).collect();
    for byte in &bytes {
        stream.write_all(&[*byte]).unwrap();
    }
    for query in queries {
        assert_eq!(read_frame(&mut stream), response(&query, 9));
    }
    assert_eq!(mock.tcp_connections.load(Ordering::Relaxed), 1);
}

#[test]
fn truncated_udp_retries_tcp_and_respects_client_size() {
    let mock = Mock::new(|q, tcp| {
        if tcp {
            vec![large_response(q, 700)]
        } else {
            let mut reply = empty_response(q, 0);
            reply[2] |= 2;
            reply[7] = 1;
            reply.extend_from_slice(&[0xc0]); // RR cut during truncation: TCP must still be tried.
            vec![reply]
        }
    });
    let daemon = Daemon::start(&[mock.address], &[]);
    let small = query("large.test", 1, 123);
    let truncated = udp(daemon.address, &small);
    assert_ne!(truncated[2] & 2, 0);
    assert!(truncated.len() <= 512);
    assert_eq!(&truncated[6..10], &[0, 0, 0, 0]);
    let mut big = small.clone();
    edns(&mut big, 1232);
    assert_eq!(udp(daemon.address, &big), large_response(&big, 700));
    let mut stream = tcp(daemon.address);
    stream.write_all(&frame(&small)).unwrap();
    assert_eq!(read_frame(&mut stream), large_response(&small, 700));
    assert!(mock.tcp_connections.load(Ordering::Relaxed) >= 1);
}

#[test]
fn edns_unknown_records_flags_and_options_survive() {
    let mock = Mock::new(|q, _| {
        let mut reply = large_response(q, 600);
        reply[3] |= 0x30;
        vec![reply]
    });
    let daemon = Daemon::start(&[mock.address], &[]);
    let mut q = query("unknown.test", 65000, 72);
    edns(&mut q, 4096);
    q[3] |= 0x10;
    let actual = udp(daemon.address, &q);
    let mut expected = large_response(&q, 600);
    expected[3] |= 0x30;
    assert_eq!(actual, expected);
    let seen = mock.seen.lock().unwrap();
    assert_eq!(&seen[0][2..], &q[2..]);
}

#[test]
fn invalid_udp_responses_are_ignored_until_correlated_reply() {
    let mock = Mock::new(|q, _| {
        let valid = response(q, 7);
        let mut id = valid.clone();
        id[0] ^= 1;
        let mut name = valid.clone();
        name[13] ^= 1;
        let mut kind = valid.clone();
        kind[question_end(q) - 3] ^= 1;
        let mut class = valid.clone();
        class[question_end(q) - 1] ^= 1;
        let mut opcode = valid.clone();
        opcode[2] ^= 8;
        vec![vec![0; 3], q.to_vec(), id, name, kind, class, opcode, valid]
    });
    let daemon = Daemon::start(&[mock.address], &[]);
    let q = query("valid.test", 1, 7);
    assert_eq!(udp(daemon.address, &q), response(&q, 7));
}

#[test]
fn timeout_servfail_and_connection_failure_fail_over_but_nxdomain_is_final() {
    let silent = Mock::new(|_, _| vec![]);
    let soft = Mock::new(|q, _| vec![empty_response(q, 2)]);
    let good = Mock::new(|q, _| vec![response(q, 8)]);
    let daemon = Daemon::start(&[silent.address, soft.address, good.address], &[]);
    let q = query("fallback.test", 1, 8);
    let started = Instant::now();
    assert_eq!(udp(daemon.address, &q), response(&q, 8));
    assert!(started.elapsed().as_secs_f32() >= 1.9 && started.elapsed().as_secs_f32() < 4.5);
    let negative = Mock::new(|q, _| vec![empty_response(q, 3)]);
    let daemon = Daemon::start(&[negative.address, good.address], &[]);
    assert_eq!(udp(daemon.address, &q), empty_response(&q, 3));
    assert_eq!(good.seen.lock().unwrap().len(), 1);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let daemon = Daemon::start(&[address, good.address], &[]);
    let mut stream = tcp(daemon.address);
    stream.write_all(&frame(&q)).unwrap();
    assert_eq!(read_frame(&mut stream), response(&q, 8));
}

fn query_with_client_cookie(name: &str, id: u16, client: &[u8; 8]) -> Vec<u8> {
    let mut wire = query(name, 1, id);
    wire[11] = 1;
    wire.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8]);
    wire.extend_from_slice(client);
    wire
}

fn badcookie_offering(query: &[u8], server: &[u8; 8]) -> Vec<u8> {
    let mut reply = query.to_vec();
    reply[2] |= 0x80;
    reply[3] = 0x87;
    let opt = question_end(&reply);
    reply[opt + 5] = 1;
    let rdlen = u16::from_be_bytes([reply[opt + 9], reply[opt + 10]]) + 8;
    reply[opt + 9..opt + 11].copy_from_slice(&rdlen.to_be_bytes());
    let option_len = u16::from_be_bytes([reply[opt + 13], reply[opt + 14]]) + 8;
    reply[opt + 13..opt + 15].copy_from_slice(&option_len.to_be_bytes());
    reply.extend_from_slice(server);
    reply
}

fn has_server_cookie(query: &[u8], server: &[u8; 8]) -> bool {
    let opt = question_end(query);
    query.len() >= opt + 15 + 8 + 8 && query[opt + 15 + 8..].starts_with(server)
}

#[test]
fn badcookie_retries_the_same_server_then_tcp() {
    let server = [0x22; 8];
    let client = [1, 2, 3, 4, 5, 6, 7, 8];
    let upstream = Mock::new(move |q, tcp| {
        if tcp && has_server_cookie(q, &server) {
            vec![response(q, 4)]
        } else if has_server_cookie(q, &server) {
            let mut reply = q.to_vec();
            reply[2] |= 0x80;
            reply[3] = 0x87;
            let opt = question_end(&reply);
            reply[opt + 5] = 1;
            vec![reply]
        } else {
            vec![badcookie_offering(q, &server)]
        }
    });
    let other = Mock::new(|q, _| vec![response(q, 1)]);
    let daemon = Daemon::start(&[upstream.address, other.address], &[]);
    let q = query_with_client_cookie("cookie.test", 9, &client);
    let answer = udp(daemon.address, &q);
    assert_eq!(
        answer[3] & 0x0f,
        0,
        "expected the TCP answer, got {answer:?}"
    );
    assert_eq!(upstream.tcp_connections.load(Ordering::Relaxed), 1);
    assert!(other.seen.lock().unwrap().is_empty());
    assert_eq!(upstream.seen.lock().unwrap().len(), 3);
}

#[test]
fn badcookie_with_a_fresh_server_cookie_is_answered_on_udp() {
    let server = [0x33; 8];
    let client = [8, 7, 6, 5, 4, 3, 2, 1];
    let upstream = Mock::new(move |q, tcp| {
        assert!(!tcp);
        if has_server_cookie(q, &server) {
            vec![response(q, 6)]
        } else {
            vec![badcookie_offering(q, &server)]
        }
    });
    let other = Mock::new(|q, _| vec![response(q, 1)]);
    let daemon = Daemon::start(&[upstream.address, other.address], &[]);
    let q = query_with_client_cookie("retry.test", 6, &client);
    let answer = udp(daemon.address, &q);
    assert_eq!(&answer[..2], &q[..2]);
    assert_eq!(answer[3] & 0x0f, 0);
    assert_eq!(upstream.seen.lock().unwrap().len(), 2);
    assert!(other.seen.lock().unwrap().is_empty());
}

#[test]
fn servfail_after_cookie_retry_tries_the_next_server() {
    let server = [0x44; 8];
    let client = [9; 8];
    let upstream = Mock::new(move |q, tcp| {
        assert!(!tcp);
        if has_server_cookie(q, &server) {
            vec![empty_response(q, 2)]
        } else {
            vec![badcookie_offering(q, &server)]
        }
    });
    let other = Mock::new(|q, _| vec![response(q, 7)]);
    let daemon = Daemon::start(&[upstream.address, other.address], &[]);
    let q = query_with_client_cookie("failover.test", 7, &client);
    assert_eq!(udp(daemon.address, &q), response(&q, 7));
    assert_eq!(upstream.seen.lock().unwrap().len(), 2);
    assert_eq!(other.seen.lock().unwrap().len(), 1);
}

#[test]
fn refused_fails_over_but_nxdomain_is_final() {
    let refused = Mock::new(|q, _| vec![empty_response(q, 5)]);
    let good = Mock::new(|q, _| vec![response(q, 4)]);
    let daemon = Daemon::start(&[refused.address, good.address], &[]);
    let q = query("refused.test", 1, 4);
    assert_eq!(udp(daemon.address, &q), response(&q, 4));

    let negative = Mock::new(|q, _| vec![empty_response(q, 3)]);
    let untouched = Mock::new(|q, _| vec![response(q, 1)]);
    let daemon = Daemon::start(&[negative.address, untouched.address], &[]);
    assert_eq!(
        udp(daemon.address, &query("nxdomain.test", 1, 3)),
        empty_response(&query("nxdomain.test", 1, 3), 3)
    );
    assert!(untouched.seen.lock().unwrap().is_empty());

    let only = Mock::new(|q, _| vec![empty_response(q, 5)]);
    let daemon = Daemon::start(&[only.address], &[]);
    let refused_query = query("last-refused.test", 1, 5);
    assert_eq!(
        udp(daemon.address, &refused_query),
        empty_response(&refused_query, 5)
    );
}

#[test]
fn unavailable_upstreams_return_servfail() {
    let mock = Mock::new(|_, _| vec![]);
    let daemon = Daemon::start(&[mock.address], &[]);
    let q = query("timeout.test", 1, 55);
    let reply = udp(daemon.address, &q);
    assert_eq!(&reply[..2], &q[..2]);
    assert_eq!(reply[3] & 15, 2);
}

#[test]
fn ipv6_listener_and_upstream() {
    let mock = Mock::on("[::1]:0", |q, _| vec![response(q, 6)]);
    let daemon = Daemon::start_on("[::1]:0", &[mock.address], &[]);
    let q = query("ipv6.test", 28, 6);
    assert_eq!(udp(daemon.address, &q), response(&q, 6));
    let mut stream = tcp(daemon.address);
    stream.write_all(&frame(&q)).unwrap();
    assert_eq!(read_frame(&mut stream), response(&q, 6));
}

#[test]
fn ipv4_mapped_upstream_reaches_the_ipv4_endpoint() {
    let mock = Mock::new(|q, _| vec![response(q, 4)]);
    let mapped = format!("[::ffff:{}]:{}", mock.address.ip(), mock.address.port())
        .parse()
        .unwrap();
    let daemon = Daemon::start(&[mapped], &[]);
    let q = query("mapped.test", 1, 4);
    assert_eq!(udp(daemon.address, &q), response(&q, 4));
    let mut stream = tcp(daemon.address);
    stream.write_all(&frame(&q)).unwrap();
    assert_eq!(read_frame(&mut stream), response(&q, 4));
}

#[test]
fn invalid_tcp_responses_fail_over_and_private_routes_do_not_leak() {
    let bad = Mock::new(|q, _| {
        let mut reply = response(q, 1);
        reply[0] ^= 1;
        vec![reply]
    });
    let good = Mock::new(|q, _| vec![response(q, 2)]);
    let daemon = Daemon::start(&[bad.address, good.address], &[]);
    let q = query("failover.test", 1, 13);
    let mut stream = tcp(daemon.address);
    stream.write_all(&frame(&q)).unwrap();
    assert_eq!(read_frame(&mut stream), response(&q, 2));
    let private = Mock::new(|q, _| vec![empty_response(q, 2)]);
    let daemon = Daemon::start(&[good.address], &[("private.test", private.address)]);
    let answer = udp(daemon.address, &query("secret.private.test", 1, 14));
    assert_eq!(answer[3] & 15, 2);
    assert_eq!(good.seen.lock().unwrap().len(), 1);
}

#[test]
fn udp_ceiling_truncates_large_edns_answer_but_tcp_keeps_it() {
    // Exceed the 1232-byte reply limit without requiring IP fragmentation.
    let mock = Mock::new(|q, _| vec![large_response(q, 1300)]);
    let daemon = Daemon::start(&[mock.address], &[]);
    let mut q = query("ceiling.test", 1, 33);
    edns(&mut q, 4096);
    let reply = udp(daemon.address, &q);
    assert_ne!(
        reply[2] & 2,
        0,
        "reply {:?}; logs {}",
        &reply[..12],
        daemon.logs.lock().unwrap()
    );
    assert!(reply.len() <= 1232);
    assert_eq!(reply[11], 1); // Keep EDNS in the generated TC reply.
    let mut stream = tcp(daemon.address);
    stream.write_all(&frame(&q)).unwrap();
    assert_eq!(read_frame(&mut stream), large_response(&q, 1300));
}
