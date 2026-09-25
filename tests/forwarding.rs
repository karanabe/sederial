mod support;
use std::{io::Write, sync::atomic::Ordering, time::Instant};
use support::*;

#[test]
fn malformed_edns_returns_a_fresh_opt_over_both_transports() {
    let upstream = Mock::new(|q, _| vec![response(q, 1)]);
    let daemon = Daemon::start(&[upstream.address], &[]);
    let base = query("edns.test", 1, 0x1234);
    let mut malformed = base.clone();
    edns(&mut malformed, 1232);
    let end = malformed.len();
    malformed[end - 2] = 2; // TLV declares two bytes, only one remains.
    let mut duplicate = base.clone();
    edns(&mut duplicate, 1232);
    duplicate.extend_from_within(base.len()..);
    duplicate[11] = 2;
    let mut short_opt = base.clone();
    edns(&mut short_opt, 1232);
    short_opt.truncate(base.len() + 9);
    let mut no_opt = base.clone();
    no_opt.push(0); // Trailing byte, no OPT advertised.
    let short_question = base[..base.len() - 1].to_vec();
    for (wire, with_opt) in [
        (malformed, true),
        (duplicate, true),
        (short_opt, false),
        (no_opt, false),
        (short_question, false),
    ] {
        for over_tcp in [false, true] {
            let reply = if over_tcp {
                let mut stream = tcp(daemon.address);
                stream.write_all(&frame(&wire)).unwrap();
                read_frame(&mut stream)
            } else {
                udp(daemon.address, &wire)
            };
            assert_eq!(&reply[..2], &base[..2]);
            assert_eq!(reply[3] & 15, 1);
            assert_eq!(&reply[6..10], &[0; 4]);
            assert_eq!(&reply[10..12], &[0, u8::from(with_opt)]);
            if with_opt {
                assert_eq!(&reply[4..6], &[0, 1]);
                assert_eq!(&reply[12..base.len()], &base[12..]);
                assert_eq!(
                    &reply[base.len()..],
                    &[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]
                );
            } else {
                assert_eq!(reply.len(), 12);
            }
        }
    }
    assert!(upstream.seen.lock().unwrap().is_empty());
}

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
        reply[3] |= 0x70;
        vec![reply]
    });
    let daemon = Daemon::start(&[mock.address], &[]);
    let mut q = query("unknown.test", 65000, 72);
    edns(&mut q, 4096);
    q[3] |= 0x50;
    let actual = udp(daemon.address, &q);
    let mut expected = large_response(&q, 600);
    expected[3] |= 0x70;
    assert_eq!(actual, expected);
    let seen = mock.seen.lock().unwrap();
    assert_eq!(&seen[0][2..], &q[2..]);
}

#[test]
fn last_dns_failure_preserves_ede_even_after_transport_failure() {
    for codes in [[2, 5], [5, 2], [2, 2]] {
        let first = Mock::new(move |q, _| vec![empty_response(q, codes[0])]);
        let last = Mock::new(move |q, _| {
            let mut reply = empty_response(q, codes[1]);
            // An independently encoded Extended DNS Error option.
            let opt = question_end(q);
            reply.truncate(opt);
            reply[11] = 1;
            reply.extend_from_slice(&[
                0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 8, 0, 15, 0, 4, 0, 22, b'n', b'o',
            ]);
            vec![reply]
        });
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_address = closed.local_addr().unwrap();
        drop(closed);
        let daemon = Daemon::start(&[first.address, last.address, closed_address], &[]);
        let mut q = query("ede.test", 1, 17);
        edns(&mut q, 1232);
        for over_tcp in [false, true] {
            let reply = if over_tcp {
                let mut stream = tcp(daemon.address);
                stream.write_all(&frame(&q)).unwrap();
                read_frame(&mut stream)
            } else {
                udp(daemon.address, &q)
            };
            assert_eq!(reply[3] & 15, codes[1]);
            assert!(reply.ends_with(&[0, 15, 0, 4, 0, 22, b'n', b'o']));
        }
    }
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
    let other = Mock::new(|q, _| vec![cookie_response(q, 0, false)]);
    let daemon = Daemon::start(&[upstream.address, other.address], &[]);
    let q = query_with_client_cookie("failover.test", 7, &client);
    assert_eq!(udp(daemon.address, &q), cookie_response(&q, 0, false));
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

// Returns a valid response COOKIE, replacing only the independently known OPT.
fn cookie_response(q: &[u8], code: u8, large: bool) -> Vec<u8> {
    let client = &q[question_end(q) + 15..question_end(q) + 23];
    let mut reply = if large {
        large_response(q, 1300)
    } else {
        empty_response(q, code & 15)
    };
    let opt = if large {
        question_end(q) + 12 + 1300
    } else {
        question_end(q)
    };
    reply.truncate(opt);
    reply[3] = 0x80 | (code & 15);
    reply[11] = 1;
    reply.extend_from_slice(&[0, 0, 41, 4, 208, code >> 4, 0, 0, 0, 0, 20, 0, 10, 0, 16]);
    reply.extend_from_slice(client);
    reply.extend_from_slice(&[0x55; 8]);
    reply
}

#[test]
fn every_udp_rcode_checks_cookie_before_accepting_the_response() {
    for code in [0, 2, 5, 23] {
        let upstream = Mock::new(move |q, over_tcp| {
            let valid = cookie_response(q, code, false);
            if over_tcp {
                return vec![valid];
            }
            let mut mismatch = valid.clone();
            mismatch[question_end(q) + 15] ^= 1;
            let mut short = valid.clone();
            let opt = question_end(q);
            short[opt + 10] = 12;
            short[opt + 14] = 8;
            short.truncate(opt + 23);
            vec![mismatch, short, valid]
        });
        let daemon = Daemon::start(&[upstream.address], &[]);
        let q = query_with_client_cookie("correlate.test", 37, &[4; 8]);
        assert_eq!(udp(daemon.address, &q), cookie_response(&q, code, false));
    }
}

#[test]
fn local_tc_retains_the_validated_response_cookie() {
    let upstream = Mock::new(|q, _| vec![cookie_response(q, 0, true)]);
    let daemon = Daemon::start(&[upstream.address], &[]);
    let q = query_with_client_cookie("cookie-large.test", 38, &[7; 8]);
    let reply = udp(daemon.address, &q);
    assert_ne!(
        reply[2] & 2,
        0,
        "reply={reply:?}, logs={:?}",
        daemon.logs.lock().unwrap()
    );
    assert_eq!(&reply[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        &reply[question_end(&q)..],
        &cookie_response(&q, 0, false)[question_end(&q)..]
    );
}

#[test]
fn cookie_before_padding_unknown_option_or_additional_rr_uses_tcp_without_moving_bytes() {
    for suffix in [0, 1, 2] {
        let upstream =
            Mock::new(|q, over_tcp| vec![cookie_response(q, if over_tcp { 0 } else { 23 }, false)]);
        let public = Mock::new(|q, _| vec![response(q, 1)]);
        let daemon = Daemon::start(&[public.address], &[("private.test", upstream.address)]);
        let mut q = query_with_client_cookie("private.test", 39, &[6; 8]);
        let opt = question_end(&q);
        if suffix < 2 {
            q[opt + 10] += 5;
            q.extend_from_slice(&[
                if suffix == 0 { 0 } else { 253 },
                if suffix == 0 { 12 } else { 232 },
                0,
                1,
                0,
            ]);
        } else {
            q[11] = 2;
            // Opaque data contains a pointer-looking byte sequence; never relocate it.
            q.extend_from_slice(&[0xc0, 12, 253, 232, 0, 1, 0, 0, 0, 0, 0, 2, 0xc0, 12]);
        }
        let reply = udp(daemon.address, &q);
        assert_eq!(reply[3] & 15, 0);
        assert_eq!(upstream.tcp_connections.load(Ordering::Relaxed), 1);
        let seen = upstream.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(&seen[1][2..], &q[2..]);
        assert!(public.seen.lock().unwrap().is_empty());
    }
}

#[test]
fn cookie_validation_covers_initial_and_retried_tcp_and_udp_responses() {
    for phase in [
        "initial-udp",
        "initial-tcp",
        "udp-retry",
        "tcp-retry",
        "tcp-after-udp",
    ] {
        for invalid in ["mismatch", "short", "missing"] {
            if invalid == "missing" && phase.starts_with("initial") {
                continue;
            }
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let upstream = Mock::new(move |q, over_tcp| {
                let call = calls.fetch_add(1, Ordering::Relaxed);
                let challenge = match phase {
                    "udp-retry" | "tcp-retry" => call == 0,
                    "tcp-after-udp" => call < 2,
                    _ => false,
                };
                if challenge {
                    return vec![cookie_response(q, 23, false)];
                }
                let valid = cookie_response(q, 0, false);
                let mut bad = valid.clone();
                let opt = question_end(q);
                match invalid {
                    "mismatch" => bad[opt + 15] ^= 1,
                    "short" => {
                        bad[opt + 10] = 12;
                        bad[opt + 14] = 8;
                        bad.truncate(opt + 23);
                    }
                    _ => {
                        bad[opt + 10] = 0;
                        bad.truncate(opt + 11);
                    }
                }
                if over_tcp {
                    vec![bad]
                } else {
                    vec![bad, valid]
                }
            });
            let public = Mock::new(|q, _| vec![response(q, 1)]);
            let daemon = Daemon::start(&[public.address], &[("private.test", upstream.address)]);
            let q = query_with_client_cookie("private.test", 52, &[8; 8]);
            let client_tcp = matches!(phase, "initial-tcp" | "tcp-retry");
            let actual = if client_tcp {
                let mut stream = tcp(daemon.address);
                stream.write_all(&frame(&q)).unwrap();
                read_frame(&mut stream)
            } else {
                udp(daemon.address, &q)
            };
            let expected_code = if phase.contains("tcp") { 2 } else { 0 };
            assert_eq!(actual[3] & 15, expected_code, "{phase} {invalid}");
            if expected_code == 0 {
                assert_eq!(actual, cookie_response(&q, 0, false));
            }
            assert!(public.seen.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn cookie_unaware_servers_remain_compatible_on_the_first_exchange() {
    let upstream = Mock::new(|q, _| {
        let mut reply = empty_response(q, 0);
        reply.truncate(question_end(q));
        reply[11] = 0;
        vec![reply]
    });
    let daemon = Daemon::start(&[upstream.address], &[]);
    for server_cookie in [false, true] {
        let mut q = query_with_client_cookie("legacy.test", 53, &[3; 8]);
        if server_cookie {
            let opt = question_end(&q);
            q[opt + 10] = 20;
            q[opt + 14] = 16;
            q.extend_from_slice(&[9; 8]);
        }
        assert_eq!(udp(daemon.address, &q)[3] & 15, 0);
        let mut stream = tcp(daemon.address);
        stream.write_all(&frame(&q)).unwrap();
        assert_eq!(read_frame(&mut stream)[3] & 15, 0);
    }
}

#[test]
fn private_route_failures_never_contact_default_over_udp_or_tcp() {
    for failure in [
        "timeout",
        "servfail",
        "refused",
        "badcookie",
        "malformed",
        "reconnect",
    ] {
        let upstream = Mock::new(move |q, _| match failure {
            "timeout" => vec![],
            "servfail" => vec![empty_response(q, 2)],
            "refused" => vec![empty_response(q, 5)],
            "badcookie" => vec![cookie_response(q, 23, false)],
            "malformed" => vec![vec![0; 3]],
            _ => vec![response(q, 9)],
        });
        let public = Mock::new(|q, _| vec![response(q, 1)]);
        let daemon = Daemon::start(&[public.address], &[("private.test", upstream.address)]);
        let q = if failure == "badcookie" {
            query_with_client_cookie("private.test", 54, &[8; 8])
        } else {
            query("private.test", 1, 54)
        };
        let answer = udp(daemon.address, &q);
        assert_eq!(&answer[..2], &q[..2]);
        let mut stream = tcp(daemon.address);
        stream.write_all(&frame(&q)).unwrap();
        read_frame(&mut stream);
        if failure == "reconnect" {
            // Mock closes idle TCP in 100 ms; the worker retains it for 2 s.
            std::thread::sleep(std::time::Duration::from_millis(250));
            stream.write_all(&frame(&q)).unwrap();
            assert_eq!(read_frame(&mut stream), response(&q, 9));
            assert!(upstream.tcp_connections.load(Ordering::Relaxed) >= 2);
        }
        assert!(public.seen.lock().unwrap().is_empty(), "{failure}");
    }
}
