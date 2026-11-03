mod support;

use std::{io::Write, sync::atomic::Ordering};
use support::*;

const LOCAL: &str = "[[local]]\ndomain='lab.test'\naddress='10.77.20.2'\n";

fn exchange(daemon: &Daemon, wire: &[u8], over_tcp: bool) -> Vec<u8> {
    if over_tcp {
        let mut stream = tcp(daemon.address);
        stream.write_all(&frame(wire)).unwrap();
        read_frame(&mut stream)
    } else {
        udp(daemon.address, wire)
    }
}

// Independent wire expectation: a fresh question, at most one IN A RR, and
// an empty EDNS0 OPT when requested. AA/AD/TC are never claimed locally.
fn local_reply(q: &[u8], code: u8, answer: Option<([u8; 4], u32)>, ra: bool) -> Vec<u8> {
    let end = question_end(q);
    let mut expected = q[..end].to_vec();
    expected[2] = 0x80 | (q[2] & 1);
    expected[3] = (q[3] & 0x10) | code | if ra { 0x80 } else { 0 };
    expected[6..12].copy_from_slice(&[0, u8::from(answer.is_some()), 0, 0, 0, q[11]]);
    if let Some((ip, ttl)) = answer {
        expected.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        expected.extend_from_slice(&ttl.to_be_bytes());
        expected.extend_from_slice(&[0, 4]);
        expected.extend_from_slice(&ip);
    }
    if q[11] == 1 {
        expected.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, q[end + 7] & 0x80, 0, 0, 0]);
    }
    expected
}

#[test]
fn standalone_local_a_nodata_and_nxdomain_over_udp_and_tcp() {
    let mut daemon = Daemon::start_config("127.0.0.1:0", LOCAL);
    for over_tcp in [false, true] {
        for name in [
            "lab.test",
            "host.lab.test",
            "deep.host.lab.test",
            "LaB.TeSt.",
        ] {
            for kind in [1, 255, 28, 15, 16, 6, 12, 33, 65000] {
                let q = query(name, kind, 0x4567);
                let answer = matches!(kind, 1 | 255).then_some(([10, 77, 20, 2], 0));
                assert_eq!(
                    exchange(&daemon, &q, over_tcp),
                    local_reply(&q, 0, answer, false),
                    "{name} {kind} TCP={over_tcp}"
                );
            }
        }
        for name in ["other.test", "notlab.test", "lab.test.other", "."] {
            for kind in [1, 28] {
                let q = query(name, kind, 0x7654);
                assert_eq!(
                    exchange(&daemon, &q, over_tcp),
                    local_reply(&q, 3, None, false)
                );
            }
        }
        let mut q = query("lab.test", 1, 0x1234);
        *q.last_mut().unwrap() = 3; // CH class has no local database.
        assert_eq!(
            exchange(&daemon, &q, over_tcp),
            local_reply(&q, 5, None, false)
        );
    }
    daemon.terminate("-TERM");
}

#[test]
fn local_edns_flags_maximum_name_and_tcp_pipeline() {
    let daemon = Daemon::start_config("127.0.0.1:0", &format!("{LOCAL}ttl=300\n"));
    // 255 wire bytes including the root, the maximum permitted QNAME.
    let longest = format!(
        "{}.{}.{}.{}.lab.test",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(52)
    );
    for over_tcp in [false, true] {
        for (name, kind, code) in [
            (longest.as_str(), 1, 0),
            ("lab.test", 28, 0),
            ("other.test", 1, 3),
        ] {
            for rd in [false, true] {
                let mut q = query(name, kind, 0xabcd);
                q[2] = if rd { 1 } else { 0 };
                q[3] = 0x30; // AD must clear; CD must survive.
                edns(&mut q, 512); // DO set, unknown option must not be echoed.
                let answer = (name != "other.test" && kind == 1).then_some(([10, 77, 20, 2], 300));
                let reply = exchange(&daemon, &q, over_tcp);
                assert_eq!(reply, local_reply(&q, code, answer, false));
                assert!(reply.len() <= 512);
            }
        }
    }
    let mut stream = tcp(daemon.address);
    let queries = [
        query("lab.test", 1, 1),
        query("absent.test", 1, 2),
        query("lab.test", 28, 3),
    ];
    for q in &queries {
        stream.write_all(&frame(q)).unwrap();
    }
    for (q, code, answer) in [
        (&queries[0], 0, Some(([10, 77, 20, 2], 300))),
        (&queries[1], 3, None),
        (&queries[2], 0, None),
    ] {
        assert_eq!(read_frame(&mut stream), local_reply(q, code, answer, false));
    }
}

#[test]
fn longest_suffix_selects_local_or_forwarding_without_type_fallback() {
    let upstream = Mock::new(|q, _| vec![response(q, 9)]);
    let daemon = Daemon::start_config(
        "127.0.0.1:0",
        &format!(
            "[default]\nservers=['{0}']\n{LOCAL}\n[[route]]\ndomain='test'\nservers=['{0}']\n\
         [[route]]\ndomain='forward.lab.test'\nservers=['{0}']\n\
         [[local]]\ndomain='special.lab.test'\naddress='10.77.20.3'\nttl=60\n\
         [[local]]\ndomain='local.forward.lab.test'\naddress='10.77.20.4'\n",
            upstream.address
        ),
    );
    for over_tcp in [false, true] {
        for (name, ip, ttl) in [
            ("lab.test", [10, 77, 20, 2], 0),
            ("deep.special.lab.test", [10, 77, 20, 3], 60),
            ("local.forward.lab.test", [10, 77, 20, 4], 0),
        ] {
            for kind in [1, 28, 16] {
                let q = query(name, kind, 7);
                assert_eq!(
                    exchange(&daemon, &q, over_tcp),
                    local_reply(&q, 0, (kind == 1).then_some((ip, ttl)), true)
                );
            }
        }
    }
    assert!(upstream.seen.lock().unwrap().is_empty());
    assert_eq!(upstream.tcp_connections.load(Ordering::Relaxed), 0);
    for over_tcp in [false, true] {
        for name in [
            "forward.lab.test",
            "host.forward.lab.test",
            "notlab.test",
            "example.com",
        ] {
            let q = query(name, 1, 8);
            assert_eq!(exchange(&daemon, &q, over_tcp), response(&q, 9));
        }
    }
    assert_eq!(upstream.seen.lock().unwrap().len(), 8);
}

#[test]
fn routes_without_default_and_root_local_policy() {
    let upstream = Mock::new(|q, _| vec![response(q, 5)]);
    let daemon = Daemon::start_config(
        "127.0.0.1:0",
        &format!(
            "{LOCAL}[[route]]\ndomain='remote.test'\nservers=['{}']",
            upstream.address
        ),
    );
    for over_tcp in [false, true] {
        let q = query("absent.test", 1, 1);
        assert_eq!(
            exchange(&daemon, &q, over_tcp),
            local_reply(&q, 3, None, true)
        );
        let q = query("remote.test", 1, 2);
        assert_eq!(exchange(&daemon, &q, over_tcp), response(&q, 5));
    }
    assert_eq!(upstream.seen.lock().unwrap().len(), 2);
    let daemon = Daemon::start_config("[::1]:0", "[[local]]\ndomain='.'\naddress='10.77.20.2'");
    for name in [".", "any.test"] {
        for over_tcp in [false, true] {
            let q = query(name, 1, 3);
            assert_eq!(
                exchange(&daemon, &q, over_tcp),
                local_reply(&q, 0, Some(([10, 77, 20, 2], 0)), false)
            );
        }
    }
}

#[test]
fn standalone_validation_precedes_local_answers() {
    let daemon = Daemon::start_config("127.0.0.1:0", LOCAL);
    for over_tcp in [false, true] {
        for kind in [251, 252, 249, 250, 41] {
            let q = query("lab.test", kind, 1);
            assert_eq!(
                exchange(&daemon, &q, over_tcp),
                local_reply(&q, 5, None, false)
            );
        }
        let mut malformed = query("lab.test", 1, 1);
        malformed.pop();
        let reply = exchange(&daemon, &malformed, over_tcp);
        assert_eq!(&reply[..4], &[0, 1, 0x81, 1]); // FORMERR, RA clear.
        let mut bad_version = query("lab.test", 1, 1);
        edns(&mut bad_version, 1232);
        let end = question_end(&bad_version);
        bad_version[end + 6] = 1;
        let mut expected = local_reply(&bad_version, 0, None, false);
        expected[end + 5] = 1; // BADVERS extended RCODE, EDNS version zero.
        assert_eq!(exchange(&daemon, &bad_version, over_tcp), expected);
    }
}
