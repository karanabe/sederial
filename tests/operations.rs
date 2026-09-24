mod support;
use std::{
    io::{Read, Write},
    net::UdpSocket,
    process::Command,
    thread,
    time::{Duration, Instant},
};
use support::*;

#[test]
fn malformed_unsupported_and_unsolicited_packets_do_not_break_service() {
    let mock = Mock::new(|q, _| vec![response(q, 1)]);
    let daemon = Daemon::start(&[mock.address], &[]);
    let q = query("private-client-name.test", 1, 1);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(daemon.address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let mut buffer = [0; 1024];
    for bytes in [&[1, 2, 3][..], &empty_response(&q, 0)] {
        socket.send(bytes).unwrap();
        assert!(socket.recv(&mut buffer).is_err());
    }
    let mut invalid = q[..12].to_vec();
    invalid.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    assert_eq!(udp(daemon.address, &invalid)[3] & 15, 1);
    let mut count = q.clone();
    count[5] = 2;
    assert_eq!(udp(daemon.address, &count)[3] & 15, 1);
    let mut opcode = q.clone();
    opcode[2] |= 8;
    assert_eq!(udp(daemon.address, &opcode)[3] & 15, 4);
    for kind in [251, 252, 249, 250, 41] {
        assert_eq!(udp(daemon.address, &query("test", kind, 2))[3] & 15, 5);
    }
    let mut version = q.clone();
    edns(&mut version, 1232);
    version[q.len() + 6] = 1;
    let error = udp(daemon.address, &version);
    assert_eq!(error[3] & 15, 0);
    assert_eq!(error[question_end(&error) + 5], 1); // extended BADVERS
    assert_eq!(udp(daemon.address, &q), response(&q, 1));
    assert!(!daemon.logs.lock().unwrap().contains("private-client-name"));
    assert_eq!(mock.seen.lock().unwrap().len(), 1);
}

#[test]
fn malformed_tcp_frames_close_only_the_offending_connection() {
    let mock = Mock::new(|q, _| vec![response(q, 1)]);
    let daemon = Daemon::start(&[mock.address], &[]);
    for length in [0_u16, 1, 11] {
        let mut stream = tcp(daemon.address);
        stream.write_all(&length.to_be_bytes()).unwrap();
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    }
    let mut partial = tcp(daemon.address);
    partial.write_all(&[0, 50, 1, 2]).unwrap();
    partial.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(partial.read(&mut [0]).unwrap(), 0);
    let q = query("still-alive.test", 1, 9);
    assert_eq!(udp(daemon.address, &q), response(&q, 1));
}

#[test]
fn tcp_capacity_is_bounded_and_udp_stays_available() {
    let mock = Mock::new(|q, _| vec![response(q, 1)]);
    let mut daemon = Daemon::start(&[mock.address], &[]);
    let clients: Vec<_> = (0..64).map(|_| tcp(daemon.address)).collect();
    thread::sleep(Duration::from_millis(200));
    let threads = std::fs::read_dir(format!("/proc/{}/task", daemon.child.id()))
        .unwrap()
        .count();
    // Main/UDP receiver, one TCP listener, eight UDP and sixteen TCP workers.
    assert!(threads <= 26, "unexpected worker count {threads}");
    let q = query("capacity.test", 1, 8);
    assert_eq!(udp(daemon.address, &q), response(&q, 1));
    assert!(daemon.terminate("-TERM") < Duration::from_secs(3));
    drop(clients);
    assert!(daemon.logs.lock().unwrap().contains("shutdown complete"));
}

#[test]
fn shutdown_interrupts_pending_upstreams_and_partial_tcp_clients() {
    for signal in ["-TERM", "-INT"] {
        let silent = Mock::new(|_, _| vec![]);
        let mut daemon = Daemon::start(&[silent.address], &[]);
        let mut stream = tcp(daemon.address);
        stream.write_all(&[0]).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .send_to(&query("pending.test", 1, 5), daemon.address)
            .unwrap();
        let started = Instant::now();
        while silent.seen.lock().unwrap().is_empty() {
            assert!(started.elapsed() < WAIT);
            thread::sleep(Duration::from_millis(10));
        }
        assert!(daemon.terminate(signal) < Duration::from_secs(3));
    }
}

#[test]
fn idle_listeners_shutdown_without_client_traffic() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for signal in ["-TERM", "-INT"] {
            let mock = Mock::on(bind, |q, _| vec![response(q, 1)]);
            let mut daemon = Daemon::start_on(bind, &[mock.address], &[]);
            // Allow several receive timeouts while accept has no connections.
            thread::sleep(Duration::from_millis(350));
            assert!(daemon.terminate(signal) < Duration::from_secs(1));
            assert!(mock.seen.lock().unwrap().is_empty());
            let logs = daemon.logs.lock().unwrap();
            assert!(logs.contains("shutdown complete"));
            assert!(!logs.contains("WARN"), "{logs}");
            assert!(!logs.contains("ERROR"), "{logs}");
        }
    }
}

#[test]
fn idle_tcp_clients_do_not_block_shutdown_or_udp_after_receive_timeouts() {
    for signal in ["-TERM", "-INT"] {
        let mock = Mock::new(|q, _| vec![response(q, 1)]);
        let mut daemon = Daemon::start(&[mock.address], &[]);
        // Both listeners must still work after multiple idle receive timeouts.
        thread::sleep(Duration::from_millis(350));
        let mut stream = tcp(daemon.address);
        let q = query("after-idle.test", 1, 7);
        stream.write_all(&frame(&q)).unwrap();
        assert_eq!(read_frame(&mut stream), response(&q, 1));
        assert_eq!(udp(daemon.address, &q), response(&q, 1));
        // Keep the established connection idle during termination.
        assert!(daemon.terminate(signal) < Duration::from_secs(1));
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        let logs = daemon.logs.lock().unwrap();
        assert!(logs.contains("shutdown complete"));
        assert!(!logs.contains("WARN"), "{logs}");
    }
}

#[test]
fn cli_and_startup_diagnostics() {
    let binary = env!("CARGO_BIN_EXE_sederial");
    for flag in ["--help", "--version"] {
        assert!(
            Command::new(binary)
                .arg(flag)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    for args in [
        vec!["--unknown"],
        vec!["--config"],
        vec!["--config", "/nonexistent/sederial.toml"],
    ] {
        let output = Command::new(binary).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr).unwrap().contains("ERROR"));
    }
    let output = Command::new(binary)
        .args(["--config", "packaging/sederial.toml", "--check"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
