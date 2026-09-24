//! DNS over TCP framing with absolute deadlines (including partial I/O).
//!
//! Socket timeouts provide cancellation checkpoints. The same absolute deadline
//! remains in force across partial reads/writes and both parts of a frame.
use crate::dns::{HEADER_LENGTH, MAX_MESSAGE_LENGTH};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Maximum socket-poll interval between cancellation checks during frame I/O.
pub(crate) const IO_POLL: Duration = Duration::from_millis(100);

/// Client transport, determining UDP size limits and the initial upstream protocol.
#[derive(Clone, Copy)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

/// An absolute time budget; copying it does not restart or extend the budget.
#[derive(Clone, Copy)]
pub(crate) struct Deadline(Instant);
impl Deadline {
    pub(crate) fn after(duration: Duration) -> Self {
        Self(Instant::now() + duration)
    }
    /// Returns the positive remaining budget after checking cancellation.
    ///
    /// # Errors
    /// Returns `Interrupted` when shutdown is requested, or `TimedOut` when the
    /// budget is exhausted. Cancellation takes precedence over expiry.
    pub(crate) fn remaining(self, stop: &AtomicBool) -> io::Result<Duration> {
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "shutdown requested",
            ));
        }
        self.0
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "exchange deadline expired"))
    }
}

/// Identifies socket outcomes that permit retry after rechecking stop/deadline.
///
/// This classifies individual I/O calls, not errors from [`Deadline::remaining`],
/// which must propagate to end the enclosing operation.
pub(crate) fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Fills a field while retaining partial progress across socket timeout polls.
///
/// `false` means EOF before any bytes of this field; EOF after partial progress
/// is an error. The frame reader decides whether a clean field EOF is allowed.
fn read_exact(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Deadline,
    stop: &AtomicBool,
) -> io::Result<bool> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream.set_read_timeout(Some(deadline.remaining(stop)?.min(IO_POLL)))?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial TCP frame",
                ));
            }
            Ok(count) => offset += count,
            Err(error) if transient(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// Reads one length-prefixed DNS message, leaving subsequent frames in the stream.
///
/// `Ok(None)` means EOF before a new frame's prefix. The prefix and body consume
/// one shared deadline, preventing slow partial input from extending the budget.
///
/// # Errors
/// Returns errors for short frames, partial EOF, cancellation, expiry or socket
/// failure. DNS contents are validated separately at the protocol boundary.
pub(crate) fn read_frame(
    stream: &mut TcpStream,
    deadline: Deadline,
    stop: &AtomicBool,
) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0; 2];
    if !read_exact(stream, &mut prefix, deadline, stop)? {
        return Ok(None);
    }
    let length = usize::from(u16::from_be_bytes(prefix));
    if length < HEADER_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP DNS frame shorter than header",
        ));
    }
    let mut wire = vec![0; length];
    if !read_exact(stream, &mut wire, deadline, stop)? {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing TCP frame body",
        ));
    }
    Ok(Some(wire))
}

/// Writes a complete DNS frame under one deadline, including partial writes.
///
/// # Errors
/// Rejects lengths outside the DNS header/message bounds and propagates
/// cancellation, timeout or socket errors. An error may follow a partial write;
/// the caller must discard the stream rather than restart the frame on it.
pub(crate) fn write_frame(
    stream: &mut TcpStream,
    wire: &[u8],
    deadline: Deadline,
    stop: &AtomicBool,
) -> io::Result<()> {
    if !(HEADER_LENGTH..=MAX_MESSAGE_LENGTH).contains(&wire.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TCP DNS frame length",
        ));
    }
    let mut frame = Vec::with_capacity(wire.len() + 2);
    frame.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    frame.extend_from_slice(wire);
    let mut offset = 0;
    while offset < frame.len() {
        stream.set_write_timeout(Some(deadline.remaining(stop)?.min(IO_POLL)))?;
        match stream.write(&frame[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TCP write returned zero",
                ));
            }
            Ok(count) => offset += count,
            Err(error) if transient(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    #[test]
    fn framing_retains_partial_prefix_across_read_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[0]).unwrap();
            thread::sleep(IO_POLL * 2);
            stream.write_all(&[12]).unwrap();
            stream.write_all(&[0; HEADER_LENGTH]).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        let frame = read_frame(
            &mut client,
            Deadline::after(Duration::from_secs(2)),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(frame, Some(vec![0; HEADER_LENGTH]));
        peer.join().unwrap();
    }

    #[test]
    fn framing_deadline_is_absolute_despite_partial_progress() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in [0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let mut client = TcpStream::connect(address).unwrap();
        let start = Instant::now();
        let error = read_frame(
            &mut client,
            Deadline::after(Duration::from_millis(90)),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_millis(250));
        drop(client);
        peer.join().unwrap();
    }
}
