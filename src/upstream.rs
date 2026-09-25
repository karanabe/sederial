//! Correlated resolver exchanges with bounded failover and TCP connection reuse.
//!
//! The caller chooses the eligible upstream group. This module tries only that
//! group and returns a complete validated response with the upstream ID still
//! attached; the request handler restores the client ID and applies size limits.

use crate::{
    dns::{
        MAX_MESSAGE_LENGTH, Packet, ParseError, Query, Response, ResponseCode, SentQuery,
        ServerCookieRetry, TransactionId,
    },
    logging,
    routing::{UpstreamAddress, UpstreamGroup},
    transport::{self, Deadline, IO_POLL, Transport},
};
use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read},
    net::{TcpStream, UdpSocket},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_INVALID_RESPONSES: usize = 64;
const TCP_REUSE_IDLE: Duration = Duration::from_secs(2);

/// A stream retained only after a complete, correlated TCP exchange.
struct CachedConnection {
    address: UpstreamAddress,
    stream: TcpStream,
    last_used: Instant,
}

/// One attempt keeps its query, rewritten ID and deadline across UDP/TCP fallback.
struct Exchange<'a> {
    sent: SentQuery,
    deadline: Deadline,
    stop: &'a AtomicBool,
}

/// Each worker owns its entropy handle and at most one reusable upstream stream.
pub(crate) struct Forwarder {
    entropy: File,
    tcp: Option<CachedConnection>,
}
impl Forwarder {
    /// Opens the OS entropy source for this worker's transaction IDs.
    ///
    /// # Errors
    /// Returns an I/O error if `/dev/urandom` cannot be opened.
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            entropy: File::open("/dev/urandom")?,
            tcp: None,
        })
    }

    /// Drops an expired cached stream when called; expiry has no background timer.
    pub(crate) fn expire_idle(&mut self) {
        if self
            .tcp
            .as_ref()
            .is_some_and(|connection| connection.last_used.elapsed() >= TCP_REUSE_IDLE)
        {
            self.tcp = None;
        }
    }

    /// Tries selected endpoints in order with fresh IDs and capped attempt budgets.
    ///
    /// UDP truncation, a DNS Cookie retry, and one retry of a reused TCP stream
    /// share the current endpoint's deadline. SERVFAIL, REFUSED and exchange
    /// errors permit failover inside this group. BADCOOKIE retries the same
    /// server with its new server cookie, then over TCP (RFC 7873 §5.3).
    /// NOERROR, NXDOMAIN and every other correlated response are final.
    ///
    /// # Errors
    /// Returns the last failure when the group is exhausted. Cancellation or
    /// failure to obtain a transaction ID aborts without trying further servers.
    pub(crate) fn forward(
        &mut self,
        query: &Query<'_>,
        upstreams: &UpstreamGroup,
        transport: Transport,
        stop: &AtomicBool,
        request_deadline: Deadline,
    ) -> Result<Response, ForwardError> {
        let mut last_error = ForwardError::Timeout;
        // Retain the latest validated DNS failure, including its opaque EDE.
        // Later transport failures do not replace a DNS response.
        let mut relayed_failure = None;
        for address in upstreams.servers() {
            let deadline = request_deadline.capped(ATTEMPT_TIMEOUT);
            deadline.remaining(stop).map_err(ForwardError::from)?;
            let id = self.next_transaction_id()?;
            let exchange = Exchange {
                sent: query.sent(id),
                deadline,
                stop,
            };
            let result = match transport {
                Transport::Tcp => self.tcp_exchange(*address, &exchange),
                Transport::Udp => self.udp_exchange(*address, &exchange),
            };
            let response = match result {
                Ok(response) if response.response_code() == ResponseCode::BadCookie => {
                    match self.finish_badcookie(*address, &exchange, response, transport) {
                        Ok(response) => response,
                        Err(ForwardError::Cancelled) => return Err(ForwardError::Cancelled),
                        Err(error) => {
                            last_error = error;
                            logging::warn(format_args!("upstream {address}: {last_error}"));
                            continue;
                        }
                    }
                }
                Ok(response) => response,
                Err(ForwardError::Cancelled) => return Err(ForwardError::Cancelled),
                Err(error) => {
                    last_error = error;
                    logging::warn(format_args!("upstream {address}: {last_error}"));
                    continue;
                }
            };
            // A BADCOOKIE here already finished the cookie retry. SERVFAIL and
            // REFUSED, including those from that retry, still advance.
            request_deadline.remaining(stop)?;
            let code = response.response_code();
            if code == ResponseCode::BadCookie || !retries_in_group(code) {
                return Ok(response);
            }
            last_error = ForwardError::from_rcode(code);
            relayed_failure = Some(response);
            logging::warn(format_args!("upstream {address}: {last_error}"));
        }
        request_deadline.remaining(stop)?;
        relayed_failure.ok_or(last_error)
    }

    /// RFC 7873 §5.3: retry this server with the returned server cookie, and
    /// if that UDP retry is still BADCOOKIE, retry once over TCP. A cookie
    /// that does not match the one we sent is discarded. The returned packet
    /// is not necessarily final: SERVFAIL and REFUSED still fail over.
    fn finish_badcookie(
        &mut self,
        address: UpstreamAddress,
        exchange: &Exchange<'_>,
        response: Response,
        transport: Transport,
    ) -> Result<Response, ForwardError> {
        match exchange.sent.server_cookie_retry(&response) {
            ServerCookieRetry::Absent => Ok(response),
            ServerCookieRetry::Discard => Err(ForwardError::InvalidResponse),
            ServerCookieRetry::Current | ServerCookieRetry::Tcp
                if matches!(transport, Transport::Tcp) =>
            {
                Ok(response)
            }
            ServerCookieRetry::Current | ServerCookieRetry::Tcp => {
                let retry = self.retry_exchange(exchange, exchange.sent.wire().to_vec())?;
                self.tcp_exchange(address, &retry)
            }
            ServerCookieRetry::Rewrite(wire) => {
                let retry = self.retry_exchange(exchange, wire)?;
                let retried = match transport {
                    Transport::Tcp => self.tcp_exchange(address, &retry)?,
                    Transport::Udp => self.udp_exchange(address, &retry)?,
                };
                if retried.response_code() != ResponseCode::BadCookie
                    || matches!(transport, Transport::Tcp)
                {
                    return Ok(retried);
                }
                let wire = match retry.sent.server_cookie_retry(&retried) {
                    ServerCookieRetry::Rewrite(wire) => wire,
                    ServerCookieRetry::Current | ServerCookieRetry::Tcp => {
                        retry.sent.wire().to_vec()
                    }
                    ServerCookieRetry::Absent | ServerCookieRetry::Discard => {
                        return Err(ForwardError::InvalidResponse);
                    }
                };
                let retry = self.retry_exchange(&retry, wire)?;
                self.tcp_exchange(address, &retry)
            }
        }
    }

    fn retry_exchange<'a>(
        &mut self,
        exchange: &Exchange<'a>,
        wire: Vec<u8>,
    ) -> Result<Exchange<'a>, ForwardError> {
        exchange.deadline.remaining(exchange.stop)?;
        Ok(Exchange {
            sent: exchange
                .sent
                .retry(wire, self.next_transaction_id()?)
                .map_err(ForwardError::Parse)?,
            deadline: exchange.deadline,
            stop: exchange.stop,
        })
    }

    fn next_transaction_id(&mut self) -> io::Result<TransactionId> {
        let mut bytes = [0; 2];
        self.entropy.read_exact(&mut bytes)?;
        Ok(TransactionId(u16::from_ne_bytes(bytes)))
    }

    /// Uses a fresh connected UDP socket, ignoring bounded invalid responses.
    fn udp_exchange(
        &mut self,
        address: UpstreamAddress,
        exchange: &Exchange<'_>,
    ) -> Result<Response, ForwardError> {
        let bind = if address.socket().is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(address.socket())?; // Kernel filters unexpected source address and port.
        socket.set_write_timeout(Some(exchange.deadline.remaining(exchange.stop)?))?;
        socket.send(exchange.sent.wire())?;
        let mut bytes = vec![0; MAX_MESSAGE_LENGTH];
        let mut invalid_responses = 0;
        loop {
            socket.set_read_timeout(Some(
                exchange.deadline.remaining(exchange.stop)?.min(IO_POLL),
            ))?;
            let length = match socket.recv(&mut bytes) {
                Ok(length) => length,
                Err(error) if transport::transient(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            exchange.deadline.remaining(exchange.stop)?;
            // Check the complete header/question before parsing records: TC can
            // legitimately accompany a datagram cut in the middle of a record.
            if exchange.sent.matches_truncated(&bytes[..length]) {
                return self.tcp_exchange(address, exchange);
            }
            match Packet::parse(&bytes[..length])
                .ok()
                .and_then(|response| exchange.sent.validate_response(response))
            {
                Some(response) => {
                    return Ok(response);
                }
                _ => {
                    invalid_responses += 1;
                    if invalid_responses == MAX_INVALID_RESPONSES {
                        return Err(ForwardError::InvalidResponse);
                    }
                    if invalid_responses == 1 {
                        logging::warn(format_args!(
                            "upstream {address}: ignored uncorrelated or malformed UDP response"
                        ));
                    }
                }
            }
        }
    }

    /// Reuses only a matching, unexpired stream and caches only successful exchanges.
    fn tcp_exchange(
        &mut self,
        address: UpstreamAddress,
        exchange: &Exchange<'_>,
    ) -> Result<Response, ForwardError> {
        self.expire_idle();
        // Taking ownership removes the cache entry before any fallible I/O.
        // Failed, partial or mismatched exchanges therefore cannot leave a
        // potentially desynchronized stream available to a later request.
        let cached = self
            .tcp
            .take()
            .filter(|connection| connection.address == address);
        let reused = cached.is_some();
        let mut stream = match cached {
            Some(connection) => connection.stream,
            None => TcpStream::connect_timeout(
                &address.socket(),
                exchange.deadline.remaining(exchange.stop)?,
            )?,
        };
        stream.set_nodelay(true)?;
        let mut result = exchange.send_over_tcp(&mut stream);
        // A peer may close an idle reused connection. Reconnect once within the same deadline.
        if reused && result.is_err() {
            stream = TcpStream::connect_timeout(
                &address.socket(),
                exchange.deadline.remaining(exchange.stop)?,
            )?;
            stream.set_nodelay(true)?;
            result = exchange.send_over_tcp(&mut stream);
        }
        if result.is_ok() {
            self.tcp = Some(CachedConnection {
                address,
                stream,
                last_used: Instant::now(),
            });
        }
        result
    }
}

impl Exchange<'_> {
    /// Sends one frame and accepts exactly one complete, correlated TCP response.
    fn send_over_tcp(&self, stream: &mut TcpStream) -> Result<Response, ForwardError> {
        transport::write_frame(stream, self.sent.wire(), self.deadline, self.stop)?;
        let bytes = transport::read_frame(stream, self.deadline, self.stop)?
            .ok_or(ForwardError::InvalidResponse)?;
        self.deadline.remaining(self.stop)?;
        let response = Packet::parse(&bytes).map_err(ForwardError::Parse)?;
        self.sent
            .validate_response(response)
            .ok_or(ForwardError::InvalidResponse)
    }
}

/// Exchange failures used for failover decisions and metadata-only diagnostics.
#[derive(Debug)]
pub(crate) enum ForwardError {
    Timeout,
    Cancelled,
    Io(io::Error),
    Parse(ParseError),
    InvalidResponse,
    ServerFailure,
    Refused,
}
impl From<io::Error> for ForwardError {
    fn from(error: io::Error) -> Self {
        if error
            .get_ref()
            .is_some_and(|source| source.is::<transport::Cancelled>())
        {
            Self::Cancelled
        } else if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            Self::Timeout
        } else {
            Self::Io(error)
        }
    }
}
impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("exchange timed out"),
            Self::Cancelled => f.write_str("shutdown requested"),
            Self::Io(e) => e.fmt(f),
            Self::Parse(e) => e.fmt(f),
            Self::InvalidResponse => f.write_str("invalid or uncorrelated response"),
            Self::ServerFailure => f.write_str("upstream returned SERVFAIL"),
            Self::Refused => f.write_str("upstream returned REFUSED"),
        }
    }
}

/// NOERROR and NXDOMAIN describe the name and stop the walk. SERVFAIL and
/// REFUSED describe this server and are tried against the next one.
fn retries_in_group(code: ResponseCode) -> bool {
    matches!(code, ResponseCode::ServerFailure | ResponseCode::Refused)
}

impl ForwardError {
    fn from_rcode(code: ResponseCode) -> Self {
        match code {
            ResponseCode::Refused => Self::Refused,
            _ => Self::ServerFailure,
        }
    }
}
impl Error for ForwardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Parse(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        net::TcpListener,
        sync::{Arc, mpsc},
        thread,
    };
    const QUERY: &[u8] =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01";
    const BUDGET: Duration = Duration::from_millis(150);
    const GUARD: Duration = Duration::from_secs(2);

    fn group(sockets: &[&UdpSocket]) -> UpstreamGroup {
        UpstreamGroup::new(
            sockets
                .iter()
                .map(|s| UpstreamAddress::new(s.local_addr().unwrap()).unwrap())
                .collect(),
        )
        .unwrap()
    }
    fn receive(socket: &UdpSocket) -> (Vec<u8>, std::net::SocketAddr) {
        socket.set_read_timeout(Some(GUARD)).unwrap();
        let mut bytes = vec![0; 1024];
        let (len, peer) = socket.recv_from(&mut bytes).unwrap();
        bytes.truncate(len);
        (bytes, peer)
    }
    fn untouched(socket: &UdpSocket) {
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv(&mut [0; 1024]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    fn accept(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let until = Instant::now() + GUARD;
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                    thread::sleep(Duration::from_millis(10))
                }
                other => panic!("missing TCP fallback: {other:?}"),
            }
        }
    }

    #[test]
    fn request_budget_bounds_failover_and_shutdown_never_contacts_next_server() {
        for cancel in [false, true] {
            let first = UdpSocket::bind("127.0.0.1:0").unwrap();
            let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
            let never = UdpSocket::bind("127.0.0.1:0").unwrap();
            let upstreams = group(&[&first, &silent, &never]);
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = Arc::clone(&stop);
            let peer = thread::spawn(move || {
                let (mut q, source) = receive(&first);
                q[2] |= 0x80;
                q[3] = 0x85;
                if cancel {
                    stopping.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                first.send_to(&q, source).unwrap();
            });
            let packet = Packet::parse(QUERY).unwrap();
            let crate::dns::QueryDecision::Forward(query) = packet.validate_query() else {
                panic!()
            };
            let result = Forwarder::new().unwrap().forward(
                &query,
                &upstreams,
                Transport::Udp,
                &stop,
                Deadline::after(BUDGET),
            );
            if cancel {
                assert!(matches!(result, Err(ForwardError::Cancelled)));
                untouched(&silent);
            } else {
                assert!(matches!(result, Err(ForwardError::Timeout)));
                receive(&silent);
            }
            untouched(&never);
            peer.join().unwrap();
        }
    }

    #[test]
    fn tc_cookie_and_reused_tcp_share_the_original_request_budget() {
        for mode in ["tc", "cookie", "reconnect"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let udp = UdpSocket::bind(listener.local_addr().unwrap()).unwrap();
            let never = UdpSocket::bind("127.0.0.1:0").unwrap();
            let upstreams = group(&[&udp, &never]);
            let mut wire = QUERY.to_vec();
            if mode == "cookie" {
                wire[11] = 1;
                wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8]);
                wire.extend_from_slice(&[7; 8]);
            }
            let mut forwarder = Forwarder::new().unwrap();
            if mode == "reconnect" {
                let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let peer = accept(&listener);
                drop(peer);
                forwarder.tcp = Some(CachedConnection {
                    address: upstreams.servers()[0],
                    stream,
                    last_used: Instant::now(),
                });
            }
            let (release, released) = mpsc::channel::<()>();
            let peer = thread::spawn(move || {
                if mode != "reconnect" {
                    let (mut q, source) = receive(&udp);
                    q[2] |= 0x80;
                    if mode == "cookie" {
                        let opt = QUERY.len();
                        q[3] = 0x87;
                        q[opt + 5] = 1;
                        q[opt + 10] = 20;
                        q[opt + 14] = 16;
                        q.extend_from_slice(&[9; 8]);
                        udp.send_to(&q, source).unwrap();
                        let (mut retry, source) = receive(&udp);
                        retry[2] |= 0x80;
                        retry[3] = 0x87;
                        retry[opt + 5] = 1;
                        udp.send_to(&retry, source).unwrap();
                    } else {
                        q[2] |= 2;
                        q[7] = 1;
                        q.push(0xc0);
                        udp.send_to(&q, source).unwrap();
                    }
                }
                let mut stream = accept(&listener);
                let received = transport::read_frame(
                    &mut stream,
                    Deadline::after(GUARD),
                    &AtomicBool::new(false),
                )
                .unwrap();
                assert!(received.is_some());
                let _ = released.recv_timeout(GUARD);
                // Hold the connection until the caller's original deadline ends.
                let _ = stream.write_all(&[]);
            });
            let packet = Packet::parse(&wire).unwrap();
            let crate::dns::QueryDecision::Forward(query) = packet.validate_query() else {
                panic!()
            };
            let started = Instant::now();
            let result = forwarder.forward(
                &query,
                &upstreams,
                if mode == "reconnect" {
                    Transport::Tcp
                } else {
                    Transport::Udp
                },
                &AtomicBool::new(false),
                Deadline::after(BUDGET),
            );
            drop(release);
            assert!(
                matches!(result, Err(ForwardError::Timeout)),
                "{mode}: {result:?}"
            );
            assert!(started.elapsed() < GUARD); // Guard only; no tight scheduler threshold.
            untouched(&never);
            peer.join().unwrap();
        }
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn cancellation_is_distinct_from_an_interrupted_io_call() {
        assert!(matches!(
            ForwardError::from(io::Error::new(io::ErrorKind::Interrupted, "OS interrupt")),
            ForwardError::Io(_)
        ));
        let cancelled = Deadline::after(Duration::from_secs(1))
            .remaining(&AtomicBool::new(true))
            .unwrap_err();
        assert!(matches!(
            ForwardError::from(cancelled),
            ForwardError::Cancelled
        ));
        let timeout = Deadline::after(Duration::ZERO)
            .remaining(&AtomicBool::new(false))
            .unwrap_err();
        assert!(matches!(ForwardError::from(timeout), ForwardError::Timeout));
    }
}
