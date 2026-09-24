//! Correlated resolver exchanges with bounded failover and TCP connection reuse.
//!
//! The caller chooses the eligible upstream group. This module tries only that
//! group and returns a complete validated response with the upstream ID still
//! attached; the request handler restores the client ID and applies size limits.

use crate::{
    dns::{MAX_MESSAGE_LENGTH, Packet, ParseError, Query, ResponseCode, TransactionId},
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
    query: &'a Query<'a>,
    id: TransactionId,
    wire: Vec<u8>,
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

    /// Tries the selected endpoints in order with a fresh ID and budget per endpoint.
    ///
    /// UDP truncation and one retry of a reused TCP stream share the current
    /// endpoint's deadline. SERVFAIL and exchange errors permit failover; other
    /// correlated response codes, including NXDOMAIN and REFUSED, are final.
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
    ) -> Result<Packet, ForwardError> {
        let mut last_error = ForwardError::Timeout;
        for address in upstreams.servers() {
            let deadline = Deadline::after(ATTEMPT_TIMEOUT);
            deadline.remaining(stop).map_err(ForwardError::from)?;
            let id = self.next_transaction_id()?;
            let exchange = Exchange {
                query,
                id,
                wire: query.with_id(id),
                deadline,
                stop,
            };
            let result = match transport {
                Transport::Tcp => self.tcp_exchange(*address, &exchange),
                Transport::Udp => self.udp_exchange(*address, &exchange),
            };
            match result {
                // Retry a soft server failure; a negative answer such as NXDOMAIN is final.
                Ok(response) if response.response_code() != ResponseCode::ServerFailure => {
                    return Ok(response);
                }
                Ok(_) => last_error = ForwardError::ServerFailure,
                Err(error) => last_error = error,
            }
            logging::warn(format_args!("upstream {address}: {last_error}"));
        }
        Err(last_error)
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
    ) -> Result<Packet, ForwardError> {
        let bind = if address.socket().is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(address.socket())?; // Kernel filters unexpected source address and port.
        socket.set_write_timeout(Some(exchange.deadline.remaining(exchange.stop)?))?;
        socket.send(&exchange.wire)?;
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
            // Check the complete header/question before parsing records: TC can
            // legitimately accompany a datagram cut in the middle of a record.
            if exchange
                .query
                .matches_truncated(&bytes[..length], exchange.id)
            {
                return self.tcp_exchange(address, exchange);
            }
            match Packet::parse(&bytes[..length]) {
                Ok(response) if response.corresponds_to(exchange.query, exchange.id) => {
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
    ) -> Result<Packet, ForwardError> {
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
    fn send_over_tcp(&self, stream: &mut TcpStream) -> Result<Packet, ForwardError> {
        transport::write_frame(stream, &self.wire, self.deadline, self.stop)?;
        let bytes = transport::read_frame(stream, self.deadline, self.stop)?
            .ok_or(ForwardError::InvalidResponse)?;
        let response = Packet::parse(&bytes).map_err(ForwardError::Parse)?;
        if !response.corresponds_to(self.query, self.id) || response.is_truncated() {
            return Err(ForwardError::InvalidResponse);
        }
        Ok(response)
    }
}

/// Exchange failures used for failover decisions and metadata-only diagnostics.
#[derive(Debug)]
pub(crate) enum ForwardError {
    Timeout,
    Io(io::Error),
    Parse(ParseError),
    InvalidResponse,
    ServerFailure,
}
impl From<io::Error> for ForwardError {
    fn from(error: io::Error) -> Self {
        if matches!(
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
            Self::Io(e) => e.fmt(f),
            Self::Parse(e) => e.fmt(f),
            Self::InvalidResponse => f.write_str("invalid or uncorrelated response"),
            Self::ServerFailure => f.write_str("upstream returned SERVFAIL"),
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
