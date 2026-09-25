//! Client listeners, transport-specific workers and coordinated service shutdown.
//!
//! UDP datagrams and TCP connections have separate bounded pools. A slow TCP
//! client therefore cannot consume the capacity reserved for UDP requests.

mod pool;

use crate::{
    config::Config,
    dns::MAX_MESSAGE_LENGTH,
    forwarding::RequestHandler,
    logging,
    routing::RoutingTable,
    transport::{self, Deadline, IO_POLL, REQUEST_TIMEOUT, Transport},
};
use pool::{Pool, Worker};
use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const UDP_WORKERS: usize = 8;
const TCP_WORKERS: usize = 16;
const UDP_QUEUE: usize = 64;
const TCP_QUEUE: usize = 16;
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Owned packet bytes and the endpoint to which its reply must be sent.
struct Datagram {
    wire: Vec<u8>,
    peer: SocketAddr,
    deadline: Deadline,
}
/// An accepted stream whose first-frame budget already includes queue time.
struct Connection {
    stream: TcpStream,
    first_deadline: Deadline,
}

/// Owns both listeners and the immutable routing policy shared by workers.
pub(crate) struct Server {
    routing: Arc<RoutingTable>,
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
}
impl Server {
    /// Binds UDP and TCP at the validated configured address without starting workers.
    ///
    /// # Errors
    /// Returns socket bind or timeout-configuration errors. If either protocol
    /// fails to initialize, the other socket is dropped before returning.
    pub(crate) fn bind(config: Config) -> io::Result<Self> {
        let listen = config.listen;
        let udp = UdpSocket::bind(listen)?;
        let tcp = TcpListener::bind(listen)?;
        udp.set_read_timeout(Some(IO_POLL))?;
        udp.set_write_timeout(Some(IO_POLL))?;
        Ok(Self {
            routing: Arc::new(config.routing),
            udp: Arc::new(udp),
            tcp,
        })
    }
    /// Serves both transports until shutdown is requested or a listener fails.
    ///
    /// Consumes the listeners and joins workers during normal shutdown. The wait
    /// for the TCP listener is bounded; a timeout is fatal and the caller must
    /// exit the process to reclaim a thread still blocked in `accept`.
    ///
    /// # Errors
    /// Returns worker initialization, thread creation, listener I/O or TCP
    /// listener shutdown errors. Individual request failures stay with workers.
    pub(crate) fn run(self, stop: Arc<AtomicBool>) -> io::Result<()> {
        // The flag carries no associated data. Channels transfer job ownership,
        // so reading or setting cancellation does not require acquire/release.
        let mut udp_pool = Pool::new(UDP_WORKERS, UDP_QUEUE, Arc::clone(&stop), "udp", || {
            Ok(UdpWorker {
                handler: RequestHandler::new(Arc::clone(&self.routing), Arc::clone(&stop))?,
                socket: Arc::clone(&self.udp),
            })
        })?;
        let mut tcp_pool = Pool::new(TCP_WORKERS, TCP_QUEUE, Arc::clone(&stop), "tcp", || {
            Ok(TcpWorker {
                handler: RequestHandler::new(Arc::clone(&self.routing), Arc::clone(&stop))?,
                stop: Arc::clone(&stop),
            })
        })?;
        let listener = self.tcp;
        let address = listener.local_addr()?;
        let shutdown = Arc::clone(&stop);
        let (finished, completion) = mpsc::sync_channel(1);
        let tcp_thread = thread::Builder::new()
            .name("tcp-listener".into())
            .spawn(move || {
                let result = accept_tcp(&listener, &shutdown, &tcp_pool);
                shutdown.store(true, Ordering::Relaxed);
                let workers = tcp_pool.shutdown(Instant::now() + LISTENER_SHUTDOWN_TIMEOUT);
                // Completion includes worker teardown, not just leaving accept.
                let _ = finished.send(());
                result.and(workers)
            })?;
        logging::info(format_args!(
            "startup: listening on {} (UDP and TCP)",
            address
        ));
        let result = receive_udp(&self.udp, &stop, &udp_pool);
        stop.store(true, Ordering::Relaxed);
        logging::info(format_args!("shutdown: stopping listeners and workers"));
        let shutdown_deadline = Instant::now() + LISTENER_SHUTDOWN_TIMEOUT;
        // std has no accept timeout. A local connection wakes blocking accept;
        // the stop check after accept prevents it from entering the worker queue.
        let wake = TcpStream::connect_timeout(&address, IO_POLL).map(drop);
        let udp_workers = udp_pool.shutdown(shutdown_deadline);
        let tcp_result = match completion
            .recv_timeout(shutdown_deadline.saturating_duration_since(Instant::now()))
        {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => tcp_thread
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("TCP listener terminated unexpectedly"))),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // A failed local wake (e.g. host firewall rules) must not hang
                // shutdown. Returning this fatal error exits the binary and
                // lets the OS reclaim a listener that could not be joined.
                let detail = match wake {
                    Ok(()) => "local wake connection succeeded".to_owned(),
                    Err(error) => format!("local wake connection failed: {error}"),
                };
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("TCP listener shutdown timed out: {detail}"),
                ))
            }
        };
        if tcp_result.is_ok() {
            logging::info(format_args!("shutdown complete"));
        }
        result.and(udp_workers).and(tcp_result)
    }
}

/// Receives datagrams and drops overflow immediately rather than blocking intake.
fn receive_udp(udp: &UdpSocket, stop: &AtomicBool, pool: &Pool<UdpWorker>) -> io::Result<()> {
    let mut buffer = vec![0; MAX_MESSAGE_LENGTH];
    while !stop.load(Ordering::Relaxed) {
        match udp.recv_from(&mut buffer) {
            Ok((length, peer)) => {
                let deadline = Deadline::after(REQUEST_TIMEOUT);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if !pool.submit(Datagram {
                    wire: buffer[..length].to_vec(),
                    peer,
                    deadline,
                }) {
                    logging::warn(format_args!("UDP capacity reached; dropping packet"));
                }
            }
            Err(error) if transport::transient(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Accepts connections, closing overflow and the local shutdown wake connection.
fn accept_tcp(tcp: &TcpListener, stop: &AtomicBool, pool: &Pool<TcpWorker>) -> io::Result<()> {
    accept_clients(
        || tcp.accept(),
        stop,
        |stream| {
            // Start the first-frame budget at acceptance; waiting for a
            // worker must not grant an idle client a fresh timeout.
            pool.submit(Connection {
                stream,
                first_deadline: Deadline::after(CLIENT_FRAME_TIMEOUT),
            })
        },
    )
}

/// Drains handshake failures without treating them as a dead listening socket.
///
/// Linux `accept(2)` returns pending errors of the new connection from `accept`
/// itself. Retrying them keeps the process up. `transport::transient` stays
/// narrower because upstream reads must fail over instead of spinning.
fn accept_clients(
    mut accept: impl FnMut() -> io::Result<(TcpStream, SocketAddr)>,
    stop: &AtomicBool,
    mut enqueue: impl FnMut(TcpStream) -> bool,
) -> io::Result<()> {
    while !stop.load(Ordering::Relaxed) {
        match accept() {
            Ok((stream, _)) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if !enqueue(stream) {
                    logging::warn(format_args!("TCP capacity reached; closing connection"));
                }
            }
            Err(error) if accept_error_is_retryable(&error) => {
                logging::warn(format_args!(
                    "TCP accept ignored a failed handshake: {error}"
                ));
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn accept_error_is_retryable(error: &io::Error) -> bool {
    if transport::transient(error) {
        return true;
    }
    match error.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable => true,
        // Several of the errnos named by accept(2) have no ErrorKind yet.
        _ => linux_accept_error_is_retryable(error.raw_os_error()),
    }
}

/// Linux pending network errors without portable ErrorKind equivalents.
fn linux_accept_error_is_retryable(errno: Option<i32>) -> bool {
    const ENONET: i32 = 64;
    const EPROTO: i32 = 71;
    const ENOPROTOOPT: i32 = 92;
    const EOPNOTSUPP: i32 = 95;
    const ENETDOWN: i32 = 100;
    const ENETUNREACH: i32 = 101;
    const ECONNABORTED: i32 = 103;
    const ECONNRESET: i32 = 104;
    const EHOSTDOWN: i32 = 112;
    const EHOSTUNREACH: i32 = 113;
    matches!(
        errno,
        Some(
            ENONET
                | EPROTO
                | ENOPROTOOPT
                | EOPNOTSUPP
                | ENETDOWN
                | ENETUNREACH
                | ECONNABORTED
                | ECONNRESET
                | EHOSTDOWN
                | EHOSTUNREACH
        )
    )
}

/// Processes a connection's frames in order until EOF, cancellation or I/O error.
///
/// Pipelined frames remain ordered. Each complete exchange starts a new budget
/// for the next frame; partial reads never extend the current frame's deadline.
fn serve_tcp(
    mut client: Connection,
    handler: &mut RequestHandler,
    stop: &AtomicBool,
) -> io::Result<()> {
    client.stream.set_nonblocking(false)?;
    client.stream.set_nodelay(true)?;
    let mut deadline = client.first_deadline;
    while !stop.load(Ordering::Relaxed) {
        let Some(wire) = transport::read_frame(&mut client.stream, deadline, stop)? else {
            break;
        };
        let request_deadline = Deadline::after(REQUEST_TIMEOUT);
        if let Some(response) = handler.respond(&wire, Transport::Tcp, request_deadline) {
            transport::write_frame(
                &mut client.stream,
                &response,
                request_deadline.capped(CLIENT_WRITE_TIMEOUT),
                stop,
            )?;
        }
        deadline = Deadline::after(CLIENT_FRAME_TIMEOUT);
    }
    Ok(())
}

/// Owns exchange state while sharing the socket used for UDP intake and replies.
struct UdpWorker {
    handler: RequestHandler,
    socket: Arc<UdpSocket>,
}

impl Worker for UdpWorker {
    type Job = Datagram;

    fn handle(&mut self, job: Datagram) {
        if let Some(wire) = self
            .handler
            .respond(&job.wire, Transport::Udp, job.deadline)
            && let Err(error) = self.socket.send_to(&wire, job.peer)
        {
            logging::warn(format_args!("UDP client response failed: {error}"));
        }
    }

    fn maintain(&mut self) {
        self.handler.expire_idle();
    }
}

/// Holds one connection for its full framed session before accepting another job.
struct TcpWorker {
    handler: RequestHandler,
    stop: Arc<AtomicBool>,
}

impl Worker for TcpWorker {
    type Job = Connection;

    fn handle(&mut self, job: Connection) {
        if let Err(error) = serve_tcp(job, &mut self.handler, &self.stop)
            && !self.stop.load(Ordering::Relaxed)
            && error.kind() != io::ErrorKind::TimedOut
        {
            logging::warn(format_args!("TCP client connection failed: {error}"));
        }
    }

    fn maintain(&mut self) {
        self.handler.expire_idle();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_connection_accept_errors_do_not_stop_the_listener() {
        let stop = AtomicBool::new(false);
        let mut calls = 0;
        let error = accept_clients(
            || {
                calls += 1;
                Err(match calls {
                    1 => io::Error::new(io::ErrorKind::ConnectionAborted, "reset"),
                    2 => io::Error::new(io::ErrorKind::HostUnreachable, "unreachable"),
                    3 => io::Error::from_raw_os_error(71), // EPROTO, often Uncategorized
                    _ => io::Error::new(io::ErrorKind::InvalidInput, "listener"),
                })
            },
            &stop,
            |_| true,
        )
        .unwrap_err();
        assert_eq!(calls, 4);
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn extended_accept_errnos_are_retryable() {
        for code in [64, 71, 92, 95, 100, 101, 103, 104, 112, 113] {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                accept_error_is_retryable(&error),
                "{code} {:?}",
                error.kind()
            );
        }
        let fatal = io::Error::new(io::ErrorKind::InvalidInput, "closed");
        assert!(!accept_error_is_retryable(&fatal));
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::sync::mpsc;
    struct GatedWorker {
        inner: UdpWorker,
        gate: Option<mpsc::Receiver<()>>,
        entered: mpsc::Sender<()>,
        finished: mpsc::Sender<()>,
    }
    impl Worker for GatedWorker {
        type Job = Datagram;
        fn maintain(&mut self) {
            if let Some(gate) = self.gate.take() {
                self.entered.send(()).unwrap();
                gate.recv_timeout(Duration::from_secs(2)).unwrap();
            }
        }
        fn handle(&mut self, job: Datagram) {
            self.inner.handle(job);
            self.finished.send(()).unwrap();
        }
    }
    #[test]
    fn expired_udp_job_waiting_in_queue_never_reaches_any_upstream() {
        use crate::routing::{Route, UpstreamAddress, UpstreamGroup};
        let private = UdpSocket::bind("127.0.0.1:0").unwrap();
        let public = UdpSocket::bind("127.0.0.1:0").unwrap();
        let group = |s: &UdpSocket| {
            UpstreamGroup::new(vec![UpstreamAddress::new(s.local_addr().unwrap()).unwrap()])
                .unwrap()
        };
        let routing = RoutingTable::new(
            group(&public),
            vec![Route {
                suffix: "private.test".parse().unwrap(),
                upstreams: group(&private),
            }],
        )
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (release, gate) = mpsc::channel();
        let (entered, waiting) = mpsc::channel();
        let (finished, done) = mpsc::channel();
        let mut worker = Some(GatedWorker {
            inner: UdpWorker {
                handler: RequestHandler::new(Arc::new(routing), Arc::clone(&stop)).unwrap(),
                socket,
            },
            gate: Some(gate),
            entered,
            finished,
        });
        let mut pool = Pool::new(1, 1, stop, "queue-test", || Ok(worker.take().unwrap())).unwrap();
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(pool.submit(Datagram {
            wire: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07private\x04test\x00\x00\x01\x00\x01".to_vec(),
            peer: client.local_addr().unwrap(), deadline: Deadline::after(Duration::ZERO),
        }));
        release.send(()).unwrap();
        done.recv_timeout(Duration::from_secs(2)).unwrap();
        pool.shutdown(Instant::now() + Duration::from_secs(2))
            .unwrap();
        for socket in [&private, &public, &client] {
            socket.set_nonblocking(true).unwrap();
            assert_eq!(
                socket.recv(&mut [0; 512]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}
