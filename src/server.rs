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
    transport::{self, Deadline, IO_POLL, Transport},
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
        let udp = UdpSocket::bind(config.listen)?;
        let tcp = TcpListener::bind(config.listen)?;
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
        let udp_pool = Pool::new(UDP_WORKERS, UDP_QUEUE, Arc::clone(&stop), "udp", || {
            Ok(UdpWorker {
                handler: RequestHandler::new(Arc::clone(&self.routing), Arc::clone(&stop))?,
                socket: Arc::clone(&self.udp),
            })
        })?;
        let tcp_pool = Pool::new(TCP_WORKERS, TCP_QUEUE, Arc::clone(&stop), "tcp", || {
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
                drop(tcp_pool);
                // Completion includes worker teardown, not just leaving accept.
                let _ = finished.send(());
                result
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
        drop(udp_pool);
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
        result.and(tcp_result)
    }
}

/// Receives datagrams and drops overflow immediately rather than blocking intake.
fn receive_udp(udp: &UdpSocket, stop: &AtomicBool, pool: &Pool<UdpWorker>) -> io::Result<()> {
    let mut buffer = vec![0; MAX_MESSAGE_LENGTH];
    while !stop.load(Ordering::Relaxed) {
        match udp.recv_from(&mut buffer) {
            Ok((length, peer)) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if !pool.submit(Datagram {
                    wire: buffer[..length].to_vec(),
                    peer,
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
    while !stop.load(Ordering::Relaxed) {
        match tcp.accept() {
            Ok((stream, _)) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                // Start the first-frame budget at acceptance; waiting for a
                // worker must not grant an idle client a fresh timeout.
                if !pool.submit(Connection {
                    stream,
                    first_deadline: Deadline::after(CLIENT_FRAME_TIMEOUT),
                }) {
                    logging::warn(format_args!("TCP capacity reached; closing connection"));
                }
            }
            Err(error) if transport::transient(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
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
        if let Some(response) = handler.respond(&wire, Transport::Tcp) {
            transport::write_frame(
                &mut client.stream,
                &response,
                Deadline::after(CLIENT_WRITE_TIMEOUT),
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
        if let Some(wire) = self.handler.respond(&job.wire, Transport::Udp)
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
