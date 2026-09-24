#![allow(dead_code)]
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const WAIT: Duration = Duration::from_secs(5);
static NEXT: AtomicUsize = AtomicUsize::new(0);

// UDP's ephemeral allocator does not know which ports TCP has in TIME_WAIT.
// Reserve both protocols together before choosing a mock/daemon endpoint.
fn reserve_endpoint(bind: &str) -> (UdpSocket, TcpListener) {
    for _ in 0..64 {
        let tcp = TcpListener::bind(bind).unwrap();
        match UdpSocket::bind(tcp.local_addr().unwrap()) {
            Ok(udp) => return (udp, tcp),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("reserve test endpoint: {error}"),
        }
    }
    panic!("no test endpoint available for both UDP and TCP");
}

pub fn query(name: &str, kind: u16, id: u16) -> Vec<u8> {
    let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire[..2].copy_from_slice(&id.to_be_bytes());
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire.extend_from_slice(&kind.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire
}
pub fn question_end(wire: &[u8]) -> usize {
    let mut at = 12;
    while wire[at] != 0 {
        at += usize::from(wire[at]) + 1;
    }
    at + 5
}
pub fn response(query: &[u8], marker: u8) -> Vec<u8> {
    let end = question_end(query);
    let kind = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    let data = match kind {
        1 => vec![192, 0, 2, marker],
        28 => {
            let mut data = vec![0; 16];
            data[15] = marker;
            data
        }
        12 => b"\x04host\x04test\x00".to_vec(),
        33 => b"\x00\x00\x00\x64\x01\x85\x04dc01\x02ad\x03lab\x07exceeds\x04test\x00".to_vec(),
        _ => vec![marker],
    };
    let mut wire = query[..end].to_vec();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[7] = 1;
    wire.extend_from_slice(&[0xc0, 0x0c]);
    wire.extend_from_slice(&kind.to_be_bytes());
    wire.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
    wire.extend_from_slice(&data);
    wire.extend_from_slice(&query[end..]);
    wire
}
pub fn empty_response(query: &[u8], code: u8) -> Vec<u8> {
    let mut bytes = query.to_vec();
    bytes[2] |= 0x80;
    bytes[3] = 0x80 | code;
    bytes
}
pub fn large_response(query: &[u8], size: usize) -> Vec<u8> {
    let mut bytes = query[..question_end(query)].to_vec();
    bytes[2] |= 0x80;
    bytes[3] = 0x80;
    bytes[7] = 1;
    // Unknown RR type with opaque RDATA, independently constructed.
    bytes.extend_from_slice(&[0xc0, 0x0c, 0xfd, 0xe8, 0, 1, 0, 0, 0, 60]);
    bytes.extend_from_slice(&(size as u16).to_be_bytes());
    bytes.resize(bytes.len() + size, 42);
    bytes.extend_from_slice(&query[question_end(query)..]);
    bytes
}
pub fn edns(query: &mut Vec<u8>, size: u16) {
    query[11] = 1;
    query.extend_from_slice(&[0, 0, 41]);
    query.extend_from_slice(&size.to_be_bytes());
    query.extend_from_slice(&[0, 0, 0x80, 0, 0, 5, 0xfd, 0xe8, 0, 1, 42]);
}
pub fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut data = (bytes.len() as u16).to_be_bytes().to_vec();
    data.extend_from_slice(bytes);
    data
}
pub fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut size = [0; 2];
    stream.read_exact(&mut size).unwrap();
    let mut data = vec![0; usize::from(u16::from_be_bytes(size))];
    stream.read_exact(&mut data).unwrap();
    data
}
pub fn udp(address: SocketAddr, wire: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .unwrap();
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket.connect(address).unwrap();
    socket.send(wire).unwrap();
    let mut bytes = vec![0; 65535];
    let count = socket.recv(&mut bytes).unwrap();
    bytes.truncate(count);
    bytes
}
pub fn tcp(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&address, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
}

pub struct Daemon {
    pub address: SocketAddr,
    pub child: Child,
    directory: PathBuf,
    logger: Option<JoinHandle<()>>,
    pub logs: Arc<Mutex<String>>,
}
impl Daemon {
    pub fn start(default: &[SocketAddr], routes: &[(&str, SocketAddr)]) -> Self {
        Self::start_on("127.0.0.1:0", default, routes)
    }
    pub fn start_on(bind: &str, default: &[SocketAddr], routes: &[(&str, SocketAddr)]) -> Self {
        let reservation = reserve_endpoint(bind);
        let address = reservation.0.local_addr().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "sederial-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("sederial.toml");
        let servers = default
            .iter()
            .map(|a| format!("'{a}'"))
            .collect::<Vec<_>>()
            .join(",");
        let mut text = format!("listen='{address}'\n[default]\nservers=[{servers}]\n");
        for (name, upstream) in routes {
            text.push_str(&format!(
                "[[route]]\ndomain='{name}'\nservers=['{upstream}']\n"
            ));
        }
        fs::write(&path, text).unwrap();
        drop(reservation);
        let mut child = Command::new(env!("CARGO_BIN_EXE_sederial"))
            .arg("--config")
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let logs = Arc::new(Mutex::new(String::new()));
        let output = Arc::clone(&logs);
        let (ready, receiver) = mpsc::channel();
        let logger = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else {
                    break;
                };
                output.lock().unwrap().push_str(&format!("{line}\n"));
                if line.contains("startup: listening") {
                    let _ = ready.send(());
                }
            }
        });
        let daemon = Self {
            address,
            child,
            directory,
            logger: Some(logger),
            logs,
        };
        assert!(
            receiver.recv_timeout(WAIT).is_ok(),
            "startup failed: {}",
            daemon.logs.lock().unwrap()
        );
        daemon
    }
    pub fn terminate(&mut self, signal: &str) -> Duration {
        let started = Instant::now();
        assert!(
            Command::new("sh")
                .args([
                    "-c",
                    "kill \"$1\" \"$2\"",
                    "sederial-test",
                    signal,
                    &self.child.id().to_string()
                ])
                .status()
                .unwrap()
                .success()
        );
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(started.elapsed() < WAIT, "shutdown exceeded deadline");
            thread::sleep(Duration::from_millis(10));
        }
        self.logger.take().unwrap().join().unwrap();
        started.elapsed()
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(logger) = self.logger.take() {
            let _ = logger.join();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

type Handler = dyn Fn(&[u8], bool) -> Vec<Vec<u8>> + Send + Sync;
pub struct Mock {
    pub address: SocketAddr,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    pub seen: Arc<Mutex<Vec<Vec<u8>>>>,
    pub tcp_connections: Arc<AtomicUsize>,
}
impl Mock {
    pub fn new(handle: impl Fn(&[u8], bool) -> Vec<Vec<u8>> + Send + Sync + 'static) -> Self {
        Self::on("127.0.0.1:0", handle)
    }
    pub fn on(
        bind: &str,
        handle: impl Fn(&[u8], bool) -> Vec<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        let (udp, listener) = reserve_endpoint(bind);
        let address = udp.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handle: Arc<Handler> = Arc::new(handle);
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        let shutdown = Arc::clone(&stop);
        let handler = Arc::clone(&handle);
        let received = Arc::clone(&seen);
        workers.push(thread::spawn(move || {
            let mut data = vec![0; 65535];
            while !shutdown.load(Ordering::Relaxed) {
                if let Ok((size, peer)) = udp.recv_from(&mut data) {
                    received.lock().unwrap().push(data[..size].to_vec());
                    for reply in handler(&data[..size], false) {
                        udp.send_to(&reply, peer).unwrap();
                    }
                }
            }
        }));
        let shutdown = Arc::clone(&stop);
        let received = Arc::clone(&seen);
        let connections = Arc::clone(&tcp_connections);
        workers.push(thread::spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                connections.fetch_add(1, Ordering::Relaxed);
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                stream.set_write_timeout(Some(WAIT)).unwrap();
                while !shutdown.load(Ordering::Relaxed) {
                    let mut length = [0; 2];
                    if stream.read_exact(&mut length).is_err() {
                        break;
                    }
                    let mut data = vec![0; usize::from(u16::from_be_bytes(length))];
                    if stream.read_exact(&mut data).is_err() {
                        break;
                    }
                    received.lock().unwrap().push(data.clone());
                    for reply in handle(&data, true) {
                        // Split framing and payload deliberately to exercise partial reads.
                        let framed = frame(&reply);
                        for part in framed.chunks(7) {
                            if stream.write_all(part).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }));
        Self {
            address,
            stop,
            workers,
            seen,
            tcp_connections,
        }
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            if let Err(error) = worker.join()
                && !thread::panicking()
            {
                std::panic::resume_unwind(error);
            }
        }
    }
}
