//! Bounded asynchronous diagnostics, with a separate lane for lifecycle events.
//! A blocked stderr can lose logs, but never holds a DNS worker or service shutdown.
use std::{
    fmt,
    io::{self, Write},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const INTERVAL: Duration = Duration::from_secs(5);
const BURST: u32 = 20;
const FLUSH_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_LINE: usize = 2048;

struct Output {
    routine: mpsc::SyncSender<String>,
    important: mpsc::SyncSender<String>,
}
static OUTPUT: OnceLock<Output> = OnceLock::new();

/// Explicit bounded flush; dropping the guard never joins a blocked writer.
pub(crate) struct Logger {
    stop: Arc<AtomicBool>,
    finished: mpsc::Receiver<()>,
    thread: Option<JoinHandle<()>>,
}
impl Logger {
    fn start(mut sink: impl Write + Send + 'static) -> io::Result<(Self, Output)> {
        let (routine, messages) = mpsc::sync_channel(64);
        let (important, events) = mpsc::sync_channel(16);
        let (done, finished) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("logger".into())
            .spawn(move || {
                loop {
                    let message = events.try_recv().or_else(|_| messages.try_recv());
                    match message {
                        Ok(line) => {
                            let _ = writeln!(sink, "{line}");
                        }
                        Err(_) if stopping.load(Ordering::Relaxed) => break,
                        Err(_) => {
                            if let Ok(line) = messages.recv_timeout(Duration::from_millis(100)) {
                                let _ = writeln!(sink, "{line}");
                            }
                        }
                    }
                }
                let _ = done.send(());
            })?;
        Ok((
            Self {
                stop,
                finished,
                thread: Some(thread),
            },
            Output { routine, important },
        ))
    }
}
impl Drop for Logger {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if self.finished.recv_timeout(FLUSH_TIMEOUT).is_ok()
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}

pub(crate) fn initialize() -> io::Result<Logger> {
    let (logger, output) = Logger::start(io::stderr())?;
    let _ = OUTPUT.set(output);
    // The default hook writes synchronously to stderr before catch_unwind runs.
    // Avoid that backpressure and never include an arbitrary panic payload.
    std::panic::set_hook(Box::new(|_| {
        error(format_args!("thread panicked; service will stop"))
    }));
    Ok(logger)
}

fn emit(level: &str, message: fmt::Arguments<'_>, important: bool) {
    let Some(output) = OUTPUT.get() else {
        return;
    };
    let mut line = format!("{level} {message}");
    if line.len() > MAX_LINE {
        let mut end = MAX_LINE;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
    }
    let sender = if important {
        &output.important
    } else {
        &output.routine
    };
    let _ = sender.try_send(line);
}

pub(crate) fn info(message: fmt::Arguments<'_>) {
    emit("INFO", message, true);
}
pub(crate) fn error(message: fmt::Arguments<'_>) {
    emit("ERROR", message, true);
}

struct WarningWindow {
    started_at: Instant,
    emitted: u32,
    suppressed: u64,
}
static WINDOW: Mutex<Option<WarningWindow>> = Mutex::new(None);

/// At most twenty routine warnings per five seconds; no output under the mutex.
pub(crate) fn warn(message: fmt::Arguments<'_>) {
    let (emit_warning, suppressed) = {
        let Ok(mut state) = WINDOW.lock() else {
            return;
        };
        let window = state.get_or_insert(WarningWindow {
            started_at: Instant::now(),
            emitted: 0,
            suppressed: 0,
        });
        let suppressed = if window.started_at.elapsed() >= INTERVAL {
            let suppressed = window.suppressed;
            *window = WarningWindow {
                started_at: Instant::now(),
                emitted: 0,
                suppressed: 0,
            };
            suppressed
        } else {
            0
        };
        if window.emitted < BURST {
            window.emitted += 1;
            (true, suppressed)
        } else {
            window.suppressed = window.suppressed.saturating_add(1);
            (false, suppressed)
        }
    };
    if suppressed > 0 {
        emit(
            "WARN",
            format_args!("suppressed {suppressed} repeated diagnostics"),
            false,
        );
    }
    if emit_warning {
        emit("WARN", message, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct SlowSink {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Write for SlowSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.entered.send(());
            // The fixture always releases itself, even if the test panics.
            let _ = self.release.recv_timeout(Duration::from_secs(2));
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn blocked_sink_has_bounded_queues_and_bounded_teardown() {
        let (entered, waiting) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (logger, output) = Logger::start(SlowSink {
            entered,
            release: released,
        })
        .unwrap();
        output.routine.try_send("first".into()).unwrap();
        waiting.recv_timeout(Duration::from_secs(1)).unwrap();
        for _ in 0..64 {
            output.routine.try_send("queued".into()).unwrap();
        }
        assert!(output.routine.try_send("overflow".into()).is_err());
        output.important.try_send("fatal".into()).unwrap();
        let start = Instant::now();
        drop(logger);
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(release);
    }
}
