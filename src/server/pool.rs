//! Bounded job delivery and worker lifetime, independent of DNS forwarding.

use crate::{logging, transport::IO_POLL};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
};

/// A worker owns the state for its jobs and maintains it between queue polls.
///
/// Implementations must bound blocking work and observe their cancellation
/// signal so pool destruction can join their threads.
pub(super) trait Worker: Send + 'static {
    /// Work transferred by ownership from the listener to a single worker.
    type Job: Send + 'static;

    /// Completes one job before this worker dequeues another.
    fn handle(&mut self, job: Self::Job);
    /// Performs cleanup between jobs and after idle polls, without a timer thread.
    fn maintain(&mut self);
}

/// The queue owns accepted jobs. Dropping a pool stops and joins all its workers.
///
/// The stop flag is shared with the service: dropping either pool requests global
/// shutdown. Queued jobs are discarded rather than drained through handlers.
pub(super) struct Pool<W: Worker> {
    sender: Option<SyncSender<W::Job>>,
    workers: Vec<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}
impl<W: Worker> Pool<W> {
    /// Initializes each worker on the calling thread, then transfers it to a thread.
    ///
    /// # Errors
    /// If initialization or spawning fails, already-started workers are stopped
    /// and joined before the error is returned.
    pub(super) fn new(
        count: usize,
        capacity: usize,
        stop: Arc<AtomicBool>,
        name: &str,
        mut create_worker: impl FnMut() -> io::Result<W>,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut pool = Self {
            sender: Some(sender),
            workers: Vec::new(),
            stop,
        };
        for index in 0..count {
            let receiver = Arc::clone(&receiver);
            let stop = Arc::clone(&pool.stop);
            let mut state = create_worker()?;
            let worker = thread::Builder::new()
                .name(format!("{name}-{index}"))
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        state.maintain();
                        // Only dequeue is serialized; processing always runs outside the lock.
                        let job = match receiver.lock() {
                            Ok(queue) => queue.recv_timeout(IO_POLL),
                            Err(_) => {
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                        };
                        match job {
                            Ok(job) if !stop.load(Ordering::Relaxed) => state.handle(job),
                            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        }
                    }
                })?;
            pool.workers.push(worker);
        }
        Ok(pool)
    }

    /// Attempts to transfer a job without waiting for queue capacity.
    ///
    /// Returns `false` and drops the job if the queue is full or disconnected.
    /// Acceptance does not guarantee execution: shutdown discards pending jobs.
    pub(super) fn submit(&self, job: W::Job) -> bool {
        match self.sender.as_ref().map(|sender| sender.try_send(job)) {
            Some(Ok(())) => true,
            Some(Err(TrySendError::Disconnected(_))) => {
                self.stop.store(true, Ordering::Relaxed);
                false
            }
            _ => false,
        }
    }
}
impl<W: Worker> Drop for Pool<W> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Disconnect before joining so workers waiting in recv_timeout wake
        // immediately even when no further client traffic arrives.
        self.sender.take();
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                logging::warn(format_args!("worker terminated unexpectedly"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct IdleWorker {
        dropped: Arc<AtomicUsize>,
    }

    impl Worker for IdleWorker {
        type Job = ();

        fn handle(&mut self, _: ()) {}
        fn maintain(&mut self) {}
    }

    impl Drop for IdleWorker {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn initialization_failure_stops_and_joins_started_workers() {
        let stop = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut initialized = 0;
        let result = Pool::new(2, 1, Arc::clone(&stop), "test-worker", || {
            initialized += 1;
            if initialized == 2 {
                return Err(io::Error::other("worker initialization failed"));
            }
            Ok(IdleWorker {
                dropped: Arc::clone(&dropped),
            })
        });

        assert!(result.is_err());
        assert!(stop.load(Ordering::Relaxed));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}
