//! Bounded job delivery and worker lifetime, independent of DNS forwarding.

use crate::transport::IO_POLL;
use std::{
    collections::VecDeque,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// A worker owns the state for its jobs and maintains it between queue polls.
///
/// Implementations must bound blocking work and observe their cancellation
/// signal so explicit shutdown can join their threads within its deadline.
pub(super) trait Worker: Send + 'static {
    /// Work transferred by ownership from the listener to a single worker.
    type Job: Send + 'static;

    /// Completes one job before this worker dequeues another.
    fn handle(&mut self, job: Self::Job);
    /// Performs cleanup between jobs and after idle polls, without a timer thread.
    fn maintain(&mut self);
}

struct Jobs<T> {
    queue: VecDeque<T>,
    capacity: usize,
    closed: bool,
}

/// The queue owns accepted jobs. Explicit shutdown stops and collects workers.
///
/// The stop flag is shared with the service: dropping either pool requests global
/// shutdown. Queued jobs are discarded rather than drained through handlers.
/// Workers wait on a condition variable, so the queue lock is not held while
/// they sleep or run [`Worker::maintain`].
pub(super) struct Pool<W: Worker> {
    jobs: Arc<Mutex<Jobs<W::Job>>>,
    ready: Arc<Condvar>,
    workers: Vec<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    completed: mpsc::Receiver<()>,
    pending: usize,
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
        let jobs = Arc::new(Mutex::new(Jobs {
            queue: VecDeque::new(),
            capacity,
            closed: false,
        }));
        let ready = Arc::new(Condvar::new());
        let (completed, receiver) = mpsc::channel();
        let mut pool = Self {
            jobs,
            ready,
            workers: Vec::new(),
            stop,
            failed: Arc::new(AtomicBool::new(false)),
            completed: receiver,
            pending: 0,
        };
        for index in 0..count {
            let jobs = Arc::clone(&pool.jobs);
            let ready = Arc::clone(&pool.ready);
            let stop = Arc::clone(&pool.stop);
            let failed = Arc::clone(&pool.failed);
            let completed = completed.clone();
            let state = match create_worker() {
                Ok(state) => state,
                Err(error) => {
                    let _ = pool.shutdown(Instant::now() + Duration::from_secs(3));
                    return Err(error);
                }
            };
            let worker = thread::Builder::new()
                .name(format!("{name}-{index}"))
                .spawn(move || {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        let mut state = state;
                        while !stop.load(Ordering::Relaxed) {
                            state.maintain();
                            match next_job(&jobs, &ready, &stop, &failed) {
                                JobPoll::Ready(job) if !stop.load(Ordering::Relaxed) => {
                                    state.handle(job);
                                }
                                JobPoll::Ready(_) | JobPoll::Stopped => break,
                                JobPoll::Idle => continue,
                            }
                        }
                        // Drop worker state inside the panic boundary as well.
                        drop(state);
                    }));
                    if result.is_err() {
                        failed.store(true, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        ready.notify_all();
                    }
                    let _ = completed.send(());
                });
            match worker {
                Ok(worker) => {
                    pool.workers.push(worker);
                    pool.pending += 1;
                }
                Err(error) => {
                    let _ = pool.shutdown(Instant::now() + Duration::from_secs(3));
                    return Err(error);
                }
            }
        }
        Ok(pool)
    }

    /// Attempts to transfer a job without waiting for queue capacity.
    ///
    /// Returns `false` and drops the job if the queue is full or disconnected.
    /// Acceptance does not guarantee execution: shutdown discards pending jobs.
    pub(super) fn submit(&self, job: W::Job) -> bool {
        let Ok(mut jobs) = self.jobs.lock() else {
            self.failed.store(true, Ordering::Relaxed);
            self.stop.store(true, Ordering::Relaxed);
            return false;
        };
        if self.stop.load(Ordering::Relaxed) || jobs.closed || jobs.queue.len() >= jobs.capacity {
            return false;
        }
        jobs.queue.push_back(job);
        drop(jobs);
        self.ready.notify_one();
        true
    }

    fn close(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.closed = true;
            jobs.queue.clear();
        } else {
            self.failed.store(true, Ordering::Relaxed);
        }
        self.ready.notify_all();
    }

    /// Collects all worker results within the service's shutdown budget.
    /// A timeout is fatal: callers must exit the process, not resume service.
    pub(super) fn shutdown(&mut self, deadline: Instant) -> io::Result<()> {
        self.close();
        while self.pending > 0 {
            match self
                .completed
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(()) => self.pending -= 1,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "worker shutdown incomplete",
                    ));
                }
            }
        }
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                self.failed.store(true, Ordering::Relaxed);
            }
        }
        if self.failed.load(Ordering::Relaxed) {
            Err(io::Error::other("worker or queue terminated unexpectedly"))
        } else {
            Ok(())
        }
    }
}
impl<W: Worker> Drop for Pool<W> {
    fn drop(&mut self) {
        self.close();
        // A failed explicit shutdown must not become an unbounded join here.
        // Unfinished threads are detached; the service caller exits the process.
        for worker in self.workers.drain(..) {
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

enum JobPoll<T> {
    Ready(T),
    Idle,
    Stopped,
}

/// Waits up to one poll interval. The mutex is released for the wait, so every
/// worker can run maintenance on its own cadence.
fn next_job<T>(
    jobs: &Mutex<Jobs<T>>,
    ready: &Condvar,
    stop: &AtomicBool,
    failed: &AtomicBool,
) -> JobPoll<T> {
    let Ok(mut jobs) = jobs.lock() else {
        failed.store(true, Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
        return JobPoll::Stopped;
    };
    loop {
        if stop.load(Ordering::Relaxed) || jobs.closed {
            return JobPoll::Stopped;
        }
        if let Some(job) = jobs.queue.pop_front() {
            return JobPoll::Ready(job);
        }
        let waited = ready.wait_timeout(jobs, IO_POLL);
        let Ok((guard, status)) = waited else {
            failed.store(true, Ordering::Relaxed);
            stop.store(true, Ordering::Relaxed);
            return JobPoll::Stopped;
        };
        jobs = guard;
        if status.timed_out()
            && jobs.queue.is_empty()
            && !jobs.closed
            && !stop.load(Ordering::Relaxed)
        {
            return JobPoll::Idle;
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

    struct CountingWorker {
        maintains: Arc<AtomicUsize>,
    }

    impl Worker for CountingWorker {
        type Job = ();

        fn handle(&mut self, _: ()) {}
        fn maintain(&mut self) {
            self.maintains.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn idle_workers_maintain_without_sharing_the_queue_wait() {
        let stop = Arc::new(AtomicBool::new(false));
        let maintains = Arc::new(AtomicUsize::new(0));
        let pool = Pool::new(4, 4, Arc::clone(&stop), "maintain", || {
            Ok(CountingWorker {
                maintains: Arc::clone(&maintains),
            })
        })
        .unwrap();
        thread::sleep(super::IO_POLL * 6);
        let ticks = maintains.load(Ordering::Relaxed);
        drop(pool);
        // Four workers each poll about every 100 ms. A lock held across the
        // wait would serialize those polls into roughly one tick per interval.
        assert!(
            ticks >= 14,
            "idle maintenance was serialized across workers ({ticks} ticks)"
        );
    }
}

#[cfg(test)]
mod panic_tests {
    use super::*;
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };

    struct PanickingWorker {
        in_maintain: bool,
        entered: mpsc::Sender<()>,
    }
    impl Worker for PanickingWorker {
        type Job = ();
        fn handle(&mut self, _: ()) {
            self.entered.send(()).unwrap();
            panic!("handle failed");
        }
        fn maintain(&mut self) {
            if self.in_maintain {
                self.entered.send(()).unwrap();
                panic!("maintain failed");
            }
        }
    }
    #[test]
    fn handle_and_maintain_panics_request_service_shutdown() {
        if std::env::var_os("SEDERIAL_PANIC_TEST_CHILD").is_none() {
            for mode in ["handle", "maintain"] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "server::pool::panic_tests::handle_and_maintain_panics_request_service_shutdown"])
                    .env("SEDERIAL_PANIC_TEST_CHILD", mode)
                    .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                    .spawn().unwrap();
                let limit = Instant::now() + Duration::from_secs(5);
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if Instant::now() >= limit {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("panic child hung");
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                assert_eq!(
                    status.code(),
                    Some(1),
                    "{mode}: worker fault must use the fatal process exit path"
                );
            }
            return;
        }
        let in_maintain = std::env::var("SEDERIAL_PANIC_TEST_CHILD").unwrap() == "maintain";
        {
            let stop = Arc::new(AtomicBool::new(false));
            let (entered, receiver) = mpsc::channel();
            let mut pool = Pool::new(1, 1, Arc::clone(&stop), "panic-test", || {
                Ok(PanickingWorker {
                    in_maintain,
                    entered: entered.clone(),
                })
            })
            .unwrap();
            pool.submit(());
            receiver.recv_timeout(Duration::from_secs(1)).unwrap();
            let limit = Instant::now() + Duration::from_secs(1);
            while !stop.load(Ordering::Relaxed) && Instant::now() < limit {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                stop.load(Ordering::Relaxed),
                "a dead worker must stop the service"
            );
            let result = pool
                .shutdown(Instant::now() + Duration::from_secs(1))
                .map_err(|error| error.to_string());
            std::process::exit(i32::from(crate::exit_status(result)));
        }
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    struct WaitingWorker {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        finished: mpsc::Sender<()>,
    }
    impl Worker for WaitingWorker {
        type Job = ();
        fn handle(&mut self, _: ()) {
            self.entered.send(()).unwrap();
            let _ = self.release.recv_timeout(Duration::from_secs(2));
            let _ = self.finished.send(());
        }
        fn maintain(&mut self) {}
    }
    #[test]
    fn timed_out_shutdown_does_not_join_a_blocked_worker_in_drop() {
        let (entered, waiting) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (finished, done) = mpsc::channel();
        let mut worker = Some(WaitingWorker {
            entered,
            release: released,
            finished,
        });
        let mut pool = Pool::new(1, 1, Arc::new(AtomicBool::new(false)), "waiting", || {
            Ok(worker.take().unwrap())
        })
        .unwrap();
        pool.submit(());
        waiting.recv_timeout(Duration::from_secs(1)).unwrap();
        pool.submit(()); // Must be discarded without entering the handler.
        let started = Instant::now();
        let result = pool.shutdown(started).map_err(|e| e.to_string());
        assert_eq!(crate::exit_status(result), 1);
        drop(pool);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(release);
        done.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(waiting.recv_timeout(Duration::from_secs(1)).is_err());
        assert_eq!(crate::exit_status(Ok(())), 0);
    }
}
