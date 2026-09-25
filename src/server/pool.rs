//! Bounded job delivery and worker lifetime, independent of DNS forwarding.

use crate::{logging, transport::IO_POLL};
use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
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

struct Jobs<T> {
    queue: VecDeque<T>,
    capacity: usize,
    closed: bool,
}

/// The queue owns accepted jobs. Dropping a pool stops and joins all its workers.
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
        let mut pool = Self {
            jobs,
            ready,
            workers: Vec::new(),
            stop,
        };
        for index in 0..count {
            let jobs = Arc::clone(&pool.jobs);
            let ready = Arc::clone(&pool.ready);
            let stop = Arc::clone(&pool.stop);
            let mut state = create_worker()?;
            let worker = thread::Builder::new()
                .name(format!("{name}-{index}"))
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        state.maintain();
                        match next_job(&jobs, &ready, &stop) {
                            JobPoll::Ready(job) if !stop.load(Ordering::Relaxed) => {
                                state.handle(job);
                            }
                            JobPoll::Ready(_) | JobPoll::Stopped => break,
                            JobPoll::Idle => continue,
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
        let Ok(mut jobs) = self.jobs.lock() else {
            self.stop.store(true, Ordering::Relaxed);
            return false;
        };
        if jobs.closed || jobs.queue.len() >= jobs.capacity {
            return false;
        }
        jobs.queue.push_back(job);
        drop(jobs);
        self.ready.notify_one();
        true
    }
}
impl<W: Worker> Drop for Pool<W> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.closed = true;
            // Discard work that has not started. In-flight handle calls finish.
            jobs.queue.clear();
        }
        // Wake every worker blocked in wait. A timeout would otherwise leave
        // shutdown waiting on the idle poll.
        self.ready.notify_all();
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                logging::warn(format_args!("worker terminated unexpectedly"));
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
fn next_job<T>(jobs: &Mutex<Jobs<T>>, ready: &Condvar, stop: &AtomicBool) -> JobPoll<T> {
    let Ok(mut jobs) = jobs.lock() else {
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
