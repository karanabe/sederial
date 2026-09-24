//! Journal-friendly stderr logging with no query names or client packet dumps.
//!
//! Callers supply metadata-only messages; this module does not redact values.
//! Diagnostic write failures are ignored so they do not fail DNS exchanges.
use std::{
    fmt,
    io::{self, Write},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Writes lifecycle or configuration metadata without warning-rate limiting.
pub(crate) fn info(message: fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr().lock(), "INFO {message}");
}

// A shared fixed window bounds diagnostics during malformed traffic or outages.
struct WarningWindow {
    started_at: Instant,
    emitted: u32,
    suppressed: u64,
}

static WINDOW: Mutex<Option<WarningWindow>> = Mutex::new(None);
const INTERVAL: Duration = Duration::from_secs(5);
const BURST: u32 = 20;
/// Emits at most twenty warnings per shared five-second window.
///
/// The next warning after a window expires also reports its suppressed count.
/// There is no timer thread, so an idle service emits no suppression summary.
pub(crate) fn warn(message: fmt::Arguments<'_>) {
    let Ok(mut state) = WINDOW.lock() else {
        return;
    };
    let now = Instant::now();
    let window = state.get_or_insert(WarningWindow {
        started_at: now,
        emitted: 0,
        suppressed: 0,
    });
    if window.started_at.elapsed() >= INTERVAL {
        if window.suppressed != 0 {
            let _ = writeln!(
                io::stderr().lock(),
                "WARN suppressed {} repeated diagnostics",
                window.suppressed
            );
        }
        window.started_at = now;
        window.emitted = 0;
        window.suppressed = 0;
    }
    if window.emitted < BURST {
        window.emitted += 1;
        let _ = writeln!(io::stderr().lock(), "WARN {message}");
    } else {
        window.suppressed = window.suppressed.saturating_add(1);
    }
}
