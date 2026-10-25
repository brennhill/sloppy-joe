//! HTTP 429 handling shared by every request to a host: the backoff schedule,
//! a host-wide pause while the host asks for one, and a fast give-up once a
//! request to that host has already exhausted its retries.
//!
//! crates.io's web API answers a burst with 429 for every request in flight,
//! sends no `Retry-After`, and keeps the block up for minutes. Without a shared
//! pause each in-flight request retries on its own schedule and keeps the
//! block alive.
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Maximum times a rate-limited (HTTP 429) request is sent.
pub(crate) const MAX_RATE_LIMIT_ATTEMPTS: u32 = 8;
const BASE_DELAY: Duration = Duration::from_secs(1);
/// Longest wait between attempts when the host does not say how long to wait.
const MAX_BACKOFF_WAIT: Duration = Duration::from_secs(30);
/// Longest wait honoured from a `Retry-After` header.
const MAX_ASKED_WAIT: Duration = Duration::from_secs(60);
/// How long a host that exhausted a request's retries gets single attempts only.
const EXHAUSTED_WINDOW: Duration = Duration::from_secs(120);

#[derive(Default)]
struct HostState {
    paused_until: Option<Instant>,
    exhausted_at: Option<Instant>,
}

fn hosts() -> &'static Mutex<HashMap<String, HostState>> {
    static HOSTS: OnceLock<Mutex<HashMap<String, HostState>>> = OnceLock::new();
    HOSTS.get_or_init(Default::default)
}

fn with_host<T>(host: &str, f: impl FnOnce(&mut HostState) -> T) -> T {
    let mut hosts = hosts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(hosts.entry(host.to_string()).or_default())
}

/// The `host:port` a URL's requests share a rate limit under.
pub(crate) fn host_key(url: &str) -> String {
    reqwest::Url::parse(url)
        .map(|url| {
            format!(
                "{}:{}",
                url.host_str().unwrap_or_default(),
                url.port_or_known_default().unwrap_or_default()
            )
        })
        .unwrap_or_default()
}

/// Wait before the next attempt: what the host asked for (bounded), else
/// exponential backoff from 1s, capped at 30s.
pub(crate) fn delay(attempt: u32, asked: Option<Duration>) -> Duration {
    match asked {
        Some(asked) => asked.min(MAX_ASKED_WAIT),
        None => BASE_DELAY
            .saturating_mul(2u32.saturating_pow(attempt))
            .min(MAX_BACKOFF_WAIT),
    }
}

/// A pseudo-random extra wait of at most a quarter of `wait`, so requests
/// released by the same pause do not all arrive at once.
pub(crate) fn jitter(wait: Duration, seed: impl Hash) -> Duration {
    let quarter = wait.as_millis() as u64 / 4;
    if quarter == 0 {
        return Duration::ZERO;
    }
    let random = std::collections::hash_map::RandomState::new().hash_one(seed);
    Duration::from_millis(random % (quarter + 1))
}

/// Ask every request to `host` to wait `wait` from now.
pub(crate) fn pause(host: &str, wait: Duration) {
    if wait.is_zero() {
        return;
    }
    let until = Instant::now() + wait;
    with_host(host, |state| {
        state.paused_until = Some(
            state
                .paused_until
                .map_or(until, |current| current.max(until)),
        );
    });
}

/// Sleep until no pause is in force for `host`.
pub(crate) async fn wait_until_unpaused(host: &str) {
    loop {
        let until = with_host(host, |state| state.paused_until);
        let remaining = until.map_or(Duration::ZERO, |until| {
            until.saturating_duration_since(Instant::now())
        });
        if remaining.is_zero() {
            return;
        }
        tokio::time::sleep(remaining).await;
    }
}

/// Record that a request to `host` was still rate limited after every attempt.
pub(crate) fn mark_exhausted(host: &str) {
    with_host(host, |state| state.exhausted_at = Some(Instant::now()));
}

/// Record that `host` answered without rate limiting: the block is over.
pub(crate) fn mark_answered(host: &str) {
    with_host(host, |state| state.exhausted_at = None);
}

/// Attempts a new request to `host` may make before handing a 429 back.
pub(crate) fn attempts_allowed(host: &str) -> u32 {
    let recently_exhausted = with_host(host, |state| {
        state
            .exhausted_at
            .is_some_and(|at| at.elapsed() < EXHAUSTED_WINDOW)
    });
    if recently_exhausted {
        1
    } else {
        MAX_RATE_LIMIT_ATTEMPTS
    }
}
