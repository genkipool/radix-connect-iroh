//! Liveness checks: whether the peer still answers, after a network change and (connector)
//! periodically, so a dead connection is dropped instead of looking alive until QUIC's idle
//! timeout.

use super::{Current, Ended, Shared};
use crate::diagnostics::{PathKind, ms};
use crate::protocol::{CloseCode, Liveness};
use crate::{Role, diagnostics, protocol};
use n0_future::time;
use n0_future::time::Instant;
use std::time::Duration;

/// How long a liveness check waits for the peer: three round trips, within these
/// bounds. The upper one covers a relay reconnecting (packets wait for it), as after
/// the app was in the background.
pub(super) const PROBE_MIN_DEADLINE: Duration = Duration::from_millis(1500);

pub(super) const PROBE_MAX_DEADLINE: Duration = Duration::from_secs(4);

/// Network changes reported within this long of a liveness check share the next one.
pub(super) const PROBE_DEBOUNCE: Duration = Duration::from_secs(2);

/// Connector: how often it checks that the wallet still answers. A closed app sends
/// nothing, and only QUIC's idle timeout (30 s) would tell; checked, it is known within
/// this plus [`PERIODIC_PROBE_DEADLINE`]. A wallet that fails a check without being gone
/// (frozen by the system, a moment without network) loses nothing: it redials, and lists
/// its requests when it is back (`requests`).
pub(super) const PERIODIC_PROBE_INTERVAL: Duration = Duration::from_secs(4);

/// How long a periodic check waits for the answer: generous against a slow radio, as
/// nothing changed that calls for a quick verdict.
pub(super) const PERIODIC_PROBE_DEADLINE: Duration = Duration::from_secs(3);

/// Connector: how long it watches the connection closely once the wallet said its app went
/// to the background. An app is closed from the system's recent apps screen, which sends it
/// to the background first: its process then ends without a word, and is known gone within
/// about [`WATCH_INTERVAL`] plus its deadline instead of [`PERIODIC_PROBE_INTERVAL`] plus
/// [`PERIODIC_PROBE_DEADLINE`]. Short, so that a wallet merely in the background is not
/// checked often for long (each check wakes its radio), and ending before the system
/// freezes a cached app, which would answer late.
pub(super) const WATCH_WINDOW: Duration = Duration::from_secs(8);

/// How often the connector checks the wallet while watching it closely.
pub(super) const WATCH_INTERVAL: Duration = Duration::from_millis(500);

/// How long a check waits while watching closely: three round trips, within these bounds
/// (the wallet just spoke, its path is known and fast).
pub(super) const WATCH_MIN_DEADLINE: Duration = Duration::from_millis(600);
pub(super) const WATCH_MAX_DEADLINE: Duration = Duration::from_millis(1500);

/// Why a connection the peer stopped answering ended.
pub(super) const NO_ANSWER: &str = "no answer to a liveness check";

/// Why a liveness check runs: it sets its deadline and how loudly it is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    /// The host reported a network change (or the app returning, the machine waking up).
    NetworkChanged,
    /// Connector: the regular check.
    Periodic,
    /// Connector: the close watch after the wallet went to the background.
    Watching,
}

impl Check {
    fn as_str(self) -> &'static str {
        match self {
            Self::NetworkChanged => "network_changed",
            Self::Periodic => "periodic",
            Self::Watching => "watching",
        }
    }

    /// The checks that come by themselves, every few seconds: logged at debug level only.
    fn is_routine(self) -> bool {
        self != Self::NetworkChanged
    }
}

/// Checks that the peer still answers each time the host reports a network change
/// (hosts report the app returning to the foreground, or the machine waking up, as
/// one): a connection that died meanwhile would otherwise look alive until QUIC's idle
/// timeout. One check at a time; changes reported meanwhile, or within
/// [`PROBE_DEBOUNCE`] of a check, share the next one. Returns only once the peer did not
/// answer, having closed the connection.
pub(super) async fn check_liveness(shared: &Shared, current: &Current) -> Ended {
    let connection = &current.connection;
    let mut requests = shared.network.subscribe();
    // Changes reported before the connection existed are no reason to check it; one
    // reported since is, even if this task only starts now.
    let mut pending = *requests.borrow_and_update() != current.network;
    let periodic_checks = shared.role == Role::Connector;
    let mut background = shared.went_to_background.subscribe();
    background.mark_unchanged();
    // Until when the connector watches closely (the wallet went to the background).
    let mut watching_until: Option<Instant> = None;
    let mut last: Option<Instant> = None;
    loop {
        let mut why = Check::NetworkChanged;
        if !std::mem::take(&mut pending) {
            let watching = watching_until.is_some_and(|until| Instant::now() < until)
                && shared
                    .peer_in_background
                    .load(std::sync::atomic::Ordering::Relaxed);
            let interval = if watching {
                WATCH_INTERVAL
            } else {
                PERIODIC_PROBE_INTERVAL
            };
            // A network change, or (connector) the next periodic check, or the wallet going
            // to the background (which only sets the pace: it just spoke).
            tokio::select! {
                changed = requests.changed() => {
                    if changed.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                Ok(()) = background.changed(), if periodic_checks => {
                    watching_until = Some(Instant::now() + WATCH_WINDOW);
                    tracing::debug!(
                        window_ms = ms(WATCH_WINDOW),
                        interval_ms = ms(WATCH_INTERVAL),
                        "the wallet went to the background: watching the connection closely"
                    );
                    continue;
                }
                () = time::sleep(interval), if periodic_checks => {
                    why = if watching { Check::Watching } else { Check::Periodic };
                }
            }
        }
        let now = Instant::now();
        // Only network changes share checks: periodic ones are paced already.
        if why == Check::NetworkChanged
            && let Some(ready) = last.map(|last| last + PROBE_DEBOUNCE)
            && ready > now
        {
            tracing::debug!(
                wait_ms = ms(ready.duration_since(now)),
                "a liveness check ran moments ago: the next one covers this change too"
            );
            time::sleep_until(ready).await;
        }
        // This check covers every change reported so far.
        requests.mark_unchanged();
        let started = Instant::now();
        last = Some(started);
        let (path, rtt) = diagnostics::selected_path(connection);
        let relay_connected = shared.relay_connected();
        let deadline = match why {
            Check::Periodic => PERIODIC_PROBE_DEADLINE,
            Check::Watching => watch_deadline(rtt),
            Check::NetworkChanged => probe_deadline(rtt, path, relay_connected),
        };
        // Every few seconds (or more often while watching): worth a debug line only.
        let periodic = why.is_routine();
        if periodic {
            tracing::debug!(
                why = why.as_str(),
                path = path.map(PathKind::as_str),
                rtt_ms = rtt.map(ms),
                deadline_ms = ms(deadline),
                "checking that the peer still answers"
            );
        } else {
            tracing::info!(
                why = why.as_str(),
                path = path.map(PathKind::as_str),
                rtt_ms = rtt.map(ms),
                relay_connected,
                deadline_ms = ms(deadline),
                "checking that the peer still answers"
            );
        }
        match protocol::probe(connection, deadline).await {
            Liveness::Alive if periodic => tracing::debug!(
                answer_ms = ms(started.elapsed()),
                "the peer answered the liveness check"
            ),
            Liveness::Alive => {
                let (path, rtt) = diagnostics::selected_path(connection);
                tracing::info!(
                    answer_ms = ms(started.elapsed()),
                    path = path.map(PathKind::as_str),
                    rtt_ms = rtt.map(ms),
                    "the peer answered the liveness check"
                );
            }
            Liveness::Inconclusive => tracing::info!(
                deadline_ms = ms(deadline),
                "could not send the liveness check in time (the peer's limit of concurrent streams is reached): keeping the connection"
            ),
            Liveness::Closed => {
                tracing::debug!("the connection ended during the liveness check");
                // Its end is reported by the streams it carried.
                std::future::pending::<()>().await;
            }
            Liveness::Unresponsive => {
                tracing::warn!(
                    why = why.as_str(),
                    deadline_ms = ms(deadline),
                    elapsed_ms = ms(started.elapsed()),
                    "the peer did not answer the liveness check: dropping the connection instead of waiting for it to time out"
                );
                connection.close(CloseCode::Unresponsive.into(), NO_ANSWER.as_bytes());
                return Ended {
                    reason: NO_ANSWER.to_owned(),
                    unresponsive: true,
                };
            }
        }
    }
}

/// How long a liveness check waits: three round trips within
/// [`PROBE_MIN_DEADLINE`]..[`PROBE_MAX_DEADLINE`], the longest while the relay the
/// connection goes through is reconnecting.
pub(super) fn probe_deadline(
    rtt: Option<Duration>,
    path: Option<PathKind>,
    relay_connected: bool,
) -> Duration {
    if path != Some(PathKind::Direct) && !relay_connected {
        return PROBE_MAX_DEADLINE;
    }
    rtt.map_or(PROBE_MIN_DEADLINE, |rtt| rtt.saturating_mul(3))
        .clamp(PROBE_MIN_DEADLINE, PROBE_MAX_DEADLINE)
}

/// How long a check waits while the connector watches closely: three round trips within
/// [`WATCH_MIN_DEADLINE`]..[`WATCH_MAX_DEADLINE`].
pub(super) fn watch_deadline(rtt: Option<Duration>) -> Duration {
    rtt.map_or(WATCH_MAX_DEADLINE, |rtt| rtt.saturating_mul(3))
        .clamp(WATCH_MIN_DEADLINE, WATCH_MAX_DEADLINE)
}
