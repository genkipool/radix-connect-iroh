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

/// Why a connection the peer stopped answering ended.
pub(super) const NO_ANSWER: &str = "no answer to a liveness check";

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
    let mut last: Option<Instant> = None;
    loop {
        let mut why = "network_changed";
        if !std::mem::take(&mut pending) {
            // A network change, or (connector) the next periodic check.
            tokio::select! {
                changed = requests.changed() => {
                    if changed.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                () = time::sleep(PERIODIC_PROBE_INTERVAL), if periodic_checks => why = "periodic",
            }
        }
        let now = Instant::now();
        if let Some(ready) = last.map(|last| last + PROBE_DEBOUNCE)
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
        let deadline = if why == "periodic" {
            PERIODIC_PROBE_DEADLINE
        } else {
            probe_deadline(rtt, path, relay_connected)
        };
        // Every few seconds: worth a debug line only.
        let periodic = why == "periodic";
        if periodic {
            tracing::debug!(
                why,
                path = path.map(PathKind::as_str),
                rtt_ms = rtt.map(ms),
                deadline_ms = ms(deadline),
                "checking that the peer still answers"
            );
        } else {
            tracing::info!(
                why,
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
                    why,
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
