//! The wallet's side of a link: it dials the connector, serves each connection until it
//! ends and dials again on the schedule of [`Retry`] (quickly for a while, then slowly),
//! cut short by wake-ups (network changes, the app returning, knocks).

use super::receive::serve;
use super::{ConnectionState, Ended, Shared};
use crate::SessionConfig;
use crate::config::Relays;
use crate::config::RetryPolicy;
use crate::diagnostics::{DialFailure, ms};
use crate::logging::Redacted;
use crate::protocol::{ALPN, CloseCode};
use iroh::endpoint::Connection;
use iroh::{EndpointAddr, TransportAddr};
use n0_future::time;
use n0_future::time::Instant;
use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument;

/// Longest wait before taking a link back from another session holding the same key.
pub(super) const MAX_REPLACED_DELAY: Duration = Duration::from_secs(300);

/// After this long without reaching the connector, the wallet's periodic "still trying"
/// line becomes a warning.
pub(super) const UNREACHABLE_WARNING: Duration = Duration::from_secs(60);

/// Why the wallet dials (again), for logs.
#[derive(Debug, Clone, Copy)]
pub(super) enum DialReason {
    /// The session just started.
    First,
    /// The previous attempt failed.
    Retry,
    /// The connection ended.
    Disconnected,
    /// Another holder of the wallet key took the connection over.
    Replaced,
    /// The connector stopped answering liveness checks.
    Unresponsive,
    /// The network changed while the wallet waited (or dialed).
    NetworkChanged,
    /// The connector knocked: it is up, and waits for the wallet.
    Knocked,
}

impl DialReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Retry => "retry",
            Self::Disconnected => "disconnected",
            Self::Replaced => "replaced",
            Self::Unresponsive => "unresponsive",
            Self::NetworkChanged => "network_changed",
            Self::Knocked => "knocked",
        }
    }
}

/// Wallet: keep dialing the Connector Extension, and serve each connection until it
/// ends.
pub(super) async fn dial(shared: &Arc<Shared>) {
    // With the public relays the connector's relay is found through address lookup.
    let peer_addr = match &shared.config.relays {
        Relays::Public => EndpointAddr::new(shared.peer),
        Relays::Custom(url) => EndpointAddr::new(shared.peer).with_relay_url(url.clone()),
    };
    let config = &shared.config;
    let mut network = shared.network.subscribe();
    let mut knocks = shared.knocks.subscribe();
    let mut retry = Retry::new(shared.started_at, shared.retry_policy());
    let mut delay = config.retry.min_delay;
    let mut replaced_in_a_row = 0;
    let mut reason = DialReason::First;
    let mut waited = Duration::ZERO;
    // Since when the connector has been out of reach (session start, or the end of the
    // last connection).
    let mut unreachable_since = shared.started_at;
    loop {
        shared.set_state(ConnectionState::Connecting);
        // This attempt already uses the current network.
        network.mark_unchanged();
        let attempt = shared.trouble().failed_attempts + 1;
        tracing::debug!(
            attempt,
            reason = reason.as_str(),
            waited_ms = ms(waited),
            timeout_ms = ms(shared.config.retry.connect_timeout),
            "dialing the connector"
        );
        let started = Instant::now();
        let dialing = time::timeout(
            shared.config.retry.connect_timeout,
            shared.endpoint.connect(peer_addr.clone(), ALPN),
        );
        let outcome = tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            outcome = dialing => outcome,
        };
        let elapsed = started.elapsed();
        let failure = match outcome {
            Ok(Ok(connection)) => {
                let current = shared.current(connection.clone());
                shared.connection.send_replace(Some(current.clone()));
                shared.record_connected();
                shared.set_state(ConnectionState::Connected);
                shared.log_connected(&current, elapsed, Some(attempt));
                // Every connection starts as the app's: the connector hears where it is now.
                shared.tell_presence(&current.connection);
                // `None`: the session is closing, and closes the connection itself.
                let Some(Ended {
                    reason: ended,
                    unresponsive,
                }) = serve(shared, &current)
                    .instrument(current.span.clone())
                    .await
                else {
                    return;
                };
                shared.connection.send_replace(None);
                shared.log_disconnected(&current, &ended);
                shared.record_disconnected(Some(ended));
                // Not connected any more, and about to dial again.
                shared.set_state(ConnectionState::Connecting);
                shared.log_snapshot();
                // iroh carried the connection across the network changes made meanwhile.
                network.mark_unchanged();
                unreachable_since = Instant::now();
                retry = Retry::new(unreachable_since, shared.retry_policy());
                if was_replaced(&connection) {
                    replaced_in_a_row += 1;
                    reason = DialReason::Replaced;
                } else {
                    replaced_in_a_row = 0;
                    reason = if unresponsive {
                        DialReason::Unresponsive
                    } else {
                        DialReason::Disconnected
                    };
                }
                delay = if unresponsive {
                    // The network changed under it: the connector is likely reachable
                    // again right away.
                    Duration::ZERO
                } else {
                    delay_after_connection(replaced_in_a_row, &shared.config)
                };
                if replaced_in_a_row > 0 {
                    tracing::warn!(
                        replaced_in_a_row,
                        delay_ms = ms(delay),
                        "another session holding this link's wallet key (another device or app instance) took the connection over: waiting before dialing again; network changes do not cut this wait short"
                    );
                }
                None
            }
            Ok(Err(error)) => Some((DialFailure::of_connect(&error), Redacted(error).to_string())),
            Err(_) => Some((DialFailure::Timeout, "timed out".to_owned())),
        };
        if let Some((failure, error)) = failure {
            let relay_connected = shared.relay_connected();
            let failure = failure.given_relay(relay_connected);
            // What the endpoint knows about the connector: with the public relays,
            // whether address lookup found its relay.
            let peer_relay = peer_relay(shared).await;
            let failed_attempts =
                shared.record_failed_attempt(format_args!("{} ({})", error, failure.hint()));
            tracing::debug!(
                attempt,
                outcome = failure.as_str(),
                elapsed_ms = ms(elapsed),
                timeout_ms = ms(shared.config.retry.connect_timeout),
                relay_connected,
                peer_relay = peer_relay.as_deref().unwrap_or("unknown"),
                error,
                "dial attempt failed"
            );
            if failure == DialFailure::Local {
                tracing::error!(
                    error,
                    "the local endpoint refused to dial the connector: this is a bug"
                );
            }
            // Every few failures, say it at a level hosts log by default.
            if failed_attempts.is_power_of_two() {
                let unreachable_for = unreachable_since.elapsed();
                if unreachable_for >= UNREACHABLE_WARNING {
                    tracing::warn!(
                        failed_attempts,
                        unreachable_ms = ms(unreachable_for),
                        last_outcome = failure.as_str(),
                        hint = failure.hint(),
                        relay_connected,
                        "still cannot reach the connector"
                    );
                } else {
                    tracing::info!(
                        failed_attempts,
                        unreachable_ms = ms(unreachable_for),
                        last_outcome = failure.as_str(),
                        hint = failure.hint(),
                        relay_connected,
                        "still trying to reach the connector"
                    );
                }
            }
            reason = DialReason::Retry;
            let slowing_down;
            (delay, slowing_down) = retry.after_failure(Instant::now());
            if slowing_down {
                tracing::info!(
                    unreachable_ms = ms(unreachable_since.elapsed()),
                    fast_retry_period_ms = ms(retry.policy.fast_period),
                    delay_ms = ms(delay),
                    "the connector is still unreachable: retrying less often (every delay_ms) until the app returns to the foreground or the network changes"
                );
            }
        }
        // A network change cuts the wait short, unless another session took the link
        // over: then only time does, or the two would keep taking it from each other.
        let follow_network = replaced_in_a_row == 0;
        tracing::debug!(
            delay_ms = ms(delay),
            reason = reason.as_str(),
            follow_network,
            "waiting before dialing again"
        );
        let waiting = Instant::now();
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            Ok(()) = network.changed(), if follow_network => {
                let knocked = knocks.has_changed().unwrap_or(false);
                knocks.mark_unchanged();
                if knocked {
                    tracing::info!(
                        waited_ms = ms(waiting.elapsed()),
                        planned_delay_ms = ms(delay),
                        "the connector knocked: dialing it now instead of waiting, and quickly again for a while"
                    );
                    reason = DialReason::Knocked;
                } else {
                    tracing::info!(
                        waited_ms = ms(waiting.elapsed()),
                        planned_delay_ms = ms(delay),
                        "the network changed: dialing again now instead of waiting, and quickly again for a while"
                    );
                    reason = DialReason::NetworkChanged;
                }
                // A wake-up: the connector may be back, retry quickly again.
                retry = Retry::new(Instant::now(), shared.retry_policy());
            }
            () = time::sleep(delay) => {}
        }
        waited = waiting.elapsed();
    }
}

/// The wallet's schedule of attempts while the connector is out of reach, following the
/// session's [`RetryPolicy`](crate::config::RetryPolicy): quick ones (a back-off from
/// `min_delay`, doubling up to `max_delay`) for `fast_period` after the connection was
/// lost, the session started or the host reported a wake-up (network change, app back in
/// the foreground), then one every `slow_delay`, so that links to connectors that stay
/// offline do not keep the phone's radio awake. A connection resets it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Retry {
    pub(super) policy: RetryPolicy,
    fast_since: Instant,
    next_fast: Duration,
    slow: bool,
}

impl Retry {
    pub(super) fn new(fast_since: Instant, policy: RetryPolicy) -> Self {
        Self {
            policy,
            fast_since,
            next_fast: policy.min_delay,
            slow: false,
        }
    }

    /// The wait after an attempt that failed at `now`, and whether it is the first of
    /// the slow ones.
    pub(super) fn after_failure(&mut self, now: Instant) -> (Duration, bool) {
        let policy = self.policy;
        if now.saturating_duration_since(self.fast_since) >= policy.fast_period {
            let first = !std::mem::replace(&mut self.slow, true);
            (policy.slow_delay, first)
        } else {
            let delay = self.next_fast;
            self.next_fast = (delay * 2).max(policy.min_delay).min(policy.max_delay);
            (delay, false)
        }
    }
}

/// The relay the endpoint knows the connector at, if any (redacted, for logs).
pub(super) async fn peer_relay(shared: &Shared) -> Option<String> {
    let info = shared.endpoint.remote_info(shared.peer).await?;
    info.addrs().find_map(|addr| match addr.addr() {
        TransportAddr::Relay(url) => Some(Redacted(url).to_string()),
        _ => None,
    })
}

/// Delay before redialing once a connection ended. When another session holding this
/// link's key (another device, or a second app instance) took over, redialing at once
/// would just take the link back, and the two would keep replacing each other: wait the
/// longest back-off, doubling (up to 5 minutes) while it keeps happening.
pub(super) fn delay_after_connection(replaced_in_a_row: u32, config: &SessionConfig) -> Duration {
    match replaced_in_a_row {
        0 => config.retry.min_delay,
        n => config
            .retry
            .max_delay
            .saturating_mul(1 << (n - 1).min(8))
            .min(MAX_REPLACED_DELAY.max(config.retry.max_delay)),
    }
}

pub(super) fn was_replaced(connection: &Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(close))
            if close.error_code == CloseCode::Replaced.into()
    )
}
