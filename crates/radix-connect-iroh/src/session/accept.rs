//! The connector's side of a link: it screens and accepts the wallet's connections (the
//! admission rules and handshake pools of `docs/PROTOCOL.md` §5) and keeps the newest one.

use super::receive::serve;
use super::{ConnectionState, Current, Shared};
use crate::diagnostics::{DialFailure, TALLY_WINDOW, Tally, ms};
use crate::logging::Redacted;
use crate::protocol::CloseCode;
use iroh::EndpointId;
use iroh::endpoint::{ConnectingError, Connection, IncomingAddr};
use n0_future::task::AbortOnDropHandle;
use n0_future::time::Instant;
use n0_future::{FuturesUnordered, StreamExt, task, time};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::Instrument;

/// Direct (UDP) handshakes the connector processes at the same time. A browser never
/// receives direct attempts; elsewhere they arrive unscreened (any key can complete a
/// handshake, the guard hook rejects strangers only afterwards), so they share this
/// bounded pool once they proved their source address.
pub(super) const MAX_DIRECT_HANDSHAKES: usize = 8;

/// Handshakes the link's wallet may have in progress at once through the relay. An
/// honest wallet has one, two around a network change; the cap bounds what a faulty
/// relay could make the connector do in the wallet's name, and is separate from the
/// direct pool so that strangers can never keep the wallet out.
pub(super) const MAX_PEER_HANDSHAKES: usize = 4;

/// How long an incoming QUIC handshake may take.
pub(super) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Where an incoming attempt comes from, without its address.
pub(super) fn origin(addr: &IncomingAddr) -> &'static str {
    match addr {
        IncomingAddr::Relay { .. } => "relay",
        IncomingAddr::Ip(_) => "direct",
        _ => "custom",
    }
}

/// The connection the connector is serving, and the task serving it.
pub(super) struct Serving {
    current: Current,
    _task: AbortOnDropHandle<()>,
}

/// Connection attempts the connector turned away, summarised every minute so that
/// strangers or a faulty relay cannot flood the logs.
#[derive(Default)]
pub(super) struct TurnedAway {
    strangers: Tally,
    wallet_pool_full: Tally,
    direct_pool_full: Tally,
}

impl TurnedAway {
    fn summary_at(&self, unauthorized: &std::sync::Mutex<Tally>) -> Option<Instant> {
        [
            self.strangers.ends_at(),
            self.wallet_pool_full.ends_at(),
            self.direct_pool_full.ends_at(),
            lock(unauthorized).ends_at(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Reports the minutes that are over. The first occurrence of a warning was
    /// already logged in full, so only the repeats are.
    fn summarise(&mut self, unauthorized: &std::sync::Mutex<Tally>) {
        let now = Instant::now();
        let window_s = TALLY_WINDOW.as_secs();
        if let Some(count) = self.strangers.take_if_over(now) {
            tracing::info!(
                count,
                window_s,
                "ignored connection attempts from strangers through the relay in the last minute"
            );
        }
        if let Some(count) = self.wallet_pool_full.take_if_over(now)
            && count > 1
        {
            tracing::warn!(
                count,
                window_s,
                limit = MAX_PEER_HANDSHAKES,
                "ignored attempts in the wallet's name in the last minute: its handshake pool was full (a misbehaving relay?)"
            );
        }
        if let Some(count) = self.direct_pool_full.take_if_over(now)
            && count > 1
        {
            tracing::warn!(
                count,
                window_s,
                limit = MAX_DIRECT_HANDSHAKES,
                "ignored direct connection attempts in the last minute: the direct handshake pool was full"
            );
        }
        let rejected = lock(unauthorized).take_if_over(now);
        if let Some(count) = rejected
            && count > 1
        {
            tracing::warn!(
                count,
                window_s,
                "rejected connections from endpoints other than the link's wallet in the last minute (unauthorized)"
            );
        }
    }
}

pub(super) fn lock(tally: &std::sync::Mutex<Tally>) -> std::sync::MutexGuard<'_, Tally> {
    tally
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Connector Extension: accept the wallet's connections. A new connection replaces the
/// current one: the wallet only dials again when it believes the old one is gone
/// (network change, app restart), and the old one may take a while to time out.
///
/// This loop is the only place that changes the connector's connection and state, so
/// a connection that ends while a newer one is being set up cannot leave a stale
/// `Disconnected` behind.
///
/// Returns the connection being served once the session closes: its task must outlive
/// the wait for the confirmations it is writing.
pub(super) async fn accept(shared: &Arc<Shared>) -> Option<Serving> {
    let mut handshakes = FuturesUnordered::new();
    let mut pending = PendingHandshakes::default();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<(u64, Option<String>)>();
    let mut serving: Option<Serving> = None;
    let mut turned_away = TurnedAway::default();
    loop {
        let summary_at = turned_away.summary_at(&shared.unauthorized);
        tokio::select! {
            biased;
            () = shared.wait_closed() => return serving,
            Some((ended, reason)) = ended_rx.recv() => {
                if serving.as_ref().is_some_and(|serving| serving.current.number == ended)
                    && let Some(Serving { current, .. }) = serving.take()
                {
                    shared.connection.send_replace(None);
                    shared.log_disconnected(
                        &current,
                        reason.as_deref().unwrap_or("the session is closing"),
                    );
                    shared.record_disconnected(reason);
                    shared.set_state(ConnectionState::Disconnected);
                    shared.log_snapshot();
                }
            }
            Some(((from_peer, started), handshake)) = handshakes.next(), if !handshakes.is_empty() => {
                pending.finished(from_peer);
                let origin = if from_peer { "wallet_via_relay" } else { "direct" };
                let setup = Instant::elapsed(&started);
                let handshake_ms = ms(setup);
                let connection: Connection = match handshake {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        let outcome = match &error {
                            // The guard hook rejected it (and said so).
                            ConnectingError::LocallyRejected { .. } => "unauthorized",
                            other => DialFailure::of_connecting(other).as_str(),
                        };
                        let error = Redacted(&error).to_string();
                        // Attempts in the wallet's name matter; direct ones come from anyone.
                        if from_peer {
                            tracing::info!(origin, outcome, handshake_ms, error, "an incoming handshake failed");
                        } else {
                            tracing::debug!(origin, outcome, handshake_ms, error, "an incoming handshake failed");
                        }
                        shared.record_error("incoming handshake", error);
                        continue;
                    }
                    Err(_) => {
                        let timeout_ms = ms(HANDSHAKE_TIMEOUT);
                        if from_peer {
                            tracing::info!(origin, timeout_ms, handshake_ms, "an incoming handshake timed out");
                        } else {
                            tracing::debug!(origin, timeout_ms, handshake_ms, "an incoming handshake timed out");
                        }
                        shared.record_error("incoming handshake", "timed out");
                        continue;
                    }
                };
                // The guard hook already refused anyone else; checked again so that this
                // invariant never depends on hook plumbing alone.
                if connection.remote_id() != shared.peer {
                    tracing::error!(
                        remote = %connection.remote_id().fmt_short(),
                        "a connection from an endpoint other than the link's wallet got past the guard: closed it"
                    );
                    connection.close(CloseCode::Unauthorized.into(), b"unauthorized");
                    shared.record_error("incoming connection", "rejected an endpoint that is not the link's wallet");
                    continue;
                }
                let current = shared.current(connection.clone());
                shared.connection.send_replace(Some(current.clone()));
                // The wallet's presence is not reset here: it says it again on this connection,
                // and resetting it opened a moment, between this line and its datagram, in
                // which a wallet in the background read as in the foreground. One that predates
                // presence never said anything, and reads as in the foreground still.
                // Replacing the task stops serving the previous connection.
                if let Some(Serving { current: previous, .. }) = serving.take() {
                    previous.connection.close(CloseCode::Replaced.into(), b"replaced");
                    current.span.in_scope(|| {
                        tracing::info!(
                            replaced_conn = previous.number,
                            replaced_after_ms = ms(previous.connected_at.elapsed()),
                            "a new connection from the wallet replaced the current one"
                        );
                    });
                    shared.log_disconnected(&previous, "replaced by a newer connection from the wallet");
                }
                let ended = ended_tx.clone();
                let task_shared = shared.clone();
                let task_current = current.clone();
                let task = task::spawn(
                    async move {
                        let reason = serve(&task_shared, &task_current).await;
                        let _ = ended.send((task_current.number, reason.map(|ended| ended.reason)));
                    }
                    .instrument(current.span.clone()),
                );
                serving = Some(Serving {
                    current: current.clone(),
                    _task: AbortOnDropHandle::new(task),
                });
                shared.record_connected();
                shared.set_state(ConnectionState::Connected);
                shared.log_connected(&current, setup, None);
            }
            () = time::sleep_until(summary_at.unwrap_or_else(Instant::now)), if summary_at.is_some() => {
                turned_away.summarise(&shared.unauthorized);
            }
            incoming = shared.endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return serving;
                };
                let addr = incoming.remote_addr();
                let decision = admission(&addr, incoming.remote_addr_validated(), shared.peer, pending);
                let now = Instant::now();
                match decision {
                    Admission::Handshake { from_peer } => match incoming.accept() {
                        Ok(accepting) => {
                            pending.started(from_peer);
                            tracing::debug!(
                                origin = if from_peer { "wallet_via_relay" } else { "direct" },
                                pending_wallet = pending.from_peer,
                                pending_direct = pending.direct,
                                "an incoming handshake started"
                            );
                            handshakes.push(tagged((from_peer, now), time::timeout(HANDSHAKE_TIMEOUT, accepting)));
                        }
                        Err(error) => tracing::debug!(error = %Redacted(error), "could not accept an incoming connection"),
                    },
                    // Costs us nothing: a genuine sender answers, a spoofed source cannot.
                    Admission::ValidateAddress => {
                        tracing::debug!("asked a direct connection attempt to prove its source address first");
                        if let Err(error) = incoming.retry() {
                            error.into_incoming().ignore();
                        }
                    }
                    Admission::Ignore(why) => {
                        match why {
                            Ignored::Stranger => {
                                if let IncomingAddr::Relay { endpoint_id, .. } = &addr {
                                    tracing::debug!(
                                        remote = %endpoint_id.fmt_short(),
                                        "ignored a connection attempt from a stranger through the relay"
                                    );
                                }
                                turned_away.strangers.count(now);
                            }
                            Ignored::WalletPoolFull => {
                                if turned_away.wallet_pool_full.count(now) {
                                    tracing::warn!(
                                        limit = MAX_PEER_HANDSHAKES,
                                        "ignored an attempt in the wallet's name: it already has the most handshakes in progress (a misbehaving relay?); repeats are summarised every minute"
                                    );
                                } else {
                                    tracing::debug!("ignored an attempt in the wallet's name: its handshake pool is full");
                                }
                            }
                            Ignored::DirectPoolFull => {
                                if turned_away.direct_pool_full.count(now) {
                                    tracing::warn!(
                                        limit = MAX_DIRECT_HANDSHAKES,
                                        "ignored a direct connection attempt: the pool of direct handshakes is full; repeats are summarised every minute"
                                    );
                                } else {
                                    tracing::debug!("ignored a direct connection attempt: the direct handshake pool is full");
                                }
                            }
                        }
                        incoming.ignore();
                    }
                }
            }
        }
    }
}

/// Pairs a future's output with a tag, so futures of one type can be told apart in a
/// [`FuturesUnordered`].
pub(super) async fn tagged<T, F: Future>(tag: T, future: F) -> (T, F::Output) {
    (tag, future.await)
}

/// Incoming handshakes in progress, by origin.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct PendingHandshakes {
    /// Through the relay, from the link's wallet.
    pub(super) from_peer: usize,
    /// Direct (UDP) attempts, from anyone.
    pub(super) direct: usize,
}

impl PendingHandshakes {
    pub(super) fn started(&mut self, from_peer: bool) {
        *self.count(from_peer) += 1;
    }

    pub(super) fn finished(&mut self, from_peer: bool) {
        let count = self.count(from_peer);
        *count = count.saturating_sub(1);
    }

    fn count(&mut self, from_peer: bool) -> &mut usize {
        if from_peer {
            &mut self.from_peer
        } else {
            &mut self.direct
        }
    }
}

/// What to do with an incoming connection attempt, before any handshake work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    Handshake {
        /// Attested by the relay as coming from the link's wallet.
        from_peer: bool,
    },
    /// Ask the sender to prove it can receive at its source address first.
    ValidateAddress,
    Ignore(Ignored),
}

/// Why an incoming attempt is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ignored {
    /// Through the relay, from an endpoint other than the link's wallet.
    Stranger,
    /// From the link's wallet, which already has the most handshakes in progress.
    WalletPoolFull,
    /// A direct attempt while the direct pool is full.
    DirectPoolFull,
}

/// Through the relay the sender's id is attested before any handshake work: the
/// link's wallet gets its own small pool (strangers can never fill its way), anyone
/// else is ignored. Direct attempts (native connectors only; a browser has no UDP)
/// must first prove their source address, then share the bounded direct pool.
pub(super) fn admission(
    addr: &IncomingAddr,
    validated: bool,
    peer: EndpointId,
    pending: PendingHandshakes,
) -> Admission {
    match addr {
        IncomingAddr::Relay { endpoint_id, .. } if *endpoint_id == peer => {
            if pending.from_peer < MAX_PEER_HANDSHAKES {
                Admission::Handshake { from_peer: true }
            } else {
                Admission::Ignore(Ignored::WalletPoolFull)
            }
        }
        IncomingAddr::Relay { .. } => Admission::Ignore(Ignored::Stranger),
        _ if !validated => Admission::ValidateAddress,
        _ if pending.direct >= MAX_DIRECT_HANDSHAKES => Admission::Ignore(Ignored::DirectPoolFull),
        _ => Admission::Handshake { from_peer: false },
    }
}
