//! Knocks: a connector that starts tells its wallet to dial now (at the relay the wallet was
//! last seen on), and the wallet takes them as wake-ups. See `docs/PROTOCOL.md` §7.1.

use super::accept::origin;
use super::{ConnectionState, Shared};
use crate::SessionConfig;
use crate::config::Relays;
use crate::diagnostics::{TALLY_WINDOW, Tally, ms};
use crate::logging::Redacted;
use crate::protocol::{CloseCode, KNOCK_ALPN, KNOCK_RESTARTED_ALPN};
use iroh::endpoint::{ConnectOptions, ConnectingError, Connection, QuicTransportConfig};
use iroh::{EndpointAddr, RelayUrl};
use n0_future::time::Instant;
use n0_future::{FuturesUnordered, StreamExt, time};
use std::time::Duration;

/// How many knocks a wallet takes at once: a knock is one handshake, and nothing else.
pub(super) const KNOCKS_IN_FLIGHT: usize = 4;

/// How long a knock's handshake may take.
pub(super) const KNOCK_TIMEOUT: Duration = Duration::from_secs(3);

/// A knock's initial RTT estimate: about a relay's round trip.
pub(super) const KNOCK_INITIAL_RTT: Duration = Duration::from_millis(100);

/// Knocks closer together than this wake the wallet once: even its own connector cannot keep
/// it dialing.
pub(super) const KNOCK_MIN_GAP: Duration = Duration::from_secs(2);

/// Connector: how long after getting its relay back while still connected it watches for that
/// connection to drop (a dead one goes within a liveness deadline, at most 3 s) to knock then.
pub(super) const RELAY_RETURN_WATCH: Duration = Duration::from_secs(10);

/// Wallet: a connection at least this old is from before a connector that knocks as just
/// restarted ([`KNOCK_RESTARTED_ALPN`]): its knocks come within the first
/// `KNOCKS_AT` + `KNOCK_TIMEOUT` (9 s) of its start, so a younger one may be to the new run.
pub(super) const RESTARTED_KNOCK_MIN_AGE: Duration = Duration::from_secs(15);

pub(super) fn restarted_knock_min_age(config: &SessionConfig) -> Duration {
    #[cfg(test)]
    if let Some(age) = config.restarted_knock_min_age {
        return age;
    }
    let _ = config;
    RESTARTED_KNOCK_MIN_AGE
}

/// When a connector knocks after its session starts, or its relay comes back, while its wallet
/// is not connected.
pub(super) const KNOCKS_AT: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_secs(2),
    Duration::from_secs(6),
];

/// Wallet: takes the knocks of its connector — a connector that just started — and dials at
/// once instead of at its next retry. A knock carries nothing: the handshake proves the
/// connector's key (the guard turns away anybody else, as for every connection), and the
/// wallet closes it right after. Anything else is ignored, as before.
pub(super) async fn answer_knocks(shared: &Shared) {
    let mut ignored = Tally::default();
    let mut handshakes = FuturesUnordered::new();
    let mut last_wake: Option<Instant> = None;
    loop {
        let summary_at = ignored.ends_at();
        tokio::select! {
            biased;
            () = time::sleep_until(summary_at.unwrap_or_else(Instant::now)), if summary_at.is_some() => {
                if let Some(count) = ignored.take_if_over(Instant::now()) {
                    tracing::info!(
                        count,
                        window_s = TALLY_WINDOW.as_secs(),
                        "ignored incoming connection attempts in the last minute (the wallet takes only its connector's knocks)"
                    );
                }
            }
            Some(knock) = handshakes.next(), if !handshakes.is_empty() => {
                let knock: Result<Result<Connection, ConnectingError>, _> = knock;
                match knock {
                    Ok(Ok(connection)) if connection.alpn() == KNOCK_ALPN || connection.alpn() == KNOCK_RESTARTED_ALPN => {
                        let restarted = connection.alpn() == KNOCK_RESTARTED_ALPN;
                        connection.close(CloseCode::Knocked.into(), b"dialing");
                        let now = Instant::now();
                        let stale = restarted
                            .then(|| shared.connection.borrow().clone())
                            .flatten()
                            .filter(|current| current.connected_at.elapsed() >= restarted_knock_min_age(&shared.config));
                        // Connected already: nothing to wake, and nothing to check. A knock
                        // while connected comes from another process holding the same link (two
                        // logins at once, say) or from a connector that restarted without closing
                        // the old connection. Checking the connection then is no answer: with two
                        // holders the check fails on a live connection, and cutting it loses what
                        // it carries — a signature the person just approved. A dead connection
                        // ends on its own (QUIC's idle timeout) and the wallet redials then.
                        if let Some(current) = stale {
                            // The only holder of the link just started: the connection is to
                            // its earlier run, which ended without closing it. One made since it
                            // started (to an earlier knock of the same start) is younger than
                            // `RESTARTED_KNOCK_MIN_AGE`, and stays.
                            tracing::info!(
                                conn = current.number,
                                connected_ms = ms(current.connected_at.elapsed()),
                                "the connector restarted: its old connection is dead, dropping it and dialing now"
                            );
                            // Counted as a knock: the dial loop, seeing it when the connection
                            // ends, dials at once instead of after the usual pause.
                            shared.knocks.send_modify(|knocks| *knocks = knocks.wrapping_add(1));
                            current.connection.close(CloseCode::Restarted.into(), b"connector restarted");
                        } else if *shared.state.borrow() == ConnectionState::Connected {
                            tracing::debug!("the connector knocked while connected: nothing to do");
                        } else if last_wake.is_some_and(|last| now.duration_since(last) < KNOCK_MIN_GAP) {
                            tracing::debug!("the connector knocked again moments after: already dialing");
                        } else {
                            last_wake = Some(now);
                            tracing::info!(
                                state = shared.state.borrow().as_str(),
                                "the connector knocked: it is up and waiting, dialing it now"
                            );
                            shared.knocks.send_modify(|knocks| *knocks = knocks.wrapping_add(1));
                            // A wake-up: a waiting dial goes now, a connection is checked.
                            shared.network.send_modify(|generation| *generation = generation.wrapping_add(1));
                        }
                    }
                    Ok(Ok(connection)) => connection.close(CloseCode::Unauthorized.into(), b"knocks only"),
                    Ok(Err(error)) => tracing::debug!(error = %Redacted(&error), "an incoming knock failed"),
                    Err(_) => tracing::debug!(timeout_ms = ms(KNOCK_TIMEOUT), "an incoming knock timed out"),
                }
            }
            incoming = shared.endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return;
                };
                if handshakes.len() >= KNOCKS_IN_FLIGHT {
                    ignored.count(Instant::now());
                    incoming.ignore();
                    continue;
                }
                let from = origin(&incoming.remote_addr());
                match incoming.accept() {
                    Ok(accepting) => handshakes.push(time::timeout(KNOCK_TIMEOUT, accepting)),
                    Err(error) => {
                        tracing::debug!(
                            origin = from,
                            error = %Redacted(&error),
                            "ignored an incoming connection attempt"
                        );
                        ignored.count(Instant::now());
                    }
                }
            }
        }
    }
}

/// Connector: knocks for its wallet as soon as the session starts, and twice more while the
/// wallet has not connected — if it knows where the wallet is (a custom relay, or the hint of
/// [`SessionConfig::with_peer_relay`]). Returns when done.
pub(super) async fn knock_on_start(shared: &Shared) {
    let Some(relay) = shared.config.knock_relay().cloned() else {
        return;
    };
    #[cfg(test)]
    if shared.config.skip_start_knocks {
        return;
    }
    // On a custom relay, once this end reaches it: it is the relay the knock goes through, and
    // that takes milliseconds. On n0's public relays, at once: the knock goes to the WALLET's
    // relay over a connection of its own, while choosing this end's home relay takes seconds
    // (the endpoint measures them all first).
    if matches!(shared.config.relays(), Relays::Custom(_)) {
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            () = shared.endpoint.online() => {}
        }
    }
    knock_round(shared, &relay, shared.started_at).await;
}

/// Connector: knocks for its wallet again each time this end gets its relay back after losing
/// it while the wallet is not connected — the computer woke from sleep, the network came
/// back. Until then the wallet cannot reach this end, and one that has been retrying for a
/// while does so only every 30 s; the knock brings it at once. As on start, the knock says
/// "restarted" for a sole holder: this end's connection is gone, so a connection the wallet
/// still holds to it is dead. Returns when the session closes.
pub(super) async fn knock_when_relay_returns(shared: &Shared) {
    let Some(relay) = shared.config.knock_relay().cloned() else {
        return;
    };
    let mut regained = shared.relay_regained.subscribe();
    loop {
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            changed = regained.changed() => if changed.is_err() {
                return;
            },
        }
        regained.mark_unchanged();
        // Still connected: the connection may have died during the outage, and its liveness
        // check drop it within seconds (the host reports the wake-up as a network change).
        let mut state = shared.state.subscribe();
        let dropped = tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            dropped = time::timeout(
                RELAY_RETURN_WATCH,
                state.wait_for(|state| *state != ConnectionState::Connected),
            ) => dropped.is_ok(),
        };
        if !dropped {
            continue;
        }
        tracing::info!("the relay is back and the wallet is not connected: knocking for it");
        knock_round(shared, &relay, Instant::now()).await;
        // A relay that came back again during the round: this round was for it.
        regained.mark_unchanged();
    }
}

/// Knocks at [`KNOCKS_AT`] from `from` while the wallet is not connected; returns at once
/// when the session closes (closing never waits for a knock, nor for the next one).
async fn knock_round(shared: &Shared, relay: &RelayUrl, from: Instant) {
    for at in KNOCKS_AT {
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            () = time::sleep_until(from + at) => {}
        }
        if *shared.state.borrow() == ConnectionState::Connected {
            return;
        }
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            _ = knock(shared, relay, shared.config.sole_holder) => {}
        }
    }
}

/// One knock at `relay`: whether the wallet took it. `restarted`: this connector just started
/// and is its link's only holder ([`KNOCK_RESTARTED_ALPN`]).
pub(super) async fn knock(shared: &Shared, relay: &RelayUrl, restarted: bool) -> bool {
    let started = Instant::now();
    let addr = EndpointAddr::new(shared.peer).with_relay_url(relay.clone());
    // Its own transport settings: an initial RTT close to a relay's, not QUIC's 333 ms guess, so
    // a knock retries quickly while the wallet is not up, and a knock abandoned when the session
    // closes drains in a fraction of a second instead of holding up the endpoint for 3.
    let mut options = ConnectOptions::new().with_transport_config(
        QuicTransportConfig::builder()
            .initial_rtt(KNOCK_INITIAL_RTT)
            .max_concurrent_bidi_streams(0u32.into())
            .max_concurrent_uni_streams(0u32.into())
            .build(),
    );
    let alpn = if restarted {
        options = options.with_additional_alpns(vec![KNOCK_ALPN.to_vec()]);
        KNOCK_RESTARTED_ALPN
    } else {
        KNOCK_ALPN
    };
    let knocking = async {
        shared
            .endpoint
            .connect_with_opts(addr, alpn, options)
            .await
            .map_err(|error| Redacted(error).to_string())?
            .await
            .map_err(|error| Redacted(error).to_string())
    };
    match time::timeout(KNOCK_TIMEOUT, knocking).await {
        Ok(Ok(connection)) => {
            // The wallet closes it as soon as it took it.
            let _ = time::timeout(KNOCK_TIMEOUT, connection.closed()).await;
            tracing::info!(
                elapsed_ms = ms(started.elapsed()),
                "knocked: the wallet took it and dials now"
            );
            true
        }
        Ok(Err(error)) => {
            // A wallet that predates knocks refuses them; one that is closed is not there.
            tracing::debug!(
                elapsed_ms = ms(started.elapsed()),
                error,
                "the knock did not get through"
            );
            false
        }
        Err(_) => {
            tracing::debug!(
                timeout_ms = ms(KNOCK_TIMEOUT),
                "the knock got no answer: the wallet is not up"
            );
            false
        }
    }
}
