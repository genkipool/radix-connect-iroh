//! Serving a connection: the peer's messages, one stream at a time, handed to the host and
//! confirmed once it took them; the wallet's datagrams (presence, request inventory); and the
//! path the connection takes.

use super::liveness::check_liveness;
use super::{ACK_FLUSH_TIMEOUT, Current, Delivery, Ended, Shared};
use crate::diagnostics::{PathKind, ms};
use crate::logging::Redacted;
use crate::protocol::{Acknowledged, Incoming};
use crate::{Role, diagnostics, protocol, requests};
use iroh::TransportAddr;
use iroh::endpoint::{Connection, PathEvent, RecvStream, SendStream};
use n0_future::time::Instant;
use n0_future::{StreamExt, task, time};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::{oneshot, watch};
use tracing::Instrument;

/// Serves a connection until it ends or the session closes: delivers the peer's
/// messages and checks that the peer still answers when the network changes. Returns
/// why the connection ended, or `None` if it did not end because the session closed.
pub(super) async fn serve(shared: &Shared, current: &Current) -> Option<Ended> {
    tokio::select! {
        ended = serve_streams(shared, current) => ended.map(|reason| Ended {
            reason,
            unresponsive: false,
        }),
        ended = check_liveness(shared, current) => Some(ended),
    }
}

/// Delivers the peer's messages, one stream at a time, until the connection ends or
/// the session closes. Each message is confirmed only once the host took it. Returns
/// why the connection ended, or `None` if it did not end because the session closed.
pub(super) async fn serve_streams(shared: &Shared, current: &Current) -> Option<String> {
    let connection = &current.connection;
    // Subscribed before reading the current path, so no switch goes unnoticed.
    let mut path_events = connection.path_events();
    let initial = diagnostics::selected_path(connection).0;
    let mut paths = PathLog {
        connected_at: current.connected_at,
        kind: initial,
        direct_seen: initial == Some(PathKind::Direct),
    };
    // Only a connector hears datagrams; one whose connection stopped yielding them stops asking.
    let mut datagrams = shared.role == Role::Connector;
    loop {
        let stream = tokio::select! {
            biased;
            () = shared.wait_closed() => return None,
            Some(event) = path_events.next() => {
                paths.log(connection, &event);
                continue;
            }
            stream = connection.accept_bi() => stream,
            datagram = connection.read_datagram(), if datagrams => {
                match datagram.as_deref() {
                    Ok(bytes) => {
                        if let Some(in_background) = protocol::read_presence(bytes) {
                            shared.heard_presence(in_background);
                        } else if let Some(inventory) = requests::read_inventory(bytes) {
                            shared.heard_inventory(current, &inventory);
                        } else {
                            tracing::debug!("ignored a datagram of an unknown kind");
                        }
                    }
                    Err(_) => datagrams = false,
                }
                continue;
            }
        };
        let (send, recv) = match stream {
            Ok(stream) => stream,
            Err(error) => return Some(diagnostics::describe_connection_end(&error)),
        };
        let seq = shared.received.fetch_add(1, Ordering::Relaxed) + 1;
        let span = tracing::info_span!("receive", recv_seq = seq);
        if !receive(shared, send, recv, seq).instrument(span).await {
            return None;
        }
    }
}

/// Reads one message from a stream the peer opened, hands it to the host and confirms
/// it once the host took it. Returns `false` once the session is closing.
pub(super) async fn receive(
    shared: &Shared,
    send: SendStream,
    mut recv: RecvStream,
    seq: u64,
) -> bool {
    let config = &shared.config;
    let started = Instant::now();
    let read = time::timeout(
        config.receive_timeout,
        protocol::read_message(send, &mut recv, config.max_message_size),
    )
    .await;
    let (message, answer) = match read {
        Ok(Ok(Incoming::Message(message, answer))) => (message, answer),
        // Logged where they were refused or found incomplete.
        Ok(Ok(Incoming::Refused)) => {
            shared.record_error("receive", "refused an oversized or malformed message");
            return true;
        }
        Ok(Ok(Incoming::Incomplete)) => return true,
        // Expected, not an error: the peer's network changed or its app woke up.
        Ok(Ok(Incoming::Probe)) => {
            tracing::debug!("answered a liveness check from the peer");
            return true;
        }
        Ok(Err(error)) => {
            if protocol::sender_abandoned(&error) {
                tracing::debug!(
                    "the peer abandoned the message before it was complete (its send was cancelled or timed out): discarded"
                );
            } else {
                tracing::debug!(error = %Redacted(&error), "could not read an incoming message");
                shared.record_error("receive", &error);
            }
            return true;
        }
        Err(_) => {
            let _ = recv.stop(0u32.into());
            tracing::warn!(
                timeout_ms = ms(config.receive_timeout),
                elapsed_ms = ms(started.elapsed()),
                "an incoming message did not arrive in time: discarded"
            );
            shared.record_error("receive", "a message did not arrive in time");
            return true;
        }
    };
    let bytes = message.len();
    tracing::debug!(
        bytes,
        read_ms = ms(started.elapsed()),
        queued_for_host = shared.queued_for_host(),
        "message received: handing it to the host"
    );
    let (taken, on_taken) = oneshot::channel();
    let queued_at = Instant::now();
    let delivery = Delivery {
        message,
        taken,
        seq,
        queued_at,
    };
    if !shared.deliver(delivery).await {
        tracing::debug!("the session is closing: the message was not handed to the host");
        return false;
    }
    // If the peer stops waiting first, dropping `on_taken` withdraws the message from
    // the host, and dropping `answer` resets the stream. A message the host already
    // took is confirmed even if the session is closing at the same moment (best effort:
    // closing may still cut it off).
    let host_slow = time::sleep(config.host_slow_after);
    tokio::pin!(host_slow, on_taken);
    let mut warned = false;
    let owed = loop {
        tokio::select! {
            biased;
            taken = &mut on_taken => break taken.ok(),
            () = shared.wait_closed() => {
                tracing::debug!(
                    waited_ms = ms(queued_at.elapsed()),
                    "the session is closing before the host took the message: withdrawn"
                );
                return false;
            }
            () = answer.peer_gave_up() => {
                tracing::info!(
                    bytes,
                    waited_ms = ms(queued_at.elapsed()),
                    "withdrew a message the host had not taken: the peer gave up waiting or the connection ended"
                );
                return true;
            }
            () = &mut host_slow, if !warned => {
                warned = true;
                tracing::warn!(
                    bytes,
                    waited_ms = ms(queued_at.elapsed()),
                    threshold_ms = ms(config.host_slow_after),
                    "the host has not taken a message yet: hosts must keep reading events, or the peer's sends time out"
                );
            }
        }
    };
    let Some(owed) = owed else {
        tracing::debug!("the message was dropped before the host took it");
        return true;
    };
    let flushing = Instant::now();
    let Some(confirmation) = answer.confirm().await else {
        drop(owed);
        log_confirmation(Acknowledged::Failed, flushing);
        return true;
    };
    // The next message is read at once: the peer's acknowledgement of this confirmation is
    // awaited on the side (still counted in `acks_in_flight`, so closing waits for it), not
    // before the next stream, which made each message of a burst wait one more round trip.
    // At most one per stream the peer may have open, each for ACK_FLUSH_TIMEOUT at most.
    task::spawn(
        async move {
            let acknowledged = confirmation.acknowledged(ACK_FLUSH_TIMEOUT).await;
            drop(owed);
            log_confirmation(acknowledged, flushing);
        }
        .instrument(tracing::Span::current()),
    );
    true
}

fn log_confirmation(acknowledged: Acknowledged, flushing: Instant) {
    match acknowledged {
        Acknowledged::Flushed => tracing::debug!(
            flush_ms = ms(flushing.elapsed()),
            "confirmation sent and acknowledged by the peer"
        ),
        Acknowledged::Unflushed => tracing::debug!(
            flush_timeout_ms = ms(ACK_FLUSH_TIMEOUT),
            "confirmation sent; the peer did not acknowledge it in time"
        ),
        Acknowledged::Failed => tracing::info!(
            "the host took a message but its confirmation could not be sent (the peer stopped waiting or the connection ended): the peer may send it again"
        ),
    }
}

/// A confirmation owed to the peer, counted in `acks_in_flight` from the moment the
/// host takes the message until it is written and acknowledged, or abandoned (dropped
/// with the channel or the future that holds it).
#[derive(Debug)]
pub(super) struct OwedConfirmation(Arc<watch::Sender<usize>>);

impl OwedConfirmation {
    pub(super) fn new(in_flight: &Arc<watch::Sender<usize>>) -> Self {
        in_flight.send_modify(|count| *count += 1);
        Self(Arc::clone(in_flight))
    }
}

impl Drop for OwedConfirmation {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count = count.saturating_sub(1));
    }
}

/// Logs when the connection switches between the relay and a direct path. Never logs
/// addresses: they are the users' IP addresses, and logs get shared.
pub(super) struct PathLog {
    connected_at: Instant,
    /// The kind of the selected path.
    kind: Option<PathKind>,
    direct_seen: bool,
}

impl PathLog {
    fn log(&mut self, connection: &Connection, event: &PathEvent) {
        let kind = |addr: &TransportAddr| match addr {
            TransportAddr::Relay(_) => PathKind::Relay,
            _ => PathKind::Direct,
        };
        match event {
            PathEvent::Selected {
                id, remote_addr, ..
            } => {
                let path = kind(remote_addr);
                let since_connected_ms = ms(self.connected_at.elapsed());
                let rtt_ms = connection.rtt(*id).map(ms);
                let previous = self.kind.replace(path);
                if path == PathKind::Direct && !self.direct_seen {
                    self.direct_seen = true;
                    tracing::info!(
                        path = path.as_str(),
                        rtt_ms,
                        first_direct_ms = since_connected_ms,
                        "the connection now goes directly between the devices"
                    );
                } else if previous != Some(path) {
                    tracing::info!(
                        path = path.as_str(),
                        rtt_ms,
                        since_connected_ms,
                        "the connection switched paths"
                    );
                } else {
                    // Between two direct paths (another interface or address family):
                    // iroh can do it several times a second while it probes.
                    tracing::debug!(
                        path = path.as_str(),
                        rtt_ms,
                        since_connected_ms,
                        "the connection moved to another path of the same kind"
                    );
                }
            }
            PathEvent::Opened { remote_addr, .. } => {
                tracing::trace!(path = kind(remote_addr).as_str(), "a network path opened");
            }
            PathEvent::Closed { remote_addr, .. } => {
                tracing::trace!(path = kind(remote_addr).as_str(), "a network path closed");
            }
            PathEvent::Lagged { missed, .. } => {
                let (path, _) = diagnostics::selected_path(connection);
                tracing::debug!(
                    missed,
                    path = path.map(PathKind::as_str),
                    "missed path events; current path"
                );
            }
            _ => {}
        }
    }
}
