use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, QuicTransportConfig, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode};
use n0_future::task::{self, AbortOnDropHandle};
use n0_future::{FuturesUnordered, StreamExt, time};
use tokio::sync::{Mutex, Notify, mpsc, watch};

use crate::guard::PeerGuard;
use crate::protocol::{self, ALPN, CloseCode, Incoming};
use crate::{ConnectionPassword, Error, Role, SendError, SessionConfig};

/// Events buffered for the host before the session stops reading from the peer.
const EVENT_BUFFER: usize = 64;

/// Incoming handshakes processed at the same time by the Connector Extension. Only
/// the link's wallet can complete one, so this only bounds the work a stranger who
/// guessed the endpoint id can cause.
const MAX_PENDING_HANDSHAKES: usize = 4;

/// How long an incoming QUIC handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Streams the peer may have open at once. Messages are read one at a time, so this
/// only caps how much the peer can queue up.
const MAX_CONCURRENT_STREAMS: u32 = 16;

/// State of the connection to the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// The wallet is dialing the Connector Extension (and keeps retrying).
    Connecting,
    /// Messages can be exchanged.
    Connected,
    /// No connection. The Connector Extension starts here and waits for the wallet.
    Disconnected,
}

/// Something that happened on a [`Session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// The connection state changed.
    StateChanged(ConnectionState),
    /// A message arrived from the peer. It has already been confirmed to the peer.
    Message(String),
}

/// One end of a Radix Connect link over iroh.
///
/// A session owns an iroh endpoint whose key is derived from the link's password and
/// role, keeps a single connection to the link's peer up (the wallet dials and
/// re-dials, the Connector Extension accepts and lets a newer connection replace an
/// older one), and exchanges messages over it.
///
/// Dropping a session stops it abruptly; call [`close`](Self::close) to tell the peer.
#[derive(Debug)]
pub struct Session {
    shared: Arc<Shared>,
    events: Mutex<mpsc::Receiver<SessionEvent>>,
    _driver: AbortOnDropHandle<()>,
}

#[derive(Debug)]
struct Shared {
    endpoint: Endpoint,
    role: Role,
    peer: EndpointId,
    config: SessionConfig,
    connection: watch::Sender<Option<Connection>>,
    state: watch::Sender<ConnectionState>,
    closed: watch::Sender<bool>,
    events: mpsc::Sender<SessionEvent>,
    /// Cuts the wallet's wait before the next dial attempt short.
    redial: Notify,
}

impl Session {
    /// Starts the `role` end of the link secured by `password`.
    ///
    /// This only creates the local endpoint; connecting happens in the background
    /// and is reported through [`next_event`](Self::next_event).
    pub async fn start(
        password: &ConnectionPassword,
        role: Role,
        config: SessionConfig,
    ) -> Result<Self, Error> {
        let peer = password.endpoint_id(role.peer());
        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into())
            .max_concurrent_uni_streams(0u32.into())
            .build();
        // Only the Connector Extension accepts connections: an endpoint without ALPNs
        // refuses every incoming handshake.
        let alpns = match role {
            Role::Connector => vec![ALPN.to_vec()],
            Role::Wallet => Vec::new(),
        };
        // `Minimal` has no address lookup: the endpoint publishes nothing about itself
        // (no DNS / pkarr records) and is found only through the configured relay.
        #[allow(unused_mut)]
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(password.secret_key(role))
            .alpns(alpns)
            .relay_mode(RelayMode::custom([config.relay_url.clone()]))
            .transport_config(transport)
            .hooks(PeerGuard::new(peer));
        #[cfg(test)]
        {
            if config.insecure_skip_relay_cert_verify {
                builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
            }
            if config.relay_only {
                builder = builder.clear_ip_transports();
            }
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|error| Error::Bind(error.to_string()))?;

        let initial_state = match role {
            Role::Wallet => ConnectionState::Connecting,
            Role::Connector => ConnectionState::Disconnected,
        };
        let (events_tx, events_rx) = mpsc::channel(EVENT_BUFFER);
        let shared = Arc::new(Shared {
            endpoint,
            role,
            peer,
            config,
            connection: watch::Sender::new(None),
            state: watch::Sender::new(initial_state),
            closed: watch::Sender::new(false),
            events: events_tx,
            redial: Notify::new(),
        });
        tracing::info!(
            role = ?role,
            local = %shared.endpoint.id().fmt_short(),
            peer = %peer.fmt_short(),
            relay = %shared.config.relay_url,
            "radix connect iroh session started"
        );
        let driver = AbortOnDropHandle::new(task::spawn(drive(shared.clone())));
        Ok(Self {
            shared,
            events: Mutex::new(events_rx),
            _driver: driver,
        })
    }

    /// The id of this end of the link.
    pub fn local_id(&self) -> EndpointId {
        self.shared.endpoint.id()
    }

    /// The id of the other end of the link: the only endpoint this session talks to.
    pub fn peer_id(&self) -> EndpointId {
        self.shared.peer
    }

    /// Which end of the link this session is.
    pub fn role(&self) -> Role {
        self.shared.role
    }

    /// The current connection state.
    pub fn state(&self) -> ConnectionState {
        *self.shared.state.borrow()
    }

    /// Sends one message to the peer and waits until the peer confirms it.
    ///
    /// Fails immediately with [`SendError::NotConnected`] when there is no
    /// connection, like the WebRTC transport does, so callers can queue and retry.
    pub async fn send(&self, message: &str) -> Result<(), SendError> {
        if self.shared.is_closed() {
            return Err(SendError::Closed);
        }
        let connection = self
            .shared
            .connection
            .borrow()
            .clone()
            .ok_or(SendError::NotConnected)?;
        protocol::send_message(
            &connection,
            message,
            self.shared.config.max_message_size,
            self.shared.config.ack_timeout,
        )
        .await
    }

    /// Waits for the next event. Returns `None` once the session is closed.
    ///
    /// Events are buffered; while the host does not consume them the session stops
    /// accepting messages, so the peer's sends time out instead of piling up.
    pub async fn next_event(&self) -> Option<SessionEvent> {
        let mut events = self.events.lock().await;
        tokio::select! {
            biased;
            () = self.shared.wait_closed() => None,
            event = events.recv() => event,
        }
    }

    /// Tells the session that the device's network changed (Wi-Fi to mobile data, new
    /// address, VPN...). iroh re-checks its paths and a waiting wallet dials again at
    /// once. Mobile hosts should call it from their connectivity callbacks: iroh cannot
    /// detect network changes by itself on Android.
    pub async fn network_changed(&self) {
        self.shared.redial.notify_one();
        self.shared.endpoint.network_change().await;
    }

    /// Closes the connection (telling the peer) and the endpoint. Idempotent.
    pub async fn close(&self) {
        if self.shared.closed.send_replace(true) {
            return;
        }
        if let Some(connection) = self.shared.connection.send_replace(None) {
            connection.close(CloseCode::Normal.into(), b"closed");
        }
        self.shared.endpoint.close().await;
        tracing::info!(local = %self.local_id().fmt_short(), "radix connect iroh session closed");
    }
}

impl Shared {
    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    async fn wait_closed(&self) {
        let mut closed = self.closed.subscribe();
        // `wait_for` only fails if the sender is dropped, which outlives `self`.
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// Queues an event for the host. Returns `false` once the session is closing.
    async fn emit(&self, event: SessionEvent) -> bool {
        tokio::select! {
            biased;
            () = self.wait_closed() => false,
            sent = self.events.send(event) => sent.is_ok(),
        }
    }

    async fn set_state(&self, state: ConnectionState) {
        let changed = self.state.send_if_modified(|current| {
            let changed = *current != state;
            *current = state;
            changed
        });
        if changed {
            tracing::debug!(?state, peer = %self.peer.fmt_short(), "connection state changed");
            self.emit(SessionEvent::StateChanged(state)).await;
        }
    }

    /// Forgets `connection` if it is still the current one. Returns whether it was.
    fn clear_connection(&self, connection: &Connection) -> bool {
        self.connection.send_if_modified(|current| {
            let is_current = current
                .as_ref()
                .is_some_and(|c| c.stable_id() == connection.stable_id());
            if is_current {
                *current = None;
            }
            is_current
        })
    }
}

async fn drive(shared: Arc<Shared>) {
    match shared.role {
        Role::Wallet => dial(&shared).await,
        Role::Connector => accept(&shared).await,
    }
}

/// Wallet: keep dialing the Connector Extension, and serve each connection until it
/// ends.
async fn dial(shared: &Arc<Shared>) {
    let peer_addr = EndpointAddr::new(shared.peer).with_relay_url(shared.config.relay_url.clone());
    let mut delay = shared.config.min_reconnect_delay;
    loop {
        shared.set_state(ConnectionState::Connecting).await;
        let attempt = time::timeout(
            shared.config.connect_timeout,
            shared.endpoint.connect(peer_addr.clone(), ALPN),
        );
        let outcome = tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            outcome = attempt => outcome,
        };
        match outcome {
            Ok(Ok(connection)) => {
                delay = shared.config.min_reconnect_delay;
                shared.connection.send_replace(Some(connection.clone()));
                serve(shared, connection).await;
            }
            Ok(Err(error)) => tracing::debug!(%error, "could not reach the connector extension"),
            Err(_) => tracing::debug!("dialing the connector extension timed out"),
        }
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            () = shared.redial.notified() => delay = shared.config.min_reconnect_delay,
            () = time::sleep(delay) => delay = (delay * 2).min(shared.config.max_reconnect_delay),
        }
    }
}

/// Connector Extension: accept the wallet's connections. A new connection replaces the
/// current one: the wallet only dials again when it believes the old one is gone
/// (network change, app restart), and the old one may take a while to time out.
async fn accept(shared: &Arc<Shared>) {
    let mut handshakes = FuturesUnordered::new();
    let mut _serving: Option<AbortOnDropHandle<()>> = None;
    loop {
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            Some(handshake) = handshakes.next(), if !handshakes.is_empty() => {
                let connection: Connection = match handshake {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        tracing::debug!(%error, "incoming handshake failed");
                        continue;
                    }
                    Err(_) => {
                        tracing::debug!("incoming handshake timed out");
                        continue;
                    }
                };
                // The guard hook already refused anyone else; checked again so that this
                // invariant never depends on hook plumbing alone.
                if connection.remote_id() != shared.peer {
                    connection.close(CloseCode::Unauthorized.into(), b"unauthorized");
                    continue;
                }
                if let Some(previous) = shared.connection.send_replace(Some(connection.clone())) {
                    previous.close(CloseCode::Replaced.into(), b"replaced");
                }
                // Replacing the handle stops serving the previous connection.
                _serving = Some(AbortOnDropHandle::new(task::spawn(serve_owned(
                    shared.clone(),
                    connection,
                ))));
            }
            incoming = shared.endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return;
                };
                if handshakes.len() >= MAX_PENDING_HANDSHAKES {
                    incoming.refuse();
                    continue;
                }
                match incoming.accept() {
                    Ok(accepting) => handshakes.push(time::timeout(HANDSHAKE_TIMEOUT, accepting)),
                    Err(error) => tracing::debug!(%error, "could not accept an incoming connection"),
                }
            }
        }
    }
}

async fn serve_owned(shared: Arc<Shared>, connection: Connection) {
    serve(&shared, connection).await;
}

/// Delivers the peer's messages, one stream at a time, until the connection ends.
async fn serve(shared: &Shared, connection: Connection) {
    tracing::info!(peer = %shared.peer.fmt_short(), "connected to the peer");
    shared.set_state(ConnectionState::Connected).await;
    loop {
        let stream = tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            stream = connection.accept_bi() => stream,
        };
        let (mut send, mut recv) = match stream {
            Ok(stream) => stream,
            Err(error) => {
                tracing::info!(%error, "connection to the peer ended");
                break;
            }
        };
        let read = time::timeout(
            shared.config.receive_timeout,
            protocol::read_message(&mut send, &mut recv, shared.config.max_message_size),
        )
        .await;
        match read {
            Ok(Ok(Incoming::Message(message))) => {
                if !shared.emit(SessionEvent::Message(message)).await {
                    return;
                }
                protocol::acknowledge(&mut send).await;
            }
            Ok(Ok(Incoming::Refused)) => {}
            Ok(Err(error)) => tracing::debug!(%error, "could not read an incoming message"),
            Err(_) => tracing::warn!("an incoming message did not arrive in time"),
        }
    }
    if shared.clear_connection(&connection) && !shared.is_closed() {
        shared.set_state(ConnectionState::Disconnected).await;
    }
}

#[cfg(test)]
mod tests;
