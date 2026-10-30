use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use iroh::address_lookup::DnsAddressLookup;
use iroh::address_lookup::{AddrFilter, PkarrPublisher, PkarrResolver};
use iroh::endpoint::{Connection, IncomingAddr, QuicTransportConfig, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, Watcher};
use n0_future::task::{self, AbortOnDropHandle};
use n0_future::{FuturesUnordered, StreamExt, time};
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};

use crate::config::Relays;
use crate::diagnostics::{self, Diagnostics};
use crate::guard::PeerGuard;
use crate::protocol::{self, ALPN, CloseCode, Incoming};
use crate::{ConnectionPassword, Error, Role, SendError, SessionConfig};

/// Events buffered for the host. At most one of them is a message: the next message is
/// only read once the host has taken the previous one.
const EVENT_BUFFER: usize = 64;

/// How long creating the local endpoint may take.
const BIND_TIMEOUT: Duration = Duration::from_secs(15);

/// How long [`Session::close`] waits for the endpoint to close gracefully.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Incoming handshakes the Connector Extension processes at the same time.
///
/// Connections arriving through the relay are screened before any handshake work: the
/// relay attests the sender's endpoint id, and anyone but the link's wallet is ignored.
/// Only direct (UDP) connection attempts, which a browser never receives, reach this
/// pool unscreened; any key can complete a handshake, the guard hook rejects strangers
/// only afterwards.
const MAX_PENDING_HANDSHAKES: usize = 8;

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
    /// A message arrived from the peer. Taking it from
    /// [`next_event`](Session::next_event) confirms it to the peer.
    Message(String),
}

/// What the session queues for the host.
#[derive(Debug)]
enum Queued {
    State(ConnectionState),
    /// `taken` tells the stream that delivered the message to confirm it.
    Message {
        message: String,
        taken: oneshot::Sender<()>,
    },
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
    events: Mutex<mpsc::Receiver<Queued>>,
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
    /// Set by the driver once it stopped and closed the endpoint.
    stopped: watch::Sender<bool>,
    events: mpsc::Sender<Queued>,
    /// Cuts the wallet's wait before the next dial attempt short.
    redial: Notify,
    /// What went wrong lately, for [`Session::diagnostics`].
    trouble: std::sync::Mutex<Trouble>,
}

/// The parts of [`Diagnostics`] that iroh does not keep for us.
#[derive(Debug, Default)]
struct Trouble {
    last_error: Option<String>,
    failed_attempts: u32,
    connected_at: Option<time::Instant>,
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
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(password.secret_key(role))
            .alpns(alpns)
            .transport_config(transport)
            .hooks(PeerGuard::new(peer));
        let builder = with_relays(builder, &config, role);
        let endpoint = time::timeout(BIND_TIMEOUT, builder.bind())
            .await
            .map_err(|_| Error::Bind("timed out".to_owned()))?
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
            stopped: watch::Sender::new(false),
            events: events_tx,
            redial: Notify::new(),
            trouble: std::sync::Mutex::default(),
        });
        tracing::info!(
            role = ?role,
            local = %shared.endpoint.id().fmt_short(),
            peer = %peer.fmt_short(),
            relays = ?shared.config.relays,
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

    /// Sends one message to the peer and waits until the peer confirms it, which the
    /// peer does when its host takes the message from its session.
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
        let sent = protocol::send_message(
            &connection,
            message,
            self.shared.config.max_message_size,
            self.shared.config.ack_timeout,
        )
        .await;
        if let Err(error) = &sent {
            tracing::warn!(%error, bytes = message.len(), "could not send a message to the peer");
            self.shared.record_error("send", error);
        }
        sent
    }

    /// A snapshot of the session's connectivity, for logs (its `Display` is one line)
    /// and diagnostics screens. Cheap; contains no secrets.
    pub fn diagnostics(&self) -> Diagnostics {
        let shared = &self.shared;
        let relays = shared.endpoint.home_relay_status().get();
        let (path, rtt) = shared
            .connection
            .borrow()
            .as_ref()
            .map_or((None, None), diagnostics::selected_path);
        let relay_url = match &shared.config.relays {
            Relays::Custom(url) => Some(url.clone()),
            // The public relay this end ended up with, once it has one.
            Relays::Public => relays
                .iter()
                .find(|relay| relay.is_connected())
                .or(relays.first())
                .map(|relay| relay.url().clone()),
        };
        // iroh reports its home relay a little after a connection already travels
        // through the relay: talking to the peer through it counts as connected.
        let relay_connected = relays.iter().any(|relay| relay.is_connected())
            || path == Some(diagnostics::PathKind::Relay);
        let relay_error = relays
            .iter()
            .find_map(|relay| relay.last_error().map(|error| error.to_string()));
        let trouble = shared.trouble();
        Diagnostics {
            role: shared.role,
            local_id: shared.endpoint.id(),
            peer_id: shared.peer,
            relay_url,
            public_relays: shared.config.relays == Relays::Public,
            relay_connected,
            relay_error,
            state: *shared.state.borrow(),
            path,
            rtt,
            failed_attempts: trouble.failed_attempts,
            last_error: trouble.last_error.clone(),
            connected_for: trouble.connected_at.map(|since| since.elapsed()),
        }
    }

    /// Waits for the next event. Returns `None` once the session is closed.
    ///
    /// Taking a message confirms it to the peer, so a message is never confirmed
    /// without having reached the host. Until the host takes it the session reads no
    /// further message, and the peer's sends time out rather than pile up.
    ///
    /// Cancel-safe: a cancelled call neither loses nor confirms a message.
    pub async fn next_event(&self) -> Option<SessionEvent> {
        let mut events = self.events.lock().await;
        loop {
            let queued = tokio::select! {
                biased;
                () = self.shared.wait_closed() => return None,
                queued = events.recv() => queued?,
            };
            match queued {
                Queued::State(state) => return Some(SessionEvent::StateChanged(state)),
                // The stream that brought the message is gone (the peer gave up waiting
                // or the connection ended): the peer was not confirmed and will send it
                // again if it still matters, so delivering it now could duplicate it.
                Queued::Message { message, taken } => {
                    if taken.send(()).is_ok() {
                        return Some(SessionEvent::Message(message));
                    }
                }
            }
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

    /// Closes the connection (telling the peer) and the endpoint, and waits until both
    /// are closed. Idempotent, and cancel-safe: the endpoint is closed by the session's
    /// own task even if this call is abandoned.
    pub async fn close(&self) {
        if !self.shared.closed.send_replace(true) {
            self.shared
                .state
                .send_replace(ConnectionState::Disconnected);
            if let Some(connection) = self.shared.connection.send_replace(None) {
                connection.close(CloseCode::Normal.into(), b"closed");
            }
        }
        let mut stopped = self.shared.stopped.subscribe();
        // `wait_for` only fails if the sender is dropped, which outlives `self`. The
        // bound keeps a peer that never acknowledges the close from blocking the host.
        let _ = time::timeout(CLOSE_TIMEOUT, stopped.wait_for(|stopped| *stopped)).await;
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
    async fn emit(&self, event: Queued) -> bool {
        tokio::select! {
            biased;
            () = self.wait_closed() => false,
            sent = self.events.send(event) => sent.is_ok(),
        }
    }

    fn trouble(&self) -> std::sync::MutexGuard<'_, Trouble> {
        // A panic while holding this lock cannot leave it inconsistent: recover.
        self.trouble
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn record_error(&self, context: &str, error: impl Display) {
        self.trouble().last_error = Some(format!("{context}: {error}"));
    }

    fn record_failed_attempt(&self, error: impl Display) {
        let mut trouble = self.trouble();
        trouble.failed_attempts = trouble.failed_attempts.saturating_add(1);
        trouble.last_error = Some(format!("dial: {error}"));
    }

    fn record_connected(&self) {
        let mut trouble = self.trouble();
        trouble.failed_attempts = 0;
        trouble.connected_at = Some(time::Instant::now());
    }

    fn record_disconnected(&self, reason: Option<String>) {
        let mut trouble = self.trouble();
        trouble.connected_at = None;
        if let Some(reason) = reason {
            trouble.last_error = Some(format!("connection ended: {reason}"));
        }
    }

    /// Records and reports a state change. Only the driver calls it, from one task,
    /// so reported states follow the real order. Nothing changes once closed.
    async fn set_state(&self, state: ConnectionState) {
        if self.is_closed() {
            return;
        }
        let changed = self.state.send_if_modified(|current| {
            let changed = *current != state;
            *current = state;
            changed
        });
        if changed {
            tracing::debug!(?state, peer = %self.peer.fmt_short(), "connection state changed");
            self.emit(Queued::State(state)).await;
        }
    }
}

/// Applies the relay choice. `Minimal` has no address lookup of its own: with a custom
/// relay the endpoint publishes nothing about itself and is found only through that
/// relay; with the public relays the connector publishes its relay URL (never its IP
/// addresses) and the wallet looks it up.
fn with_relays(
    builder: iroh::endpoint::Builder,
    config: &SessionConfig,
    role: Role,
) -> iroh::endpoint::Builder {
    #[cfg(test)]
    let builder = test_builder(builder, config);
    match &config.relays {
        Relays::Custom(url) => builder.relay_mode(RelayMode::custom([url.clone()])),
        Relays::Public => {
            #[cfg(test)]
            if let Some(test) = &config.test_public_infrastructure {
                return builder
                    .relay_mode(RelayMode::custom([test.relay_url.clone()]))
                    .preset(test.lookup.preset());
            }
            let builder = builder.relay_mode(RelayMode::Default);
            match role {
                Role::Connector => builder
                    .addr_filter(AddrFilter::relay_only())
                    .address_lookup(PkarrPublisher::n0_dns()),
                Role::Wallet => {
                    let builder = builder.address_lookup(PkarrResolver::n0_dns());
                    // Browsers cannot query DNS; elsewhere it is a second, independent
                    // way to find the connector.
                    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
                    let builder = builder.address_lookup(DnsAddressLookup::n0_dns());
                    builder
                }
            }
        }
    }
}

#[cfg(test)]
fn test_builder(
    mut builder: iroh::endpoint::Builder,
    config: &SessionConfig,
) -> iroh::endpoint::Builder {
    if config.insecure_skip_relay_cert_verify {
        builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
    }
    if config.relay_only {
        builder = builder.clear_ip_transports();
    }
    builder
}

async fn drive(shared: Arc<Shared>) {
    let run = async {
        match shared.role {
            Role::Wallet => {
                tokio::select! {
                    () = dial(&shared) => {}
                    () = ignore_incoming(&shared) => {}
                }
            }
            Role::Connector => accept(&shared).await,
        }
    };
    tokio::select! {
        () = run => {}
        () = log_relay_status(&shared) => {}
    }
    shared.endpoint.close().await;
    shared.stopped.send_replace(true);
    tracing::info!(local = %shared.endpoint.id().fmt_short(), "radix connect iroh session closed");
}

/// Wallet: keep dialing the Connector Extension, and serve each connection until it
/// ends.
async fn dial(shared: &Arc<Shared>) {
    // With the public relays the connector's relay is found through address lookup.
    let peer_addr = match &shared.config.relays {
        Relays::Public => EndpointAddr::new(shared.peer),
        Relays::Custom(url) => EndpointAddr::new(shared.peer).with_relay_url(url.clone()),
    };
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
                shared.record_connected();
                shared.set_state(ConnectionState::Connected).await;
                let ended = serve(shared, &connection).await;
                shared.connection.send_replace(None);
                shared.record_disconnected(ended);
            }
            Ok(Err(error)) => {
                tracing::debug!(%error, "could not reach the connector");
                shared.record_failed_attempt(&error);
            }
            Err(_) => {
                tracing::debug!(timeout = ?shared.config.connect_timeout, "dialing the connector timed out: is it running, with iroh, on the same relay?");
                shared.record_failed_attempt(
                    "timed out (is the connector running, with iroh, on the same relay?)",
                );
            }
        }
        let failed_attempts = shared.trouble().failed_attempts;
        // Every few failures, say it at a level hosts log by default.
        if failed_attempts > 0 && failed_attempts.is_power_of_two() {
            tracing::info!(failed_attempts, "still trying to reach the connector");
        }
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            () = shared.redial.notified() => delay = shared.config.min_reconnect_delay,
            () = time::sleep(delay) => delay = (delay * 2).min(shared.config.max_reconnect_delay),
        }
    }
}

/// Logs when this end gains or loses its relay: without it the peer cannot reach it,
/// which is the first thing to check when a link does not connect. Never returns.
async fn log_relay_status(shared: &Shared) {
    let mut statuses = shared.endpoint.home_relay_status().stream();
    let mut was_connected = false;
    while let Some(statuses) = statuses.next().await {
        let connected = statuses.iter().any(|relay| relay.is_connected());
        let error = statuses
            .iter()
            .find_map(|relay| relay.last_error().map(|error| error.to_string()));
        let relay = statuses
            .iter()
            .find(|relay| relay.is_connected())
            .or(statuses.first())
            .map_or_else(|| "none".to_owned(), |relay| relay.url().to_string());
        if connected && !was_connected {
            tracing::info!(%relay, "connected to the relay");
        } else if !connected && (was_connected || error.is_some()) {
            tracing::warn!(%relay, error = error.as_deref().unwrap_or("none"), "not connected to the relay: the peer cannot reach this end");
        }
        was_connected = connected;
    }
    std::future::pending::<()>().await;
}

/// Wallet: drop every incoming connection attempt without answering. The endpoint has
/// no ALPN, so none could succeed, but unaccepted attempts would pile up in memory.
async fn ignore_incoming(shared: &Shared) {
    loop {
        let incoming = tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            incoming = shared.endpoint.accept() => incoming,
        };
        match incoming {
            Some(incoming) => incoming.ignore(),
            None => return,
        }
    }
}

/// Connector Extension: accept the wallet's connections. A new connection replaces the
/// current one: the wallet only dials again when it believes the old one is gone
/// (network change, app restart), and the old one may take a while to time out.
///
/// This loop is the only place that changes the connector's connection and state, so
/// a connection that ends while a newer one is being set up cannot leave a stale
/// `Disconnected` behind.
async fn accept(shared: &Arc<Shared>) {
    let mut handshakes = FuturesUnordered::new();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<(usize, Option<String>)>();
    let mut serving: Option<(usize, AbortOnDropHandle<()>)> = None;
    loop {
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            Some((ended, reason)) = ended_rx.recv() => {
                if serving.as_ref().is_some_and(|(id, _)| *id == ended) {
                    serving = None;
                    shared.connection.send_replace(None);
                    shared.record_disconnected(reason);
                    shared.set_state(ConnectionState::Disconnected).await;
                }
            }
            Some(handshake) = handshakes.next(), if !handshakes.is_empty() => {
                let connection: Connection = match handshake {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        tracing::debug!(%error, "incoming handshake failed");
                        shared.record_error("incoming handshake", &error);
                        continue;
                    }
                    Err(_) => {
                        tracing::debug!("incoming handshake timed out");
                        shared.record_error("incoming handshake", "timed out");
                        continue;
                    }
                };
                // The guard hook already refused anyone else; checked again so that this
                // invariant never depends on hook plumbing alone.
                if connection.remote_id() != shared.peer {
                    connection.close(CloseCode::Unauthorized.into(), b"unauthorized");
                    shared.record_error("incoming connection", "rejected an endpoint that is not the link's wallet");
                    continue;
                }
                let id = connection.stable_id();
                if let Some(previous) = shared.connection.send_replace(Some(connection.clone())) {
                    previous.close(CloseCode::Replaced.into(), b"replaced");
                }
                let ended = ended_tx.clone();
                let task_shared = shared.clone();
                // Replacing the handle stops serving the previous connection.
                serving = Some((
                    id,
                    AbortOnDropHandle::new(task::spawn(async move {
                        let reason = serve(&task_shared, &connection).await;
                        let _ = ended.send((id, reason));
                    })),
                ));
                shared.record_connected();
                shared.set_state(ConnectionState::Connected).await;
            }
            incoming = shared.endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return;
                };
                // Through the relay, the sender's id is known before any handshake work.
                if let IncomingAddr::Relay { endpoint_id, .. } = incoming.remote_addr()
                    && endpoint_id != shared.peer
                {
                    tracing::debug!(remote = %endpoint_id.fmt_short(), "ignoring a connection attempt from a stranger");
                    incoming.ignore();
                    continue;
                }
                if handshakes.len() >= MAX_PENDING_HANDSHAKES {
                    incoming.ignore();
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

/// Delivers the peer's messages, one stream at a time, until the connection ends or
/// the session closes. Each message is confirmed only once the host took it. Returns
/// why the connection ended, if it did not end because the session closed.
async fn serve(shared: &Shared, connection: &Connection) -> Option<String> {
    let (path, rtt) = diagnostics::selected_path(connection);
    tracing::info!(peer = %shared.peer.fmt_short(), ?path, ?rtt, "connected to the peer");
    loop {
        let stream = tokio::select! {
            biased;
            () = shared.wait_closed() => return None,
            stream = connection.accept_bi() => stream,
        };
        let (send, mut recv) = match stream {
            Ok(stream) => stream,
            Err(error) => {
                let reason = diagnostics::describe_connection_end(&error);
                tracing::info!(%reason, "connection to the peer ended");
                return Some(reason);
            }
        };
        let read = time::timeout(
            shared.config.receive_timeout,
            protocol::read_message(send, &mut recv, shared.config.max_message_size),
        )
        .await;
        match read {
            Ok(Ok(Incoming::Message(message, answer))) => {
                let (taken, on_taken) = oneshot::channel();
                if !shared.emit(Queued::Message { message, taken }).await {
                    return None;
                }
                // If the peer stops waiting first, dropping `on_taken` withdraws the
                // message from the host, and dropping `answer` resets the stream.
                // A message the host already took is confirmed even if the session is
                // closing at the same moment (best effort: closing may still cut it off).
                let taken = tokio::select! {
                    biased;
                    taken = on_taken => taken.is_ok(),
                    () = shared.wait_closed() => return None,
                    () = answer.peer_gave_up() => false,
                };
                if taken {
                    answer.acknowledge().await;
                }
            }
            Ok(Ok(Incoming::Refused | Incoming::Incomplete)) => {}
            Ok(Err(error)) => {
                tracing::debug!(%error, "could not read an incoming message");
                shared.record_error("receive", &error);
            }
            Err(_) => {
                let _ = recv.stop(0u32.into());
                tracing::warn!("an incoming message did not arrive in time");
                shared.record_error("receive", "a message did not arrive in time");
            }
        }
    }
}

#[cfg(test)]
mod tests;
