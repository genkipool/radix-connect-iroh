use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use iroh::address_lookup::DnsAddressLookup;
use iroh::address_lookup::{AddrFilter, PkarrPublisher, PkarrResolver};
use iroh::endpoint::{Connection, IncomingAddr, PathEvent, QuicTransportConfig, presets};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, TransportAddr,
    Watcher,
};
use n0_future::task::{self, AbortOnDropHandle};
use n0_future::{FuturesUnordered, StreamExt, time};
use tokio::sync::{Mutex, mpsc, oneshot, watch};

use crate::config::Relays;
use crate::diagnostics::{self, Diagnostics};
use crate::guard::PeerGuard;
use crate::protocol::{self, ALPN, CloseCode, Incoming};
use crate::{ConnectionPassword, Error, Role, SendError, SessionConfig};

/// Messages waiting for the host. Normally at most one: the next message is only read
/// once the host took the previous one (a replaced connection may leave one behind,
/// which is then withdrawn).
const MESSAGE_BUFFER: usize = 4;

/// How long creating the local endpoint may take.
const BIND_TIMEOUT: Duration = Duration::from_secs(15);

/// How long [`Session::close`] waits for the endpoint to close gracefully.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Direct (UDP) handshakes the connector processes at the same time. A browser never
/// receives direct attempts; elsewhere they arrive unscreened (any key can complete a
/// handshake, the guard hook rejects strangers only afterwards), so they share this
/// bounded pool once they proved their source address.
const MAX_DIRECT_HANDSHAKES: usize = 8;

/// Handshakes the link's wallet may have in progress at once through the relay. An
/// honest wallet has one, two around a network change; the cap bounds what a faulty
/// relay could make the connector do in the wallet's name, and is separate from the
/// direct pool so that strangers can never keep the wallet out.
const MAX_PEER_HANDSHAKES: usize = 4;

/// Longest wait before taking a link back from another session holding the same key.
const MAX_REPLACED_DELAY: Duration = Duration::from_secs(300);

/// How long closing waits for confirmations already written to reach the peer.
const ACK_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// Bytes the peer may have in flight across all its streams, instead of QUIC's
/// unbounded default: messages are read one at a time, so this only bounds what an
/// authenticated peer can make us buffer.
const RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;

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

/// A message waiting for the host. `taken` tells the stream that brought it to confirm
/// it.
#[derive(Debug)]
struct Delivery {
    message: String,
    taken: oneshot::Sender<()>,
}

/// What the host reads through [`Session::next_event`]. States are a watch rather than
/// queued events, so a host that falls behind never blocks the connection handling:
/// it gets the latest state.
#[derive(Debug)]
struct Inbox {
    messages: mpsc::Receiver<Delivery>,
    state: watch::Receiver<ConnectionState>,
    reported: ConnectionState,
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
    inbox: Mutex<Inbox>,
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
    messages: mpsc::Sender<Delivery>,
    /// Bumped on every network change: a change made while the wallet waits to dial
    /// again cuts the wait short.
    network: watch::Sender<u64>,
    /// Confirmations written but not yet acknowledged by the peer; closing waits for
    /// them briefly so that a message the host took is not reported as lost.
    acks_in_flight: watch::Sender<usize>,
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
            .receive_window(RECEIVE_WINDOW.into())
            // The protocol uses no datagrams: don't buffer any.
            .datagram_receive_buffer_size(None)
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
        let (messages_tx, messages_rx) = mpsc::channel(MESSAGE_BUFFER);
        let shared = Arc::new(Shared {
            endpoint,
            role,
            peer,
            config,
            connection: watch::Sender::new(None),
            state: watch::Sender::new(initial_state),
            closed: watch::Sender::new(false),
            stopped: watch::Sender::new(false),
            messages: messages_tx,
            network: watch::Sender::new(0),
            acks_in_flight: watch::Sender::new(0),
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
        let inbox = Inbox {
            messages: messages_rx,
            state: shared.state.subscribe(),
            reported: initial_state,
        };
        Ok(Self {
            shared,
            inbox: Mutex::new(inbox),
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
            // The receiver allows this long for a message to arrive; so does the sender.
            self.shared.config.receive_timeout,
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
        let mut inbox = self.inbox.lock().await;
        let Inbox {
            messages,
            state,
            reported,
        } = &mut *inbox;
        loop {
            tokio::select! {
                biased;
                () = self.shared.wait_closed() => return None,
                // States first: a connection is reported before its first message.
                Ok(()) = state.changed() => {
                    let latest = *state.borrow_and_update();
                    if latest != *reported {
                        *reported = latest;
                        return Some(SessionEvent::StateChanged(latest));
                    }
                }
                delivery = messages.recv() => {
                    let Delivery { message, taken } = delivery?;
                    // If the stream that brought the message is gone (the peer gave up
                    // waiting or the connection ended), the peer was not confirmed and
                    // will send it again if it still matters: delivering it now could
                    // duplicate it.
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
        self.shared
            .network
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        self.shared.endpoint.network_change().await;
    }

    /// Closes the connection (telling the peer) and the endpoint, and waits until both
    /// are closed. Idempotent, and cancel-safe: the session's own task closes them even
    /// if this call is abandoned.
    pub async fn close(&self) {
        if !self.shared.closed.send_replace(true) {
            self.shared
                .state
                .send_replace(ConnectionState::Disconnected);
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

    /// Hands a message to the host. Returns `false` once the session is closing.
    async fn deliver(&self, delivery: Delivery) -> bool {
        tokio::select! {
            biased;
            () = self.wait_closed() => false,
            sent = self.messages.send(delivery) => sent.is_ok(),
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

    /// Records a state change for the host. Only the driver calls it, from one task,
    /// so states follow the real order. Nothing changes once closed.
    fn set_state(&self, state: ConnectionState) {
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
        }
    }

    /// Lets confirmations already written reach the peer, briefly, then closes the
    /// connection, telling the peer.
    async fn close_connection(&self) {
        let mut acks = self.acks_in_flight.subscribe();
        // `wait_for` only fails if the sender is dropped, which outlives `self`.
        let _ = time::timeout(
            ACK_FLUSH_TIMEOUT,
            acks.wait_for(|in_flight| *in_flight == 0),
        )
        .await;
        if let Some(connection) = self.connection.send_replace(None) {
            connection.close(CloseCode::Normal.into(), b"closed");
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
        Relays::Custom(url) => builder.relay_mode(custom_relay_mode(url)),
        Relays::Public => {
            #[cfg(test)]
            if let Some(test) = &config.test_public_infrastructure {
                return builder
                    .relay_mode(RelayMode::custom([test.relay_url.clone()]))
                    .preset(test.lookup.preset());
            }
            // `default_relay_mode` honours IROH_FORCE_STAGING_RELAYS, as n0's address
            // lookup does, so relays and lookup never point at different deployments.
            let builder = builder.relay_mode(iroh::endpoint::default_relay_mode());
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

/// A single custom relay. A plain-http relay is a local development one, which serves
/// no QUIC address discovery: don't probe it for that.
fn custom_relay_mode(url: &RelayUrl) -> RelayMode {
    if url.scheme() == "http" {
        RelayMode::Custom(RelayMap::from_iter([RelayConfig::new(url.clone(), None)]))
    } else {
        RelayMode::custom([url.clone()])
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
    shared.close_connection().await;
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
    let mut network = shared.network.subscribe();
    let mut delay = shared.config.min_reconnect_delay;
    let mut replaced_in_a_row = 0;
    loop {
        shared.set_state(ConnectionState::Connecting);
        // This attempt already uses the current network.
        network.mark_unchanged();
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
                shared.connection.send_replace(Some(connection.clone()));
                shared.record_connected();
                shared.set_state(ConnectionState::Connected);
                let ended = serve(shared, &connection).await;
                shared.connection.send_replace(None);
                shared.record_disconnected(ended);
                // Not connected any more, and about to dial again.
                shared.set_state(ConnectionState::Connecting);
                // iroh carried the connection across the network changes made meanwhile.
                network.mark_unchanged();
                if was_replaced(&connection) {
                    replaced_in_a_row += 1;
                    tracing::warn!(
                        replaced_in_a_row,
                        "another session took over this link; backing off"
                    );
                } else {
                    replaced_in_a_row = 0;
                }
                delay = delay_after_connection(replaced_in_a_row, &shared.config);
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
        // A network change cuts the wait short, unless another session took the link
        // over: then only time does, or the two would keep taking it from each other.
        let follow_network = replaced_in_a_row == 0;
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            Ok(()) = network.changed(), if follow_network => delay = shared.config.min_reconnect_delay,
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
    let mut pending = PendingHandshakes::default();
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
                    shared.set_state(ConnectionState::Disconnected);
                }
            }
            Some((from_peer, handshake)) = handshakes.next(), if !handshakes.is_empty() => {
                pending.finished(from_peer);
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
                shared.set_state(ConnectionState::Connected);
            }
            incoming = shared.endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return;
                };
                let decision = admission(
                    &incoming.remote_addr(),
                    incoming.remote_addr_validated(),
                    shared.peer,
                    pending,
                );
                match decision {
                    Admission::Handshake { from_peer } => match incoming.accept() {
                        Ok(accepting) => {
                            pending.started(from_peer);
                            handshakes.push(tagged(from_peer, time::timeout(HANDSHAKE_TIMEOUT, accepting)));
                        }
                        Err(error) => tracing::debug!(%error, "could not accept an incoming connection"),
                    },
                    // Costs us nothing: a genuine sender answers, a spoofed source cannot.
                    Admission::ValidateAddress => {
                        if let Err(error) = incoming.retry() {
                            error.into_incoming().ignore();
                        }
                    }
                    Admission::Ignore => {
                        tracing::debug!(addr = ?incoming.remote_addr(), "ignoring a connection attempt");
                        incoming.ignore();
                    }
                }
            }
        }
    }
}

/// Delay before redialing once a connection ended. When another session holding this
/// link's key (another device, or a second app instance) took over, redialing at once
/// would just take the link back, and the two would keep replacing each other: wait the
/// longest back-off, doubling (up to 5 minutes) while it keeps happening.
fn delay_after_connection(replaced_in_a_row: u32, config: &SessionConfig) -> Duration {
    match replaced_in_a_row {
        0 => config.min_reconnect_delay,
        n => config
            .max_reconnect_delay
            .saturating_mul(1 << (n - 1).min(8))
            .min(MAX_REPLACED_DELAY.max(config.max_reconnect_delay)),
    }
}

/// Pairs a future's output with a tag, so futures of one type can be told apart in a
/// [`FuturesUnordered`].
async fn tagged<F: Future>(tag: bool, future: F) -> (bool, F::Output) {
    (tag, future.await)
}

/// Incoming handshakes in progress, by origin.
#[derive(Debug, Clone, Copy, Default)]
struct PendingHandshakes {
    /// Through the relay, from the link's wallet.
    from_peer: usize,
    /// Direct (UDP) attempts, from anyone.
    direct: usize,
}

impl PendingHandshakes {
    fn started(&mut self, from_peer: bool) {
        *self.count(from_peer) += 1;
    }

    fn finished(&mut self, from_peer: bool) {
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

fn was_replaced(connection: &Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(close))
            if close.error_code == CloseCode::Replaced.into()
    )
}

/// What to do with an incoming connection attempt, before any handshake work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Handshake {
        /// Attested by the relay as coming from the link's wallet.
        from_peer: bool,
    },
    /// Ask the sender to prove it can receive at its source address first.
    ValidateAddress,
    Ignore,
}

/// Through the relay the sender's id is attested before any handshake work: the
/// link's wallet gets its own small pool (strangers can never fill its way), anyone
/// else is ignored. Direct attempts (native connectors only; a browser has no UDP)
/// must first prove their source address, then share the bounded direct pool.
fn admission(
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
                Admission::Ignore
            }
        }
        IncomingAddr::Relay { .. } => Admission::Ignore,
        _ if !validated => Admission::ValidateAddress,
        _ if pending.direct >= MAX_DIRECT_HANDSHAKES => Admission::Ignore,
        _ => Admission::Handshake { from_peer: false },
    }
}

/// Delivers the peer's messages, one stream at a time, until the connection ends or
/// the session closes. Each message is confirmed only once the host took it. Returns
/// why the connection ended, if it did not end because the session closed.
async fn serve(shared: &Shared, connection: &Connection) -> Option<String> {
    // Subscribed before reading the current path, so no switch goes unnoticed.
    let mut path_events = connection.path_events();
    let (path, rtt) = diagnostics::selected_path(connection);
    tracing::info!(peer = %shared.peer.fmt_short(), ?path, ?rtt, "connected to the peer");
    loop {
        let stream = tokio::select! {
            biased;
            () = shared.wait_closed() => return None,
            Some(event) = path_events.next() => {
                log_path_event(connection, &event);
                continue;
            }
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
                if !shared.deliver(Delivery { message, taken }).await {
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
                    shared
                        .acks_in_flight
                        .send_modify(|in_flight| *in_flight += 1);
                    answer.acknowledge(ACK_FLUSH_TIMEOUT).await;
                    shared
                        .acks_in_flight
                        .send_modify(|in_flight| *in_flight -= 1);
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

/// Logs when the connection switches between the relay and a direct path. Never logs
/// addresses: they are the users' IP addresses, and logs get shared.
fn log_path_event(connection: &Connection, event: &PathEvent) {
    match event {
        PathEvent::Selected { remote_addr, .. } => {
            let path = match remote_addr {
                TransportAddr::Relay(_) => "relay",
                _ => "direct",
            };
            tracing::info!(path, "the connection now goes through a new path");
        }
        PathEvent::Lagged { .. } => {
            let (path, _) = diagnostics::selected_path(connection);
            tracing::debug!(?path, "missed path events; current path");
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
