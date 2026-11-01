use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use iroh::address_lookup::DnsAddressLookup;
use iroh::address_lookup::{AddrFilter, PkarrPublisher, PkarrResolver};
use iroh::endpoint::{
    ConnectOptions, ConnectingError, Connection, IncomingAddr, PathEvent, QuicTransportConfig,
    RecvStream, SendStream, presets,
};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, TransportAddr,
    Watcher,
};
use n0_future::task::{self, AbortOnDropHandle};
use n0_future::time::Instant;
use n0_future::{FuturesUnordered, StreamExt, time};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tracing::Instrument;

use crate::config::Relays;
use crate::diagnostics::{
    self, Diagnostics, DialFailure, PathKind, TALLY_WINDOW, Tally, Traffic, ms,
};
use crate::guard::PeerGuard;
use crate::logging::Redacted;
use crate::protocol::{
    self, ALPN, Acknowledged, CloseCode, Incoming, KNOCK_ALPN, Liveness, SendFailure, SendPhase,
    Sent,
};
use crate::relay_health::{self, RelayNotice};
use crate::requests::{self, Delivered, Held};
use crate::{ConnectionPassword, Error, Role, SendError, SessionConfig};

/// Messages waiting for the host. Normally at most one: the next message is only read
/// once the host took the previous one (a replaced connection may leave one behind,
/// which is then withdrawn).
const MESSAGE_BUFFER: usize = 4;
/// Notices for the host (requests delivered again, the wallet's presence): few, and each
/// one small. One that finds the buffer full is dropped: the next one says more.
const NOTICE_BUFFER: usize = 32;

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

/// After this long without reaching the connector, the wallet's periodic "still trying"
/// line becomes a warning.
const UNREACHABLE_WARNING: Duration = Duration::from_secs(60);

/// How long a liveness check waits for the peer: three round trips, within these
/// bounds. The upper one covers a relay reconnecting (packets wait for it), as after
/// the app was in the background.
const PROBE_MIN_DEADLINE: Duration = Duration::from_millis(1500);
const PROBE_MAX_DEADLINE: Duration = Duration::from_secs(4);

/// Network changes reported within this long of a liveness check share the next one.
const PROBE_DEBOUNCE: Duration = Duration::from_secs(2);
/// Connector: how often it checks that a wallet whose app is in the background still
/// answers. Closed from there, the app sends nothing, and only QUIC's idle timeout (30 s)
/// would tell; checked, it is known within this plus a check's deadline. A wallet the
/// system only froze fails the check too, which loses nothing: it lists its requests when
/// it is back (`requests`), and redials then.
const BACKGROUND_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Why a connection the peer stopped answering ended.
const NO_ANSWER: &str = "no answer to a liveness check";

/// Numbers sessions in this process: they tie log lines, and the relay's notices, to
/// their session.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

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

impl ConnectionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
        }
    }
}

/// Something that happened on a [`Session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// The connection state changed.
    StateChanged(ConnectionState),
    /// A message arrived from the peer. Taking it from
    /// [`next_event`](Session::next_event) confirms it to the peer.
    Message(String),
    /// Connector: a dApp request (by `interactionId`) the wallet had received and lost —
    /// its app was closed — was delivered to it again, and it confirmed it. See
    /// `docs/PROTOCOL.md`, "Request inventory".
    RequestRedelivered(String),
    /// Connector: the wallet's app went to the background (`true`) or came back.
    PeerPresence {
        /// Whether the wallet's app is in the background.
        in_background: bool,
    },
}

/// What the session tells the host besides states and messages.
#[derive(Debug)]
enum Notice {
    Redelivered(String),
    Presence(bool),
}

/// A message waiting for the host. `taken` tells the stream that brought it to confirm
/// it.
#[derive(Debug)]
struct Delivery {
    message: String,
    taken: oneshot::Sender<OwedConfirmation>,
    /// The session's number for the incoming message, for logs.
    seq: u64,
    queued_at: Instant,
}

/// What the host reads through [`Session::next_event`]. States are a watch rather than
/// queued events, so a host that falls behind never blocks the connection handling:
/// it gets the latest state.
#[derive(Debug)]
struct Inbox {
    messages: mpsc::Receiver<Delivery>,
    notices: mpsc::Receiver<Notice>,
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

/// Why a connection ended.
#[derive(Debug)]
struct Ended {
    reason: String,
    /// It was dropped because the peer did not answer a liveness check.
    unresponsive: bool,
}

/// The connection in use, with what the logs say about it.
#[derive(Debug, Clone)]
struct Current {
    connection: Connection,
    /// The session's number for this connection (its log lines carry `conn=`).
    number: u64,
    span: tracing::Span,
    connected_at: Instant,
    /// The network generation when it was established: later changes call for a
    /// liveness check.
    network: u64,
}

#[derive(Debug)]
struct Shared {
    endpoint: Endpoint,
    role: Role,
    peer: EndpointId,
    config: SessionConfig,
    /// This session's number in the process (`session=` in its log lines).
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "tests tell sessions apart by it")
    )]
    session: u64,
    /// The span every line of this session is logged in (`session=… role=… local=…
    /// peer=…`); iroh's relay tasks inherit it.
    span: tracing::Span,
    started_at: Instant,
    connection: watch::Sender<Option<Current>>,
    state: watch::Sender<ConnectionState>,
    closed: watch::Sender<bool>,
    /// Set by the driver once it stopped and closed the endpoint.
    stopped: watch::Sender<bool>,
    messages: mpsc::Sender<Delivery>,
    /// Bumped on every network change: a change made while the wallet waits to dial
    /// again cuts the wait short.
    network: watch::Sender<u64>,
    /// Wallet: bumped on every knock it took (a wake-up too, which also bumps `network`),
    /// so the dial loop can say why it dials now.
    knocks: watch::Sender<u64>,
    /// Confirmations owed to the peer: for messages the host took, until they are
    /// written and acknowledged. Closing waits for them briefly so that a message the
    /// host took is not reported as lost.
    acks_in_flight: Arc<watch::Sender<usize>>,
    /// What went wrong lately, for [`Session::diagnostics`].
    trouble: std::sync::Mutex<Trouble>,
    /// Numbers of the last connection, outgoing and incoming message.
    connections: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
    /// The relay's notices for this session (another holder of the key took over).
    relay: relay_health::Registration,
    /// Connections the guard rejected as unauthorized, summarised every minute.
    unauthorized: Arc<std::sync::Mutex<Tally>>,
    /// Wallet: whether its app is in the background, as the host said; told to the connector
    /// on every connection.
    in_background: AtomicBool,
    /// Connector: whether the wallet last said its app is in the background.
    peer_in_background: AtomicBool,
    /// Connector: bumped when the wallet's app goes to the background or comes back, so the
    /// liveness checks start or stop at once.
    presence: watch::Sender<u64>,
    /// Wallet: the requests its host took and has not answered, for the inventory.
    held: std::sync::Mutex<Held>,
    /// Connector: the requests it delivered that the wallet has not answered.
    delivered: Arc<std::sync::Mutex<Delivered>>,
    /// Connector: whether the wallet sends inventories, so lost requests come back.
    peer_reports_requests: AtomicBool,
    notices: mpsc::Sender<Notice>,
}

/// The parts of [`Diagnostics`] that iroh does not keep for us.
#[derive(Debug, Default)]
struct Trouble {
    last_error: Option<String>,
    failed_attempts: u32,
    connected_at: Option<Instant>,
    key_collision: bool,
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
        let session = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        let local = password.endpoint_id(role);
        let peer = password.endpoint_id(role.peer());
        let span = tracing::info_span!(
            "session",
            session,
            role = role.as_str(),
            local = %local.fmt_short(),
            peer = %peer.fmt_short(),
        );
        // Before the endpoint exists: a notice can come with its first relay connection.
        let relay = relay_health::register(session);
        let unauthorized = Arc::default();
        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into())
            .max_concurrent_uni_streams(0u32.into())
            .receive_window(RECEIVE_WINDOW.into())
            // The only datagrams are the wallet's presence (`protocol::presence`): room for a
            // few. A wallet needs it too, to send them (QUIC sends datagrams only with them on),
            // though no connector sends it any.
            .datagram_receive_buffer_size(Some(protocol::PRESENCE_BUFFER))
            .build();
        // The connector accepts the wallet's connections; the wallet accepts only knocks
        // (its connector telling it to dial now), and no connection that carries anything.
        let alpns = match role {
            Role::Connector => vec![ALPN.to_vec()],
            Role::Wallet => vec![KNOCK_ALPN.to_vec()],
        };
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(password.secret_key(role))
            .alpns(alpns)
            .transport_config(transport)
            .hooks(PeerGuard::new(peer, Arc::clone(&unauthorized)));
        let builder = with_relays(builder, &config, role);
        let started_at = Instant::now();
        // iroh's tasks, its relay actor among them, inherit the span the endpoint is
        // bound in: their lines carry this session's context.
        let bind = span.in_scope(|| builder.bind());
        let bound = time::timeout(BIND_TIMEOUT, bind)
            .instrument(span.clone())
            .await;
        let endpoint = match bound {
            Ok(Ok(endpoint)) => endpoint,
            Ok(Err(error)) => {
                span.in_scope(|| {
                    tracing::warn!(
                        error = %Redacted(&error),
                        elapsed_ms = ms(started_at.elapsed()),
                        "could not start the session: the endpoint failed to bind"
                    );
                });
                return Err(Error::Bind(Redacted(error).to_string()));
            }
            Err(_) => {
                span.in_scope(|| {
                    tracing::warn!(
                        timeout_ms = ms(BIND_TIMEOUT),
                        elapsed_ms = ms(started_at.elapsed()),
                        "could not start the session: binding the endpoint timed out"
                    );
                });
                return Err(Error::Bind("timed out".to_owned()));
            }
        };

        let initial_state = match role {
            Role::Wallet => ConnectionState::Connecting,
            Role::Connector => ConnectionState::Disconnected,
        };
        let (messages_tx, messages_rx) = mpsc::channel(MESSAGE_BUFFER);
        let (notices_tx, notices_rx) = mpsc::channel(NOTICE_BUFFER);
        let shared = Arc::new(Shared {
            endpoint,
            role,
            peer,
            config,
            session,
            span: span.clone(),
            started_at,
            connection: watch::Sender::new(None),
            state: watch::Sender::new(initial_state),
            closed: watch::Sender::new(false),
            stopped: watch::Sender::new(false),
            messages: messages_tx,
            network: watch::Sender::new(0),
            knocks: watch::Sender::new(0),
            acks_in_flight: Arc::new(watch::Sender::new(0)),
            trouble: std::sync::Mutex::default(),
            connections: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            relay,
            unauthorized,
            in_background: AtomicBool::new(false),
            peer_in_background: AtomicBool::new(false),
            presence: watch::Sender::new(0),
            held: std::sync::Mutex::default(),
            delivered: Arc::default(),
            peer_reports_requests: AtomicBool::new(false),
            notices: notices_tx,
        });
        span.in_scope(|| {
            let config = &shared.config;
            tracing::info!(
                version = env!("CARGO_PKG_VERSION"),
                relays = %RelaysField(&config.relays),
                bind_ms = ms(started_at.elapsed()),
                connect_timeout_ms = ms(config.connect_timeout),
                min_reconnect_delay_ms = ms(config.min_reconnect_delay),
                max_reconnect_delay_ms = ms(config.max_reconnect_delay),
                fast_retry_period_ms = ms(config.fast_retry_period),
                slow_reconnect_delay_ms = ms(config.slow_reconnect_delay),
                transfer_timeout_ms = ms(config.receive_timeout),
                ack_timeout_ms = ms(config.ack_timeout),
                max_message_bytes = config.max_message_size,
                "session started"
            );
        });
        let driver = AbortOnDropHandle::new(task::spawn(drive(shared.clone()).instrument(span)));
        let inbox = Inbox {
            messages: messages_rx,
            notices: notices_rx,
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
        let seq = self.shared.sent.fetch_add(1, Ordering::Relaxed) + 1;
        let span = tracing::info_span!(
            parent: &self.shared.span,
            "send",
            send_seq = seq,
            conn = tracing::field::Empty,
        );
        self.shared.send(message).instrument(span).await
    }

    /// A snapshot of the session's connectivity, for logs (its `Display` is one line)
    /// and diagnostics screens. Cheap; contains no secrets.
    /// The relay the peer is on, as this end knows it (best while connected). A connector
    /// keeps its wallet's as the link's relay hint, for [`SessionConfig::with_peer_relay`]:
    /// the next session knocks there.
    pub async fn peer_relay(&self) -> Option<RelayUrl> {
        let info = self.shared.endpoint.remote_info(self.shared.peer).await?;
        info.addrs().find_map(|addr| match addr.addr() {
            TransportAddr::Relay(url) => Some(url.clone()),
            _ => None,
        })
    }

    /// Connector: knocks for the wallet at `relay` now — a wallet that is up dials at once.
    /// Whether it took the knock (a wallet that predates knocks, or is not up, does not).
    /// Sessions knock by themselves when they start; this is for a host that knows better.
    pub async fn knock(&self, relay: &RelayUrl) -> bool {
        if self.shared.role != Role::Connector {
            return false;
        }
        knock(&self.shared, relay)
            .instrument(self.shared.span.clone())
            .await
    }

    /// Wallet: tells the connector whether the app is in the background (call when it goes
    /// there and when it comes back), now and on every later connection. A connector racing
    /// several wallets for one request then sends it to the one the person opens, not to one
    /// still connected a while after its app went to the background. Best effort: a connector
    /// that predates this ignores it, and nothing else changes.
    pub fn set_in_background(&self, in_background: bool) {
        self.shared
            .in_background
            .store(in_background, Ordering::Relaxed);
        if let Some(current) = self.shared.connection.borrow().clone() {
            self.shared.tell_presence(&current.connection);
        }
    }

    /// Connector: whether the wallet last said its app is in the background (it says so on
    /// every connection). `false` when it never said (a wallet that predates this), or once it
    /// is back in the foreground.
    pub fn peer_in_background(&self) -> bool {
        self.shared.peer_in_background.load(Ordering::Relaxed)
    }

    /// Connector: whether the wallet tells which requests it still has when it connects,
    /// so one it lost is delivered again by itself ([`SessionEvent::RequestRedelivered`]).
    /// `false` until it first does, and for a wallet that predates it.
    pub fn peer_reports_requests(&self) -> bool {
        self.shared.peer_reports_requests.load(Ordering::Relaxed)
    }

    pub fn diagnostics(&self) -> Diagnostics {
        self.shared.diagnostics()
    }

    /// Waits for the next event. Returns `None` once the session is closed.
    ///
    /// Taking a message confirms it to the peer, so a message is never confirmed
    /// without having reached the host. Until the host takes it the session reads no
    /// further message, and the peer's sends time out rather than pile up.
    ///
    /// Cancel-safe: a cancelled call neither loses nor confirms a message.
    pub async fn next_event(&self) -> Option<SessionEvent> {
        let span = &self.shared.span;
        let mut inbox = self.inbox.lock().await;
        let Inbox {
            messages,
            notices,
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
                        tracing::trace!(parent: span, state = latest.as_str(), "the host read a state change");
                        return Some(SessionEvent::StateChanged(latest));
                    }
                }
                Some(notice) = notices.recv() => {
                    return Some(match notice {
                        Notice::Redelivered(id) => SessionEvent::RequestRedelivered(id),
                        Notice::Presence(in_background) => SessionEvent::PeerPresence { in_background },
                    });
                }
                delivery = messages.recv() => {
                    let Delivery { message, taken, seq, queued_at } = delivery?;
                    // If the stream that brought the message is gone (the peer gave up
                    // waiting or the connection ended), the peer was not confirmed and
                    // will send it again if it still matters: delivering it now could
                    // duplicate it. Owed from now on, so that closing waits for it.
                    if taken.send(OwedConfirmation::new(&self.shared.acks_in_flight)).is_ok() {
                        self.shared.took(&message);
                        tracing::debug!(
                            parent: span,
                            recv_seq = seq,
                            bytes = message.len(),
                            wait_ms = ms(queued_at.elapsed()),
                            "the host took a message"
                        );
                        return Some(SessionEvent::Message(message));
                    }
                    tracing::debug!(
                        parent: span,
                        recv_seq = seq,
                        "skipped a withdrawn message instead of handing it to the host"
                    );
                }
            }
        }
    }

    /// Tells the session that the device's network changed (Wi-Fi to mobile data, new
    /// address, VPN...), or that the app returned to the foreground or the machine woke
    /// up. iroh re-checks its paths, a waiting wallet dials again at once, and the
    /// current connection is checked in the background: if the peer does not answer
    /// within a few seconds, the connection is dropped (and the wallet redials at once)
    /// instead of looking alive until it times out. Mobile hosts should call it from
    /// their connectivity callbacks (iroh cannot detect network changes by itself on
    /// Android) and when the app returns to the foreground.
    pub async fn network_changed(&self) {
        let shared = &self.shared;
        async {
            tracing::info!(
                state = shared.state.borrow().as_str(),
                "the host reported a network change"
            );
            shared
                .network
                .send_modify(|generation| *generation = generation.wrapping_add(1));
            shared.endpoint.network_change().await;
        }
        .instrument(shared.span.clone())
        .await;
    }

    /// Closes the connection (telling the peer) and the endpoint, and waits until both
    /// are closed. Idempotent, and cancel-safe: the session's own task closes them even
    /// if this call is abandoned.
    pub async fn close(&self) {
        let shared = &self.shared;
        async {
            let requested = Instant::now();
            if !shared.closed.send_replace(true) {
                let state = shared.state.send_replace(ConnectionState::Disconnected);
                tracing::info!(
                    state = state.as_str(),
                    queued_for_host = shared.queued_for_host(),
                    confirmations_in_flight = *shared.acks_in_flight.borrow(),
                    "closing the session"
                );
            }
            let mut stopped = shared.stopped.subscribe();
            // `wait_for` only fails if the sender is dropped, which outlives `self`. The
            // bound keeps a peer that never acknowledges the close from blocking the host.
            let waited = time::timeout(CLOSE_TIMEOUT, stopped.wait_for(|stopped| *stopped)).await;
            if waited.is_err() {
                tracing::warn!(
                    timeout_ms = ms(CLOSE_TIMEOUT),
                    elapsed_ms = ms(requested.elapsed()),
                    "closing the session timed out: it goes on closing in the background"
                );
            }
        }
        .instrument(shared.span.clone())
        .await;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.shared.is_closed() {
            self.shared.span.in_scope(|| {
                tracing::info!(
                    state = self.shared.state.borrow().as_str(),
                    "session dropped without being closed: the peer is not told, and notices only when the connection times out"
                );
            });
        }
    }
}

impl Shared {
    /// Wallet: sends its presence on `connection` (twice, a moment apart: a datagram may be
    /// lost, and a lost one only means the connector believes the app is in the foreground).
    fn tell_presence(&self, connection: &iroh::endpoint::Connection) {
        if self.role != Role::Wallet {
            return;
        }
        let in_background = self.in_background.load(Ordering::Relaxed);
        let datagram = protocol::presence(in_background);
        let sent = |connection: &iroh::endpoint::Connection| {
            connection
                .send_datagram(bytes::Bytes::copy_from_slice(&datagram))
                .is_ok()
        };
        if !sent(connection) {
            // A connector that predates presence takes no datagrams: nothing to tell it.
            tracing::debug!(
                in_background,
                "presence not sent: the peer takes no datagrams"
            );
            return;
        }
        tracing::debug!(in_background, "told the peer the app's presence");
        let inventory = self.lock_held().inventory();
        let _ = connection.send_datagram(bytes::Bytes::copy_from_slice(&inventory));
        let again = connection.clone();
        task::spawn(async move {
            time::sleep(Duration::from_millis(250)).await;
            let _ = again.send_datagram(bytes::Bytes::copy_from_slice(&datagram));
            let _ = again.send_datagram(bytes::Bytes::copy_from_slice(&inventory));
        });
    }

    fn lock_held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_delivered(&self) -> std::sync::MutexGuard<'_, Delivered> {
        self.delivered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The host took `message` from the peer.
    fn took(&self, message: &str) {
        match self.role {
            Role::Wallet => self.lock_held().took(message),
            Role::Connector => self.lock_delivered().took(message),
        }
    }

    /// The peer confirmed `message`, sent on connection `number`.
    fn confirmed(&self, message: &str, number: u64) {
        match self.role {
            Role::Wallet => self.lock_held().sent(message),
            Role::Connector => self.lock_delivered().sent(message, number),
        }
    }

    /// Connector: the wallet's inventory arrived on `current`. Each request it lost is
    /// delivered again there, in the background.
    fn heard_inventory(&self, current: &Current, inventory: &requests::Inventory) {
        if !self.peer_reports_requests.swap(true, Ordering::Relaxed) {
            tracing::info!("the wallet reports the requests it holds: lost ones come back");
        }
        let lost = self.lock_delivered().lost(inventory, current.number);
        for (id, message) in lost {
            tracing::info!(
                held = inventory.digests.len(),
                "the wallet lost a request it had received (its app was closed): sending it again"
            );
            let connection = current.connection.clone();
            let notices = self.notices.clone();
            let config = self.config.clone();
            let span = current.span.clone();
            task::spawn(
                async move {
                    match protocol::send_message(
                        &connection,
                        &message,
                        config.max_message_size,
                        config.receive_timeout,
                        config.ack_timeout,
                    )
                    .await
                    {
                        Ok(_) => {
                            tracing::info!("the wallet confirmed the request sent again");
                            let _ = notices.try_send(Notice::Redelivered(id));
                        }
                        Err(failure) => tracing::warn!(
                            error = %failure.error,
                            "could not send again a request the wallet lost: the next connection will"
                        ),
                    }
                }
                .instrument(span),
            );
        }
    }

    /// Connector: what the wallet said of its app.
    fn heard_presence(&self, in_background: bool) {
        let before = self
            .peer_in_background
            .swap(in_background, Ordering::Relaxed);
        if before != in_background {
            self.presence.send_modify(|changes| *changes += 1);
            let _ = self.notices.try_send(Notice::Presence(in_background));
            tracing::info!(
                in_background,
                "the wallet says its app is {}",
                if in_background {
                    "in the background"
                } else {
                    "in the foreground"
                }
            );
        }
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    async fn wait_closed(&self) {
        let mut closed = self.closed.subscribe();
        // `wait_for` only fails if the sender is dropped, which outlives `self`.
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// Messages handed to the host that it has not taken yet.
    fn queued_for_host(&self) -> usize {
        self.messages.max_capacity() - self.messages.capacity()
    }

    fn relay_connected(&self) -> bool {
        let relays = self.endpoint.home_relay_status().get();
        relays.iter().any(|relay| relay.is_connected())
    }

    /// See [`Session::send`]. Runs in the message's `send` span.
    async fn send(&self, message: &str) -> Result<(), SendError> {
        let bytes = message.len();
        if self.is_closed() {
            tracing::debug!(bytes, "send refused: the session is closed");
            return Err(SendError::Closed);
        }
        let current = self.connection.borrow().clone();
        let Some(current) = current else {
            tracing::debug!(bytes, "send refused: not connected to the peer");
            return Err(SendError::NotConnected);
        };
        tracing::Span::current().record("conn", current.number);
        if self.role == Role::Connector && self.lock_delivered().already_on(message, current.number)
        {
            tracing::info!(
                bytes,
                "not sent: the wallet got this request again on this connection already"
            );
            return Ok(());
        }
        tracing::debug!(bytes, "sending a message");
        let started = Instant::now();
        let mut cancelled = CancelledSend {
            started,
            armed: true,
        };
        let sent = protocol::send_message(
            &current.connection,
            message,
            self.config.max_message_size,
            // The receiver allows this long for a message to arrive; so does the sender.
            self.config.receive_timeout,
            self.config.ack_timeout,
        )
        .await;
        cancelled.armed = false;
        match sent {
            Ok(Sent {
                transfer,
                confirmation,
            }) => {
                tracing::debug!(
                    bytes,
                    transfer_ms = ms(transfer),
                    confirm_ms = ms(confirmation),
                    total_ms = ms(started.elapsed()),
                    "message confirmed by the peer"
                );
                self.confirmed(message, current.number);
                Ok(())
            }
            Err(SendFailure {
                error,
                phase,
                elapsed,
            }) => {
                let timeout = phase.map(|phase| match phase {
                    SendPhase::Transfer => self.config.receive_timeout,
                    SendPhase::Confirmation => self.config.ack_timeout,
                });
                tracing::warn!(
                    bytes,
                    outcome = send_outcome(&error),
                    phase = phase.map(SendPhase::as_str),
                    elapsed_ms = ms(elapsed),
                    timeout_ms = timeout.map(ms),
                    total_ms = ms(started.elapsed()),
                    error = %error,
                    "could not send a message to the peer"
                );
                self.record_error("send", &error);
                Err(error)
            }
        }
    }

    fn diagnostics(&self) -> Diagnostics {
        let relays = self.endpoint.home_relay_status().get();
        let (path, rtt) = self
            .connection
            .borrow()
            .as_ref()
            .map_or((None, None), |current| {
                diagnostics::selected_path(&current.connection)
            });
        let relay_url = match &self.config.relays {
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
        let relay_connected =
            relays.iter().any(|relay| relay.is_connected()) || path == Some(PathKind::Relay);
        let relay_error = relays
            .iter()
            .find_map(|relay| relay.last_error().map(|error| Redacted(error).to_string()));
        let trouble = self.trouble();
        Diagnostics {
            role: self.role,
            local_id: self.endpoint.id(),
            peer_id: self.peer,
            relay_url,
            public_relays: self.config.relays == Relays::Public,
            relay_connected,
            relay_error,
            state: *self.state.borrow(),
            path,
            rtt,
            failed_attempts: trouble.failed_attempts,
            last_error: trouble.last_error.clone(),
            connected_for: trouble.connected_at.map(|since| since.elapsed()),
            key_collision: trouble.key_collision,
        }
    }

    /// One line with the whole snapshot, on every connect and disconnect.
    fn log_snapshot(&self) {
        tracing::info!(snapshot = %self.diagnostics(), "connectivity snapshot");
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
        self.trouble().last_error = Some(format!("{context}: {}", Redacted(error)));
    }

    /// Counts a failed dial attempt; returns how many failed in a row.
    fn record_failed_attempt(&self, error: impl Display) -> u32 {
        let mut trouble = self.trouble();
        trouble.failed_attempts = trouble.failed_attempts.saturating_add(1);
        trouble.last_error = Some(format!("dial: {}", Redacted(error)));
        trouble.failed_attempts
    }

    fn record_connected(&self) {
        let mut trouble = self.trouble();
        trouble.failed_attempts = 0;
        trouble.connected_at = Some(Instant::now());
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
        let mut previous = state;
        let changed = self.state.send_if_modified(|current| {
            previous = *current;
            *current = state;
            previous != state
        });
        if changed {
            tracing::debug!(
                from = previous.as_str(),
                to = state.as_str(),
                "connection state changed"
            );
        }
    }

    /// Numbers a new connection and opens its span.
    fn current(&self, connection: Connection) -> Current {
        let number = self.connections.fetch_add(1, Ordering::Relaxed) + 1;
        Current {
            connection,
            number,
            span: tracing::info_span!("connection", conn = number),
            connected_at: Instant::now(),
            network: *self.network.borrow(),
        }
    }

    /// Logs a new connection, how long it took to set up and how it travels.
    fn log_connected(&self, current: &Current, setup: Duration, attempt: Option<u32>) {
        let (path, rtt) = diagnostics::selected_path(&current.connection);
        current.span.in_scope(|| {
            tracing::info!(
                path = path.map(PathKind::as_str),
                rtt_ms = rtt.map(ms),
                setup_ms = ms(setup),
                attempt,
                "connected to the peer"
            );
        });
        self.log_snapshot();
    }

    /// Logs the end of a connection: why, how long it lasted, and its traffic.
    fn log_disconnected(&self, current: &Current, reason: &str) {
        let traffic = Traffic::of(&current.connection);
        current.span.in_scope(|| {
            tracing::info!(
                reason,
                connected_ms = ms(current.connected_at.elapsed()),
                sent_bytes = traffic.sent_bytes,
                received_bytes = traffic.received_bytes,
                lost_packets = traffic.lost_packets,
                blocked_by_peer_stream_limit = traffic.blocked_by_peer_stream_limit,
                peer_blocked_by_stream_limit = traffic.peer_blocked_by_stream_limit,
                "disconnected from the peer"
            );
        });
    }

    /// Lets confirmations already written reach the peer, briefly, then closes the
    /// connection (telling the peer) and the endpoint.
    async fn shut_down(&self) {
        let closing = Instant::now();
        let mut acks = self.acks_in_flight.subscribe();
        let in_flight = *acks.borrow();
        // `wait_for` only fails if the sender is dropped, which outlives `self`.
        let flushed = time::timeout(
            ACK_FLUSH_TIMEOUT,
            acks.wait_for(|in_flight| *in_flight == 0),
        )
        .await
        .is_ok();
        if in_flight > 0 && flushed {
            tracing::debug!(
                confirmations = in_flight,
                flush_ms = ms(closing.elapsed()),
                "confirmations reached the peer before closing"
            );
        } else if !flushed {
            tracing::info!(
                unflushed = *self.acks_in_flight.borrow(),
                timeout_ms = ms(ACK_FLUSH_TIMEOUT),
                "closing before every confirmation reached the peer: it may report those messages as timed out"
            );
        }
        if let Some(current) = self.connection.send_replace(None) {
            current
                .connection
                .close(CloseCode::Normal.into(), b"closed");
            self.log_disconnected(&current, "this session closed");
        }
        let endpoint_closing = Instant::now();
        self.endpoint.close().await;
        self.stopped.send_replace(true);
        tracing::info!(
            lifetime_ms = ms(self.started_at.elapsed()),
            close_ms = ms(closing.elapsed()),
            endpoint_close_ms = ms(endpoint_closing.elapsed()),
            confirmations_in_flight = in_flight,
            confirmations_flushed = flushed,
            "session closed"
        );
    }
}

/// Logs a send the host abandoned (its future was dropped) once it is dropped.
struct CancelledSend {
    started: Instant,
    armed: bool,
}

impl Drop for CancelledSend {
    fn drop(&mut self) {
        if self.armed {
            tracing::debug!(
                elapsed_ms = ms(self.started.elapsed()),
                "the host cancelled the send: its stream is reset, the peer never takes a partial message"
            );
        }
    }
}

/// A stable word for a send failure, for logs.
fn send_outcome(error: &SendError) -> &'static str {
    match error {
        SendError::NotConnected => "not_connected",
        SendError::Timeout => "timeout",
        SendError::MessageTooLarge { .. } => "too_large",
        SendError::Rejected => "rejected",
        SendError::ConnectionLost(_) => "connection_lost",
        SendError::Closed => "closed",
    }
}

/// The relay choice for the session's first line: `public`, or the custom relay's URL.
struct RelaysField<'a>(&'a Relays);

impl Display for RelaysField<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Relays::Public => f.write_str("public"),
            Relays::Custom(url) => write!(f, "{}", Redacted(url)),
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
                // `dial` returns once the session closes, after confirming a message its
                // host already took; `answer_knocks` only when the endpoint is gone.
                tokio::select! {
                    () = dial(&shared) => {}
                    () = answer_knocks(&shared) => {}
                }
                None
            }
            Role::Connector => {
                // Side by side: the knocks end within seconds, the session is the accept loop.
                let (serving, ()) = tokio::join!(accept(&shared), knock_on_start(&shared));
                serving
            }
        }
    };
    let serving = tokio::select! {
        serving = run => serving,
        () = watch_relay(&shared) => None,
    };
    // The connector's serving task stays alive while closing waits for confirmations.
    shared.shut_down().await;
    drop(serving);
}

/// Why the wallet dials (again), for logs.
#[derive(Debug, Clone, Copy)]
enum DialReason {
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
async fn dial(shared: &Arc<Shared>) {
    // With the public relays the connector's relay is found through address lookup.
    let peer_addr = match &shared.config.relays {
        Relays::Public => EndpointAddr::new(shared.peer),
        Relays::Custom(url) => EndpointAddr::new(shared.peer).with_relay_url(url.clone()),
    };
    let config = &shared.config;
    let mut network = shared.network.subscribe();
    let mut knocks = shared.knocks.subscribe();
    let mut retry = Retry::new(shared.started_at, config);
    let mut delay = config.min_reconnect_delay;
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
            timeout_ms = ms(shared.config.connect_timeout),
            "dialing the connector"
        );
        let started = Instant::now();
        let dialing = time::timeout(
            shared.config.connect_timeout,
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
                retry = Retry::new(unreachable_since, config);
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
                timeout_ms = ms(shared.config.connect_timeout),
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
            (delay, slowing_down) = retry.after_failure(Instant::now(), config);
            if slowing_down {
                tracing::info!(
                    unreachable_ms = ms(unreachable_since.elapsed()),
                    fast_retry_period_ms = ms(config.fast_retry_period),
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
                retry = Retry::new(Instant::now(), config);
            }
            () = time::sleep(delay) => {}
        }
        waited = waiting.elapsed();
    }
}

/// The wallet's schedule of attempts while the connector is out of reach: quick ones
/// (a back-off from `min_reconnect_delay`, doubling up to `max_reconnect_delay`) for
/// `fast_retry_period` after the connection was lost, the session started or the host
/// reported a wake-up (network change, app back in the foreground), then one every
/// `slow_reconnect_delay`, so that links to connectors that stay offline do not keep the
/// phone's radio awake. A connection resets it.
#[derive(Debug, Clone, Copy)]
struct Retry {
    fast_since: Instant,
    next_fast: Duration,
    slow: bool,
}

impl Retry {
    fn new(fast_since: Instant, config: &SessionConfig) -> Self {
        Self {
            fast_since,
            next_fast: config.min_reconnect_delay,
            slow: false,
        }
    }

    /// The wait after an attempt that failed at `now`, and whether it is the first of
    /// the slow ones.
    fn after_failure(&mut self, now: Instant, config: &SessionConfig) -> (Duration, bool) {
        if now.saturating_duration_since(self.fast_since) >= config.fast_retry_period {
            let first = !std::mem::replace(&mut self.slow, true);
            (config.slow_reconnect_delay, first)
        } else {
            let delay = self.next_fast;
            self.next_fast = (delay * 2)
                .max(config.min_reconnect_delay)
                .min(config.max_reconnect_delay);
            (delay, false)
        }
    }
}

/// The relay the endpoint knows the connector at, if any (redacted, for logs).
async fn peer_relay(shared: &Shared) -> Option<String> {
    let info = shared.endpoint.remote_info(shared.peer).await?;
    info.addrs().find_map(|addr| match addr.addr() {
        TransportAddr::Relay(url) => Some(Redacted(url).to_string()),
        _ => None,
    })
}

/// Logs when this end gains or loses its relay (without it the peer cannot reach it,
/// the first thing to check when a link does not connect) and the relay's notices
/// that another holder of this link's key took over. Never returns.
async fn watch_relay(shared: &Shared) {
    let mut statuses = shared.endpoint.home_relay_status().stream();
    let mut notices = shared.relay.notices();
    let mut relay = RelayLog {
        connected: false,
        warned: false,
        home: None,
        since: shared.started_at,
    };
    loop {
        tokio::select! {
            Some(statuses) = statuses.next() => relay.status(shared, &statuses),
            Ok(()) = notices.changed() => {
                let notice = *notices.borrow_and_update();
                if let Some(notice) = notice {
                    relay.notice(shared, notice);
                }
            }
            else => break,
        }
    }
    std::future::pending::<()>().await;
}

/// What [`watch_relay`] remembers between updates.
struct RelayLog {
    connected: bool,
    /// Whether the current outage was already reported at `warn`.
    warned: bool,
    home: Option<RelayUrl>,
    /// Since when the relay has been connected, or not.
    since: Instant,
}

impl RelayLog {
    fn status(&mut self, shared: &Shared, statuses: &[iroh::endpoint::RelayStatus]) {
        let connected_to = statuses.iter().find(|relay| relay.is_connected());
        let connected = connected_to.is_some();
        let error = statuses
            .iter()
            .find_map(|relay| relay.last_error().map(|error| Redacted(error).to_string()));
        let auth_denied = statuses
            .iter()
            .find_map(|relay| relay.auth_denied_reason().map(str::to_owned));
        let url = connected_to
            .or(statuses.first())
            .map(|relay| relay.url().clone());
        let relay = url
            .as_ref()
            .map_or_else(|| "none".to_owned(), |url| Redacted(url).to_string());
        let now = Instant::now();
        if connected && !self.connected {
            tracing::info!(
                relay,
                after_ms = ms(now.duration_since(self.since)),
                "connected to the relay"
            );
            self.since = now;
            self.warned = false;
            // The relay delivers to its newest client: this end, now.
            if std::mem::take(&mut shared.trouble().key_collision) {
                tracing::info!(
                    "reconnected to the relay, which delivers to this end again: the other holder of this link's key no longer receives through it"
                );
            }
        } else if connected && url != self.home {
            tracing::info!(relay, "moved to another relay");
        } else if !connected && self.connected {
            tracing::warn!(
                relay,
                error = error.as_deref().unwrap_or("none"),
                connected_ms = ms(now.duration_since(self.since)),
                "lost the connection to the relay: the peer cannot reach this end until it reconnects"
            );
            self.since = now;
            self.warned = true;
        } else if !connected && (error.is_some() || auth_denied.is_some()) {
            if self.warned {
                tracing::debug!(
                    relay,
                    error = error.as_deref().unwrap_or("none"),
                    down_ms = ms(now.duration_since(self.since)),
                    "still not connected to the relay"
                );
            } else {
                tracing::warn!(
                    relay,
                    error = error.as_deref().unwrap_or("none"),
                    auth_denied = auth_denied.as_deref(),
                    "cannot connect to the relay: the peer cannot reach this end"
                );
                self.warned = true;
            }
        }
        self.connected = connected;
        if connected {
            self.home = url;
        }
    }

    fn notice(&mut self, shared: &Shared, notice: RelayNotice) {
        let relay = self
            .home
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |url| Redacted(url).to_string());
        match notice {
            RelayNotice::Displaced => {
                shared.trouble().key_collision = true;
                tracing::warn!(
                    relay,
                    "another device or app instance with this link's key connected to the relay; this end no longer receives through it (the relay delivers to the newest holder)"
                );
                shared.log_snapshot();
            }
            RelayNotice::Restored => {
                if std::mem::take(&mut shared.trouble().key_collision) {
                    tracing::info!(
                        relay,
                        "the relay delivers to this end again: the other holder of this link's key disconnected"
                    );
                } else {
                    tracing::debug!(relay, "the relay reports the connection healthy again");
                }
            }
        }
    }
}

/// How many knocks a wallet takes at once: a knock is one handshake, and nothing else.
const KNOCKS_IN_FLIGHT: usize = 4;
/// How long a knock's handshake may take.
const KNOCK_TIMEOUT: Duration = Duration::from_secs(3);
/// A knock's initial RTT estimate: about a relay's round trip.
const KNOCK_INITIAL_RTT: Duration = Duration::from_millis(100);
/// Knocks closer together than this wake the wallet once: even its own connector cannot keep
/// it dialing.
const KNOCK_MIN_GAP: Duration = Duration::from_secs(2);
/// When a connector knocks after its session starts, while its wallet is not connected.
const KNOCKS_AT: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_secs(2),
    Duration::from_secs(6),
];

/// Wallet: takes the knocks of its connector — a connector that just started — and dials at
/// once instead of at its next retry. A knock carries nothing: the handshake proves the
/// connector's key (the guard turns away anybody else, as for every connection), and the
/// wallet closes it right after. Anything else is ignored, as before.
async fn answer_knocks(shared: &Shared) {
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
                    Ok(Ok(connection)) if connection.alpn() == KNOCK_ALPN => {
                        connection.close(CloseCode::Knocked.into(), b"dialing");
                        let now = Instant::now();
                        // Connected already: nothing to wake, and nothing to check. A knock
                        // while connected comes from another process holding the same link (two
                        // logins at once, say) or from a connector that restarted without closing
                        // the old connection. Checking the connection then is no answer: with two
                        // holders the check fails on a live connection, and cutting it loses what
                        // it carries — a signature the person just approved. A dead connection
                        // ends on its own (QUIC's idle timeout) and the wallet redials then.
                        if *shared.state.borrow() == ConnectionState::Connected {
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
async fn knock_on_start(shared: &Shared) {
    let Some(relay) = shared.config.knock_relay().cloned() else {
        return;
    };
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
    for at in KNOCKS_AT {
        // Closing never waits for a knock (nor for the next one).
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            () = time::sleep_until(shared.started_at + at) => {}
        }
        if *shared.state.borrow() == ConnectionState::Connected {
            return;
        }
        tokio::select! {
            biased;
            () = shared.wait_closed() => return,
            _ = knock(shared, &relay) => {}
        }
    }
}

/// One knock at `relay`: whether the wallet took it.
async fn knock(shared: &Shared, relay: &RelayUrl) -> bool {
    let started = Instant::now();
    let addr = EndpointAddr::new(shared.peer).with_relay_url(relay.clone());
    // Its own transport settings: an initial RTT close to a relay's, not QUIC's 333 ms guess, so
    // a knock retries quickly while the wallet is not up, and a knock abandoned when the session
    // closes drains in a fraction of a second instead of holding up the endpoint for 3.
    let options = ConnectOptions::new().with_transport_config(
        QuicTransportConfig::builder()
            .initial_rtt(KNOCK_INITIAL_RTT)
            .max_concurrent_bidi_streams(0u32.into())
            .max_concurrent_uni_streams(0u32.into())
            .build(),
    );
    let knocking = async {
        shared
            .endpoint
            .connect_with_opts(addr, KNOCK_ALPN, options)
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

/// Where an incoming attempt comes from, without its address.
fn origin(addr: &IncomingAddr) -> &'static str {
    match addr {
        IncomingAddr::Relay { .. } => "relay",
        IncomingAddr::Ip(_) => "direct",
        _ => "custom",
    }
}

/// The connection the connector is serving, and the task serving it.
struct Serving {
    current: Current,
    _task: AbortOnDropHandle<()>,
}

/// Connection attempts the connector turned away, summarised every minute so that
/// strangers or a faulty relay cannot flood the logs.
#[derive(Default)]
struct TurnedAway {
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

fn lock(tally: &std::sync::Mutex<Tally>) -> std::sync::MutexGuard<'_, Tally> {
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
async fn accept(shared: &Arc<Shared>) -> Option<Serving> {
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
async fn tagged<T, F: Future>(tag: T, future: F) -> (T, F::Output) {
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
    Ignore(Ignored),
}

/// Why an incoming attempt is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ignored {
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
                Admission::Ignore(Ignored::WalletPoolFull)
            }
        }
        IncomingAddr::Relay { .. } => Admission::Ignore(Ignored::Stranger),
        _ if !validated => Admission::ValidateAddress,
        _ if pending.direct >= MAX_DIRECT_HANDSHAKES => Admission::Ignore(Ignored::DirectPoolFull),
        _ => Admission::Handshake { from_peer: false },
    }
}

/// Serves a connection until it ends or the session closes: delivers the peer's
/// messages and checks that the peer still answers when the network changes. Returns
/// why the connection ended, or `None` if it did not end because the session closed.
async fn serve(shared: &Shared, current: &Current) -> Option<Ended> {
    tokio::select! {
        ended = serve_streams(shared, current) => ended.map(|reason| Ended {
            reason,
            unresponsive: false,
        }),
        ended = check_liveness(shared, current) => Some(ended),
    }
}

/// Checks that the peer still answers each time the host reports a network change
/// (hosts report the app returning to the foreground, or the machine waking up, as
/// one): a connection that died meanwhile would otherwise look alive until QUIC's idle
/// timeout. One check at a time; changes reported meanwhile, or within
/// [`PROBE_DEBOUNCE`] of a check, share the next one. Returns only once the peer did not
/// answer, having closed the connection.
async fn check_liveness(shared: &Shared, current: &Current) -> Ended {
    let connection = &current.connection;
    let mut requests = shared.network.subscribe();
    // Changes reported before the connection existed are no reason to check it; one
    // reported since is, even if this task only starts now.
    let mut pending = *requests.borrow_and_update() != current.network;
    let mut presence = shared.presence.subscribe();
    let mut last: Option<Instant> = None;
    loop {
        let mut why = "network_changed";
        if !std::mem::take(&mut pending) {
            // A network change, or — while the wallet's app is in the background — the next
            // periodic check. A change of presence only starts or stops the period.
            let in_background =
                shared.role == Role::Connector && shared.peer_in_background.load(Ordering::Relaxed);
            tokio::select! {
                changed = requests.changed() => {
                    if changed.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                () = time::sleep(BACKGROUND_PROBE_INTERVAL), if in_background => why = "app_in_background",
                Ok(()) = presence.changed() => continue,
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
        let deadline = probe_deadline(rtt, path, relay_connected);
        // Every few seconds while the app is in the background: worth a debug line only.
        let periodic = why != "network_changed";
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
fn probe_deadline(
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

/// Delivers the peer's messages, one stream at a time, until the connection ends or
/// the session closes. Each message is confirmed only once the host took it. Returns
/// why the connection ended, or `None` if it did not end because the session closed.
async fn serve_streams(shared: &Shared, current: &Current) -> Option<String> {
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
async fn receive(shared: &Shared, send: SendStream, mut recv: RecvStream, seq: u64) -> bool {
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
    let acknowledged = answer.acknowledge(ACK_FLUSH_TIMEOUT).await;
    drop(owed);
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
    true
}

/// A confirmation owed to the peer, counted in `acks_in_flight` from the moment the
/// host takes the message until it is written and acknowledged, or abandoned (dropped
/// with the channel or the future that holds it).
#[derive(Debug)]
struct OwedConfirmation(Arc<watch::Sender<usize>>);

impl OwedConfirmation {
    fn new(in_flight: &Arc<watch::Sender<usize>>) -> Self {
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
struct PathLog {
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

#[cfg(test)]
mod tests;
