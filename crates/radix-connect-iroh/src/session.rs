use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use iroh::endpoint::{Connection, QuicTransportConfig, presets};
use iroh::{Endpoint, EndpointId, RelayUrl, TransportAddr, Watcher};
use n0_future::task::{self, AbortOnDropHandle};
use n0_future::time;
use n0_future::time::Instant;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tracing::Instrument;

use crate::config::{DORMANT_AFTER, Relays, RetryPolicy};
use crate::diagnostics::{self, Diagnostics, PathKind, Tally, Traffic, ms};
use crate::guard::PeerGuard;
use crate::link_memory::{self, LinkMemory};
use crate::logging::Redacted;
use crate::protocol::{
    self, ALPN, CloseCode, KNOCK_ALPN, KNOCK_RESTARTED_ALPN, SendFailure, SendPhase, Sent,
};
use crate::relay_health;
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

/// How long closing waits for confirmations already written to reach the peer.
const ACK_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// Bytes the peer may have in flight across all its streams, instead of QUIC's
/// unbounded default: messages are read one at a time, so this only bounds what an
/// authenticated peer can make us buffer.
const RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;

/// Streams the peer may have open at once. Messages are read one at a time, so this
/// only caps how much the peer can queue up.
const MAX_CONCURRENT_STREAMS: u32 = 16;

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
    /// Bumped each time this end reconnects to its relay after losing it (the computer woke
    /// from sleep, the network came back): a connector then knocks for its wallet again.
    relay_regained: watch::Sender<u64>,
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
    /// Connector: the relay the wallet last said it is reachable on (one of this session's
    /// relays): where its knocks go, and the link's relay hint.
    peer_home_relay: std::sync::Mutex<Option<RelayUrl>>,
    /// When the peer was last connected (Unix seconds; 0: not known), from the link memory
    /// given back, then each connection: kept in the memory, and with `known_since` what
    /// makes a wallet treat a link as dormant (see `RetryPolicy::dormant`).
    last_connected: AtomicU64,
    /// Since when the link is known (Unix seconds): from the memory given back, or this
    /// session's start for a link with none.
    known_since: Option<u64>,
    /// Bumped each time the wallet says its app went to the background: the connector then
    /// watches the connection closely for a moment (see `liveness`).
    went_to_background: watch::Sender<u64>,
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
            // In order of preference: a connector offers both kinds of knock.
            Role::Wallet => vec![KNOCK_RESTARTED_ALPN.to_vec(), KNOCK_ALPN.to_vec()],
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
        let last_connected = AtomicU64::new(config.last_connected.unwrap_or(0));
        let known_since = config.known_since.or_else(link_memory::unix_now);
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
            relay_regained: watch::Sender::new(0),
            acks_in_flight: Arc::new(watch::Sender::new(0)),
            trouble: std::sync::Mutex::default(),
            connections: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            relay,
            unauthorized,
            in_background: AtomicBool::new(false),
            peer_in_background: AtomicBool::new(false),
            peer_home_relay: std::sync::Mutex::default(),
            last_connected,
            known_since,
            went_to_background: watch::Sender::new(0),
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
                connect_timeout_ms = ms(config.retry.connect_timeout),
                min_reconnect_delay_ms = ms(config.retry.min_delay),
                max_reconnect_delay_ms = ms(config.retry.max_delay),
                fast_retry_period_ms = ms(config.retry.fast_period),
                slow_reconnect_delay_ms = ms(config.retry.slow_delay),
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

    /// What this session remembers of its link, for the host to store with it and give back
    /// to the link's next session ([`SessionConfig::with_link_memory`]): an opaque string with
    /// no secret (the relay the peer was last seen on, when it was last connected, and since
    /// when the link is known). Read it after a connection ([`ConnectionState::Connected`])
    /// and when stopping the session.
    pub async fn link_memory(&self) -> String {
        let peer_relay = self
            .peer_relay()
            .await
            .or_else(|| self.shared.config.peer_relay.clone());
        self.shared.memory(peer_relay).to_text()
    }

    /// The relay the peer is on, as this end knows it (best while connected). A connector
    /// keeps its wallet's as the link's relay hint, for [`SessionConfig::with_peer_relay`]:
    /// the next session knocks there. The relay the wallet says it is on, once it did;
    /// before that (or with a wallet that predates it) a relay the connection knows the peer
    /// by, which may be the one that carried the connection rather than the wallet's own.
    pub async fn peer_relay(&self) -> Option<RelayUrl> {
        if let Some(told) = self.shared.peer_home_relay() {
            return Some(told);
        }
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
        knock(&self.shared, relay, false)
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

    /// Connector: the host cancelled the dApp request `interaction_id` (its dApp, or the
    /// person, gave up on it). It is no longer delivered again to a wallet that lost it: a
    /// wallet opened later does not show a request nobody waits for. A request the wallet
    /// still holds stays there; only the wallet can end it.
    pub fn forget_request(&self, interaction_id: &str) {
        if self.shared.role == Role::Connector {
            self.shared.lock_delivered().forget(interaction_id);
        }
    }

    /// A snapshot of the session's connectivity, for logs (its `Display` is one line)
    /// and diagnostics screens. Cheap; contains no secrets.
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
        self.tell_home_relay(connection);
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

    /// Wallet: tells the connector the relay it is reachable on, when it has one (twice, a
    /// moment apart, as its presence). Again whenever it gets a relay or moves to another.
    fn tell_home_relay(&self, connection: &iroh::endpoint::Connection) {
        if self.role != Role::Wallet {
            return;
        }
        let Some(datagram) = self
            .endpoint
            .addr()
            .relay_urls()
            .next()
            .and_then(protocol::home_relay)
        else {
            return;
        };
        if connection
            .send_datagram(bytes::Bytes::copy_from_slice(&datagram))
            .is_err()
        {
            return;
        }
        tracing::debug!("told the peer the relay this end is on");
        let again = connection.clone();
        task::spawn(async move {
            time::sleep(Duration::from_millis(250)).await;
            let _ = again.send_datagram(bytes::Bytes::from(datagram));
        });
    }

    /// Wallet: this end got a relay, or moved to another: tells the connector, if connected.
    fn home_relay_changed(&self) {
        if let Some(current) = self.connection.borrow().clone() {
            self.tell_home_relay(&current.connection);
        }
    }

    /// Connector: the wallet said it is reachable on `relay`. Kept only if it is one of this
    /// session's relays: a knock goes nowhere else.
    fn heard_home_relay(&self, relay: RelayUrl) {
        let ours = match &self.config.relays {
            Relays::Custom(url) => *url == relay,
            // The relays the endpoint was built with (see `with_relays`).
            Relays::Public => iroh::endpoint::default_relay_mode()
                .relay_map()
                .contains(&relay),
        };
        if !ours {
            tracing::debug!(
                relay = %Redacted(&relay),
                "ignored the relay the wallet says it is on: not one of this end's relays"
            );
            return;
        }
        let mut known = self
            .peer_home_relay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if known.as_ref() != Some(&relay) {
            tracing::info!(relay = %Redacted(&relay), "the wallet says which relay it is on");
            *known = Some(relay);
        }
    }

    /// Connector: the relay the wallet last said it is on.
    fn peer_home_relay(&self) -> Option<RelayUrl> {
        self.peer_home_relay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Connector: where to knock for the wallet now: the relay it said it is on in this
    /// session, else the hint the session started with (see [`SessionConfig::knock_relay`]).
    fn knock_relay(&self) -> Option<RelayUrl> {
        let configured = self.config.knock_relay().cloned();
        if !self.config.knocks || matches!(self.config.relays, Relays::Custom(_)) {
            return configured;
        }
        self.peer_home_relay().or(configured)
    }

    /// Connector: what the wallet said of its app.
    fn heard_presence(&self, in_background: bool) {
        let before = self
            .peer_in_background
            .swap(in_background, Ordering::Relaxed);
        if before != in_background {
            if in_background {
                self.went_to_background.send_modify(|count| *count += 1);
            }
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
        if let Some(now) = link_memory::unix_now() {
            self.last_connected.store(now, Ordering::Relaxed);
        }
    }

    /// What this session knows of its link now, with `peer_relay` as the peer's relay.
    fn memory(&self, peer_relay: Option<RelayUrl>) -> LinkMemory {
        LinkMemory {
            peer_relay,
            last_connected: Some(self.last_connected.load(Ordering::Relaxed)).filter(|&at| at != 0),
            known_since: self.known_since,
        }
    }

    /// The wallet's dialing schedule: [dormant](RetryPolicy::dormant) for a link whose connector
    /// has not been connected for [`DORMANT_AFTER`] (or never, in that long since the link is
    /// known), the regular one otherwise, a new link's included.
    fn retry_policy(&self) -> RetryPolicy {
        let dormant = link_memory::unix_now()
            .and_then(|now| self.memory(None).since_last_seen(now))
            .is_some_and(|since| since >= DORMANT_AFTER.as_secs());
        if dormant {
            self.config.retry.dormant()
        } else {
            self.config.retry
        }
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
                // Side by side: the session is the accept loop; the knocks on start end within
                // seconds, and those after a relay outage when the session closes.
                let knocking = async {
                    tokio::join!(knock_on_start(&shared), knock_when_relay_returns(&shared));
                };
                let (serving, ()) = tokio::join!(accept(&shared), knocking);
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

mod accept;
mod dial;
mod endpoint;
mod knocks;
mod liveness;
mod receive;
mod relay_watch;

use accept::accept;
use dial::dial;
use endpoint::{RelaysField, with_relays};
use knocks::{answer_knocks, knock, knock_on_start, knock_when_relay_returns};
use receive::OwedConfirmation;
use relay_watch::watch_relay;

#[cfg(test)]
mod tests;
