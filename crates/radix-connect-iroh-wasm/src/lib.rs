//! Browser bindings of [`radix_connect_iroh`] for the Radix Connector Extension. See
//! `docs/BINDINGS.md` for the resulting TypeScript API.
//!
//! In the browser iroh cannot use UDP: every connection goes through the relay's
//! WebSocket (`wss://`), still end-to-end encrypted by QUIC between the two endpoints.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Once;
use std::time::Duration;

use js_sys::{Function, Object, Promise, Reflect};
use radix_connect_iroh as core;
use radix_connect_iroh::logging::{
    DiagnosticsLayer, format_event_with_context, host_log_enabled, needed_for_diagnostics,
};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, spawn_local};
use zeroize::Zeroize;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &'static str = r#"
export type IrohRole = 'wallet' | 'connector'
export type IrohConnectionState = 'connecting' | 'connected' | 'disconnected'
export type IrohSessionEvent =
  | { type: 'stateChanged'; state: IrohConnectionState }
  | { type: 'message'; message: string }
  /** A request the wallet lost with its app was delivered to it again. */
  | { type: 'requestRedelivered'; interactionId: string }
  /** The wallet's app went to the background, or came back. */
  | { type: 'peerPresence'; inBackground: boolean }
export type IrohErrorCode =
  | 'invalidPassword'
  | 'invalidRelayUrl'
  | 'bind'
  | 'notConnected'
  | 'timeout'
  | 'messageTooLarge'
  | 'rejected'
  | 'connectionLost'
  | 'closed'
  | 'internal'
/** Rejection value of every failing call. */
export type IrohError = Error & { code: IrohErrorCode }
export type IrohLogLevel = 'error' | 'warn' | 'info' | 'debug' | 'trace'
/** A snapshot of a session's connectivity. Holds no secrets. */
export type IrohDiagnostics = {
  role: IrohRole
  localEndpointId: string
  peerEndpointId: string
  /** The custom relay, or the public relay this end connected to. */
  relayUrl?: string
  /** Whether this end uses n0's public relays. */
  publicRelays: boolean
  /** Without the relay the peer cannot reach this end. */
  relayConnected: boolean
  relayError?: string
  state: IrohConnectionState
  path?: 'direct' | 'relay'
  rttMs?: number
  failedAttempts: number
  lastError?: string
  connectedForMs?: number
  /** All of the above in one line, ready for a log. */
  summary: string
  /**
   * Another device or browser profile with this link took this end's place on the
   * relay: the peer cannot reach this end until it leaves or this end reconnects.
   */
  keyCollision: boolean
}
export type IrohLogger = (level: IrohLogLevel, target: string, message: string) => void
"#;

/// A JS `Error` carrying a machine-readable `code`.
fn js_error(code: &str, message: impl std::fmt::Display) -> JsValue {
    let error = js_sys::Error::new(&message.to_string());
    // Setting a property on a fresh Error object cannot fail.
    let _ = Reflect::set(&error, &"code".into(), &code.into());
    error.into()
}

fn error_from(error: core::Error) -> JsValue {
    let code = match &error {
        core::Error::InvalidPassword => "invalidPassword",
        core::Error::InvalidRelayUrl(_) => "invalidRelayUrl",
        core::Error::Bind(_) => "bind",
        _ => "internal",
    };
    js_error(code, error)
}

fn send_error_from(error: core::SendError) -> JsValue {
    let code = match &error {
        core::SendError::NotConnected => "notConnected",
        core::SendError::Timeout => "timeout",
        core::SendError::MessageTooLarge { .. } => "messageTooLarge",
        core::SendError::Rejected => "rejected",
        core::SendError::ConnectionLost(_) => "connectionLost",
        core::SendError::Closed => "closed",
        _ => "internal",
    };
    js_error(code, error)
}

fn role_from(role: &str) -> Result<core::Role, JsValue> {
    match role {
        "wallet" => Ok(core::Role::Wallet),
        "connector" => Ok(core::Role::Connector),
        other => Err(js_error("internal", format!("unknown role {other:?}"))),
    }
}

fn state_name(state: core::ConnectionState) -> &'static str {
    match state {
        core::ConnectionState::Connecting => "connecting",
        core::ConnectionState::Connected => "connected",
        core::ConnectionState::Disconnected => "disconnected",
    }
}

fn event_to_js(event: core::SessionEvent) -> JsValue {
    let object = Object::new();
    let (kind, key, value): (&str, &str, JsValue) = match event {
        core::SessionEvent::StateChanged(state) => {
            ("stateChanged", "state", state_name(state).into())
        }
        core::SessionEvent::Message(message) => ("message", "message", message.into()),
        core::SessionEvent::RequestRedelivered(id) => {
            ("requestRedelivered", "interactionId", id.into())
        }
        core::SessionEvent::PeerPresence { in_background } => {
            ("peerPresence", "inBackground", in_background.into())
        }
    };
    // Setting properties on a fresh plain object cannot fail.
    let _ = Reflect::set(&object, &"type".into(), &kind.into());
    let _ = Reflect::set(&object, &key.into(), &value);
    object.into()
}

fn diagnostics_to_js(diagnostics: core::Diagnostics) -> JsValue {
    let object = Object::new();
    let millis = |duration: Duration| JsValue::from_f64(duration.as_millis() as f64);
    let set = |key: &str, value: JsValue| {
        // Setting properties on a fresh plain object cannot fail.
        let _ = Reflect::set(&object, &key.into(), &value);
    };
    set("summary", diagnostics.to_string().into());
    set(
        "role",
        match diagnostics.role {
            core::Role::Wallet => "wallet",
            core::Role::Connector => "connector",
        }
        .into(),
    );
    set("localEndpointId", diagnostics.local_id.to_string().into());
    set("peerEndpointId", diagnostics.peer_id.to_string().into());
    if let Some(url) = diagnostics.relay_url {
        set("relayUrl", url.to_string().into());
    }
    set("publicRelays", diagnostics.public_relays.into());
    set("relayConnected", diagnostics.relay_connected.into());
    if let Some(error) = diagnostics.relay_error {
        set("relayError", error.into());
    }
    set("state", state_name(diagnostics.state).into());
    if let Some(path) = diagnostics.path {
        let path = match path {
            core::PathKind::Direct => "direct",
            core::PathKind::Relay => "relay",
        };
        set("path", path.into());
    }
    if let Some(rtt) = diagnostics.rtt {
        set("rttMs", millis(rtt));
    }
    set("failedAttempts", diagnostics.failed_attempts.into());
    if let Some(error) = diagnostics.last_error {
        set("lastError", error.into());
    }
    if let Some(connected_for) = diagnostics.connected_for {
        set("connectedForMs", millis(connected_for));
    }
    set("keyCollision", diagnostics.key_collision.into());
    object.into()
}

/// Takes ownership of the JS copy of the password and wipes it once parsed.
fn password_from(mut bytes: Vec<u8>) -> Result<core::ConnectionPassword, JsValue> {
    let password = core::ConnectionPassword::from_slice(&bytes);
    bytes.zeroize();
    password.map_err(error_from)
}

/// One end of a Radix Connect link over iroh.
#[wasm_bindgen]
#[derive(Debug)]
pub struct IrohSession {
    session: Rc<core::Session>,
}

#[wasm_bindgen]
impl IrohSession {
    /// Starts the `role` end of the link secured by `password` (32 bytes). With no
    /// `relayUrl` it uses n0's public relays (the default); otherwise that custom relay.
    /// Both ends of a link must make the same choice. Connecting happens in the
    /// background (see `nextEvent`).
    ///
    /// `peerRelayUrl`: for a connector, the relay its wallet was last seen on (`peerRelay`,
    /// kept with the link): the session knocks there as it starts, and a wallet that is up
    /// connects at once. A wrong or unusable one only means no knock.
    ///
    /// `soleHolder`: for a connector that is the only holder of its links (an extension): as
    /// it starts, a wallet still connected to an earlier run that ended without closing (a
    /// reload) drops that connection and dials at once. Never for a link several processes
    /// may hold at once.
    pub async fn start(
        password: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "IrohRole")] role: String,
        #[wasm_bindgen(js_name = relayUrl)] relay_url: Option<String>,
        #[wasm_bindgen(js_name = ackTimeoutMs)] ack_timeout_ms: Option<u32>,
        #[wasm_bindgen(js_name = peerRelayUrl)] peer_relay_url: Option<String>,
        #[wasm_bindgen(js_name = soleHolder)] sole_holder: Option<bool>,
    ) -> Result<IrohSession, JsValue> {
        let password = password_from(password)?;
        let role = role_from(&role)?;
        let mut config =
            core::SessionConfig::for_relay(relay_url.as_deref()).map_err(error_from)?;
        if let Some(ack_timeout_ms) = ack_timeout_ms {
            config = config.with_ack_timeout(Duration::from_millis(ack_timeout_ms.into()));
        }
        if let Some(peer_relay_url) = peer_relay_url.as_deref() {
            config = config
                .clone()
                .with_peer_relay(peer_relay_url)
                .unwrap_or(config);
        }
        if sole_holder == Some(true) {
            config = config.as_sole_holder();
        }
        install_subscriber();
        let session = core::Session::start(&password, role, config)
            .await
            .map_err(error_from)?;
        Ok(Self {
            session: Rc::new(session),
        })
    }

    /// Hex id of this end of the link.
    #[wasm_bindgen(js_name = localEndpointId)]
    pub fn local_endpoint_id(&self) -> String {
        self.session.local_id().to_string()
    }

    /// Hex id of the other end: the only endpoint this session talks to.
    #[wasm_bindgen(js_name = peerEndpointId)]
    pub fn peer_endpoint_id(&self) -> String {
        self.session.peer_id().to_string()
    }

    /// Current connection state.
    #[wasm_bindgen(unchecked_return_type = "IrohConnectionState")]
    pub fn state(&self) -> String {
        state_name(self.session.state()).to_owned()
    }

    /// A snapshot of the connectivity, for logs and diagnostics screens. Cheap.
    /// Connector: whether the wallet reports the requests it holds, so one it lost with
    /// its app comes back by itself (a `requestRedelivered` event).
    #[wasm_bindgen(js_name = peerReportsRequests)]
    pub fn peer_reports_requests(&self) -> bool {
        self.session.peer_reports_requests()
    }

    /// Connector: the dApp request `interactionId` was cancelled: it is not delivered
    /// again to a wallet that lost it with its app.
    #[wasm_bindgen(js_name = forgetRequest)]
    pub fn forget_request(&self, #[wasm_bindgen(js_name = interactionId)] interaction_id: String) {
        self.session.forget_request(&interaction_id);
    }

    #[wasm_bindgen(unchecked_return_type = "IrohDiagnostics")]
    pub fn diagnostics(&self) -> JsValue {
        diagnostics_to_js(self.session.diagnostics())
    }

    /// Sends one message (UTF-8 JSON) and resolves once the peer confirmed it.
    /// Rejects at once with code `notConnected` when there is no connection.
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn send(&self, message: String) -> Promise {
        let session = self.session.clone();
        future_to_promise(async move {
            session
                .send(&message)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(send_error_from)
        })
    }

    /// Resolves with the next event, or `undefined` once the session is shut down.
    /// Taking a message confirms it to the peer: keep a loop calling this for the
    /// whole life of the session.
    #[wasm_bindgen(js_name = nextEvent, unchecked_return_type = "Promise<IrohSessionEvent | undefined>")]
    pub fn next_event(&self) -> Promise {
        let session = self.session.clone();
        future_to_promise(async move {
            Ok(session
                .next_event()
                .await
                .map_or(JsValue::UNDEFINED, event_to_js))
        })
    }

    /// Reports that the network changed, or that the machine woke up or the extension
    /// became active again: a waiting wallet dials at once, and the current connection
    /// is checked, dropped within seconds if the peer no longer answers (instead of
    /// looking connected until it times out).
    /// The relay the peer is on, as this end knows it (best while connected), or undefined:
    /// for a connector, what to keep with the link and pass back as `peerRelayUrl`.
    #[wasm_bindgen(js_name = peerRelay, unchecked_return_type = "Promise<string | undefined>")]
    pub fn peer_relay(&self) -> Promise {
        let session = self.session.clone();
        future_to_promise(async move {
            Ok(session
                .peer_relay()
                .await
                .map_or(JsValue::UNDEFINED, |url| JsValue::from_str(url.as_str())))
        })
    }

    #[wasm_bindgen(js_name = networkChanged, unchecked_return_type = "Promise<void>")]
    pub fn network_changed(&self) -> Promise {
        let session = self.session.clone();
        future_to_promise(async move {
            session.network_changed().await;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Closes the connection, telling the peer, and the endpoint. Idempotent. Call
    /// `free()` afterwards to release the memory.
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn shutdown(&self) -> Promise {
        let session = self.session.clone();
        future_to_promise(async move {
            session.close().await;
            Ok(JsValue::UNDEFINED)
        })
    }
}

impl Drop for IrohSession {
    /// `free()` without `shutdown()`, or with calls still pending: close the session
    /// anyway, so it stops accepting the wallet. A no-op after `shutdown()`.
    fn drop(&mut self) {
        let session = self.session.clone();
        spawn_local(async move { session.close().await });
    }
}

/// The URLs of n0's public relays, used when no custom relay is configured (for display).
#[wasm_bindgen(js_name = publicRelayUrls)]
pub fn public_relay_urls() -> Vec<String> {
    core::public_relay_urls()
        .into_iter()
        .map(|url| url.to_string())
        .collect()
}

/// Hex endpoint id of the `role` end of the link secured by `password`.
#[wasm_bindgen(js_name = endpointId)]
pub fn endpoint_id(
    password: Vec<u8>,
    #[wasm_bindgen(unchecked_param_type = "IrohRole")] role: String,
) -> Result<String, JsValue> {
    Ok(password_from(password)?
        .endpoint_id(role_from(&role)?)
        .to_string())
}

/// Checks a relay URL the user typed. Returns why it is not usable, or `undefined`.
#[wasm_bindgen(js_name = validateRelayUrl)]
pub fn validate_relay_url(#[wasm_bindgen(js_name = relayUrl)] relay_url: String) -> Option<String> {
    core::SessionConfig::new(&relay_url)
        .err()
        .map(|error| error.to_string())
}

thread_local! {
    static LOGGER: RefCell<Option<(Function, Level)>> = const { RefCell::new(None) };
}
static SUBSCRIBER: Once = Once::new();

fn level_from(level: &str) -> Result<Level, JsValue> {
    match level {
        "error" => Ok(Level::ERROR),
        "warn" => Ok(Level::WARN),
        "info" => Ok(Level::INFO),
        "debug" => Ok(Level::DEBUG),
        "trace" => Ok(Level::TRACE),
        other => Err(js_error("internal", format!("unknown log level {other:?}"))),
    }
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

/// Sends log lines up to `maxLevel` to `logger(level, target, message)`, replacing any
/// previous logger. iroh and QUIC internals are capped at `info` (`warn` unless
/// `maxLevel` is `debug` or `trace`). Lines carry their context (`session=… role=…
/// conn=…`) and never an IP address.
#[wasm_bindgen(js_name = setLogger)]
pub fn set_logger(
    #[wasm_bindgen(unchecked_param_type = "IrohLogger")] logger: Function,
    #[wasm_bindgen(js_name = maxLevel, unchecked_param_type = "IrohLogLevel")] max_level: String,
) -> Result<(), JsValue> {
    let max_level = level_from(&max_level)?;
    LOGGER.with(|installed| *installed.borrow_mut() = Some((logger, max_level)));
    install_subscriber();
    tracing::callsite::rebuild_interest_cache();
    Ok(())
}

/// Installs the library's subscriber, once. Sessions need it even without a logger: it
/// notices when another holder of a link's key takes this end's place on the relay.
fn install_subscriber() {
    SUBSCRIBER.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::registry()
                .with(DiagnosticsLayer)
                .with(JsLogLayer),
        );
    });
}

fn logger_enabled(metadata: &Metadata<'_>) -> bool {
    LOGGER.with(|installed| {
        installed.borrow().as_ref().is_some_and(|(_, max_level)| {
            host_log_enabled(metadata.target(), *metadata.level(), *max_level)
        })
    })
}

struct JsLogLayer;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for JsLogLayer {
    fn enabled(&self, metadata: &Metadata<'_>, _: Context<'_, S>) -> bool {
        logger_enabled(metadata) || needed_for_diagnostics(metadata)
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if !logger_enabled(metadata) {
            return;
        }
        let logger = LOGGER.with(|installed| {
            installed
                .borrow()
                .as_ref()
                .map(|(logger, _)| logger.clone())
        });
        if let Some(logger) = logger {
            // A throwing logger must not break the transport.
            let _ = logger.call3(
                &JsValue::NULL,
                &level_name(*metadata.level()).into(),
                &metadata.target().into(),
                &format_event_with_context(event, &ctx).into(),
            );
        }
    }
}
