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
use radix_connect_iroh::logging::{format_event, host_log_enabled};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &'static str = r#"
export type IrohRole = 'wallet' | 'connector'
export type IrohConnectionState = 'connecting' | 'connected' | 'disconnected'
export type IrohSessionEvent =
  | { type: 'stateChanged'; state: IrohConnectionState }
  | { type: 'message'; message: string }
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
    let (kind, key, value) = match event {
        core::SessionEvent::StateChanged(state) => {
            ("stateChanged", "state", state_name(state).to_owned())
        }
        core::SessionEvent::Message(message) => ("message", "message", message),
    };
    // Setting properties on a fresh plain object cannot fail.
    let _ = Reflect::set(&object, &"type".into(), &kind.into());
    let _ = Reflect::set(&object, &key.into(), &value.into());
    object.into()
}

/// Takes ownership of the JS copy of the password and wipes it once parsed.
fn password_from(mut bytes: Vec<u8>) -> Result<core::ConnectionPassword, JsValue> {
    let password = core::ConnectionPassword::from_slice(&bytes);
    bytes.fill(0);
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
    /// Starts the `role` end of the link secured by `password` (32 bytes), using the
    /// relay at `relayUrl`. Connecting happens in the background (see `nextEvent`).
    pub async fn start(
        password: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "IrohRole")] role: String,
        #[wasm_bindgen(js_name = relayUrl)] relay_url: String,
        #[wasm_bindgen(js_name = ackTimeoutMs)] ack_timeout_ms: Option<u32>,
    ) -> Result<IrohSession, JsValue> {
        let password = password_from(password)?;
        let role = role_from(&role)?;
        let mut config = core::SessionConfig::new(&relay_url).map_err(error_from)?;
        if let Some(ack_timeout_ms) = ack_timeout_ms {
            config = config.with_ack_timeout(Duration::from_millis(ack_timeout_ms.into()));
        }
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

/// The relay used when none is configured (n0's public EU relay, for development).
#[wasm_bindgen(js_name = defaultRelayUrl)]
pub fn default_relay_url() -> String {
    core::DEFAULT_RELAY_URL.to_owned()
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
/// previous logger. iroh and QUIC internals are capped at `info`.
#[wasm_bindgen(js_name = setLogger)]
pub fn set_logger(
    #[wasm_bindgen(unchecked_param_type = "IrohLogger")] logger: Function,
    #[wasm_bindgen(js_name = maxLevel, unchecked_param_type = "IrohLogLevel")] max_level: String,
) -> Result<(), JsValue> {
    let max_level = level_from(&max_level)?;
    LOGGER.with(|installed| *installed.borrow_mut() = Some((logger, max_level)));
    SUBSCRIBER.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(JsLogLayer),
        );
    });
    tracing::callsite::rebuild_interest_cache();
    Ok(())
}

fn logger_enabled(metadata: &Metadata<'_>) -> bool {
    LOGGER.with(|installed| {
        installed.borrow().as_ref().is_some_and(|(_, max_level)| {
            host_log_enabled(metadata.target(), *metadata.level(), *max_level)
        })
    })
}

struct JsLogLayer;

impl<S: Subscriber> Layer<S> for JsLogLayer {
    fn enabled(&self, metadata: &Metadata<'_>, _: Context<'_, S>) -> bool {
        logger_enabled(metadata)
    }

    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
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
                &format_event(event).into(),
            );
        }
    }
}
