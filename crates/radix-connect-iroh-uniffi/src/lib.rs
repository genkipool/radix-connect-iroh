//! uniffi bindings of [`radix_connect_iroh`] for the Radix Wallet (Kotlin on Android,
//! Swift on iOS). See `docs/BINDINGS.md` for the resulting foreign API.
//!
//! The foreign side drives the futures (Kotlin coroutines), but iroh needs a tokio
//! runtime for its own tasks and timers, so every call that touches the network runs
//! on a private multi-threaded runtime owned by this library.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use n0_future::task::AbortOnDropHandle;
use radix_connect_iroh as core;
use zeroize::Zeroize;

#[cfg(target_os = "android")]
mod android;
mod log;

pub use log::{IrohLogLevel, IrohLogSink, iroh_install_log_sink};

uniffi::setup_scaffolding!();

/// Worker threads of the runtime. Two links' worth of QUIC traffic is light.
const RUNTIME_WORKER_THREADS: usize = 2;

static RUNTIME: LazyLock<Result<tokio::runtime::Runtime, String>> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(RUNTIME_WORKER_THREADS)
        .thread_name("radix-connect-iroh")
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
});

fn runtime() -> Result<&'static tokio::runtime::Runtime, IrohError> {
    RUNTIME.as_ref().map_err(|reason| IrohError::Internal {
        reason: format!("could not start the async runtime: {reason}"),
    })
}

/// Runs `future` on the library runtime. Dropping the returned future (the foreign
/// caller was cancelled) aborts the work.
async fn on_runtime<F>(future: F) -> Result<F::Output, IrohError>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let handle = AbortOnDropHandle::new(runtime()?.spawn(future));
    handle.await.map_err(|error| IrohError::Internal {
        reason: error.to_string(),
    })
}

/// Which end of a link a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum IrohRole {
    /// The Radix Wallet: dials the Connector Extension.
    Wallet,
    /// The Radix Connector Extension: waits for the wallet.
    Connector,
}

impl From<IrohRole> for core::Role {
    fn from(role: IrohRole) -> Self {
        match role {
            IrohRole::Wallet => Self::Wallet,
            IrohRole::Connector => Self::Connector,
        }
    }
}

/// State of the connection to the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum IrohConnectionState {
    /// The wallet is dialing (and keeps retrying).
    Connecting,
    /// Messages can be exchanged.
    Connected,
    /// No connection.
    Disconnected,
}

impl From<core::ConnectionState> for IrohConnectionState {
    fn from(state: core::ConnectionState) -> Self {
        match state {
            core::ConnectionState::Connecting => Self::Connecting,
            core::ConnectionState::Connected => Self::Connected,
            core::ConnectionState::Disconnected => Self::Disconnected,
        }
    }
}

/// Something that happened on a session.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum IrohSessionEvent {
    /// The connection state changed.
    StateChanged {
        /// The new state.
        state: IrohConnectionState,
    },
    /// A message (UTF-8 JSON) arrived from the peer. Taking it from `next_event`
    /// confirmed it to the peer.
    Message {
        /// The message.
        message: String,
    },
}

impl IrohSessionEvent {
    /// The event for the host, or `None` for one only a connector hears (a request
    /// delivered again, the wallet's presence): this binding runs the wallet's end.
    fn from_core(event: core::SessionEvent) -> Option<Self> {
        match event {
            core::SessionEvent::StateChanged(state) => Some(Self::StateChanged {
                state: state.into(),
            }),
            core::SessionEvent::Message(message) => Some(Self::Message { message }),
            core::SessionEvent::RequestRedelivered(_) | core::SessionEvent::PeerPresence { .. } => {
                None
            }
        }
    }
}

/// How the connection to the peer currently travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum IrohPathKind {
    /// Directly between the two devices.
    Direct,
    /// Through the relay server.
    Relay,
}

/// A snapshot of a session's connectivity for logs and diagnostics screens. It holds
/// no secrets (endpoint ids are public keys; errors never include message contents).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IrohDiagnostics {
    /// Which end of the link this session is.
    pub role: IrohRole,
    /// Hex id of this end.
    pub local_endpoint_id: String,
    /// Hex id of the peer.
    pub peer_endpoint_id: String,
    /// The relay this end uses: the custom one, or the public relay it connected to
    /// (`None` while it has none yet).
    pub relay_url: Option<String>,
    /// Whether this end uses n0's public relays.
    pub public_relays: bool,
    /// Whether this end is connected to the relay (without it the peer cannot reach it).
    pub relay_connected: bool,
    /// The last error talking to the relay.
    pub relay_error: Option<String>,
    /// State of the connection to the peer.
    pub state: IrohConnectionState,
    /// How the connection travels, while connected.
    pub path: Option<IrohPathKind>,
    /// Round-trip time of the selected path, while connected.
    pub rtt_ms: Option<u64>,
    /// Failed attempts to reach the peer since the last connection.
    pub failed_attempts: u32,
    /// The last thing that went wrong.
    pub last_error: Option<String>,
    /// How long the current connection has been up.
    pub connected_for_ms: Option<u64>,
    /// All of the above in one line, ready for a log.
    pub summary: String,
    /// Another device or app instance with this link took this end's place on the
    /// relay: the peer cannot reach this end until it leaves or this end reconnects.
    pub key_collision: bool,
}

impl From<core::Diagnostics> for IrohDiagnostics {
    fn from(diagnostics: core::Diagnostics) -> Self {
        let millis =
            |duration: std::time::Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self {
            summary: diagnostics.to_string(),
            role: match diagnostics.role {
                core::Role::Wallet => IrohRole::Wallet,
                core::Role::Connector => IrohRole::Connector,
            },
            local_endpoint_id: diagnostics.local_id.to_string(),
            peer_endpoint_id: diagnostics.peer_id.to_string(),
            relay_url: diagnostics.relay_url.map(|url| url.to_string()),
            public_relays: diagnostics.public_relays,
            relay_connected: diagnostics.relay_connected,
            relay_error: diagnostics.relay_error,
            state: diagnostics.state.into(),
            path: diagnostics.path.map(|path| match path {
                core::PathKind::Direct => IrohPathKind::Direct,
                core::PathKind::Relay => IrohPathKind::Relay,
            }),
            rtt_ms: diagnostics.rtt.map(millis),
            failed_attempts: diagnostics.failed_attempts,
            last_error: diagnostics.last_error,
            connected_for_ms: diagnostics.connected_for.map(millis),
            key_collision: diagnostics.key_collision,
        }
    }
}

/// Settings of a session. Both ends of a link must use the same relay.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IrohSessionConfig {
    /// A custom relay server, e.g. `https://relay.example.com`; `None` (the default)
    /// uses n0's public relays, closest one, found through address lookup. Both ends
    /// of a link must make the same choice.
    #[uniffi(default = None)]
    pub relay_url: Option<String>,
    /// How long `send` waits for the peer to confirm a message.
    #[uniffi(default = 10000)]
    pub ack_timeout_ms: u64,
    /// Largest message sent or accepted, in bytes.
    #[uniffi(default = 8388608)]
    pub max_message_size: u64,
}

impl TryFrom<IrohSessionConfig> for core::SessionConfig {
    type Error = IrohError;

    fn try_from(config: IrohSessionConfig) -> Result<Self, IrohError> {
        let max_message_size =
            usize::try_from(config.max_message_size).map_err(|_| IrohError::Internal {
                reason: "max_message_size does not fit this platform".to_owned(),
            })?;
        Ok(core::SessionConfig::for_relay(config.relay_url.as_deref())?
            .with_ack_timeout(Duration::from_millis(config.ack_timeout_ms))
            .with_max_message_size(max_message_size))
    }
}

/// Errors of this library. Kotlin sees them as `IrohException` subclasses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum IrohError {
    /// The connection password is not 32 bytes.
    #[error("the connection password must be 32 bytes")]
    InvalidPassword,
    /// The relay URL is not usable.
    #[error("invalid relay URL: {reason}")]
    InvalidRelayUrl {
        /// Why.
        reason: String,
    },
    /// The local endpoint could not be created.
    #[error("could not start the iroh endpoint: {reason}")]
    Bind {
        /// Why.
        reason: String,
    },
    /// Not connected to the peer; nothing was sent.
    #[error("not connected to the peer")]
    NotConnected,
    /// The peer did not confirm the message in time; it may have received it.
    #[error("the peer did not confirm the message in time")]
    Timeout,
    /// The message is larger than the maximum; nothing was sent.
    #[error("the message is {size} bytes, the maximum is {max}")]
    MessageTooLarge {
        /// Size of the message in bytes.
        size: u64,
        /// Maximum in bytes.
        max: u64,
    },
    /// The peer refused the message.
    #[error("the peer rejected the message")]
    Rejected,
    /// The connection broke while sending.
    #[error("the connection was lost: {reason}")]
    ConnectionLost {
        /// Why.
        reason: String,
    },
    /// The session has been shut down.
    #[error("the session is shut down")]
    Closed,
    /// Unexpected internal failure.
    #[error("internal error: {reason}")]
    Internal {
        /// Why.
        reason: String,
    },
}

impl From<core::Error> for IrohError {
    fn from(error: core::Error) -> Self {
        match error {
            core::Error::InvalidPassword => Self::InvalidPassword,
            core::Error::InvalidRelayUrl(reason) => Self::InvalidRelayUrl { reason },
            core::Error::Bind(reason) => Self::Bind { reason },
            other => Self::Internal {
                reason: other.to_string(),
            },
        }
    }
}

impl From<core::SendError> for IrohError {
    fn from(error: core::SendError) -> Self {
        match error {
            core::SendError::NotConnected => Self::NotConnected,
            core::SendError::Timeout => Self::Timeout,
            core::SendError::MessageTooLarge { size, max } => Self::MessageTooLarge {
                size: size as u64,
                max: max as u64,
            },
            core::SendError::Rejected => Self::Rejected,
            core::SendError::ConnectionLost(reason) => Self::ConnectionLost { reason },
            core::SendError::Closed => Self::Closed,
            other => Self::Internal {
                reason: other.to_string(),
            },
        }
    }
}

/// Takes ownership of the foreign copy of the password and wipes it once parsed.
fn password_from(mut bytes: Vec<u8>) -> Result<core::ConnectionPassword, IrohError> {
    let password = core::ConnectionPassword::from_slice(&bytes);
    bytes.zeroize();
    Ok(password?)
}

/// One end of a Radix Connect link over iroh. See `radix_connect_iroh::Session`.
#[derive(Debug, uniffi::Object)]
pub struct IrohSession {
    session: Arc<core::Session>,
}

#[uniffi::export]
impl IrohSession {
    /// Starts the `role` end of the link secured by `password` (32 bytes).
    #[uniffi::constructor]
    pub async fn start(
        password: Vec<u8>,
        role: IrohRole,
        config: IrohSessionConfig,
    ) -> Result<Arc<Self>, IrohError> {
        let password = password_from(password)?;
        let config = core::SessionConfig::try_from(config)?;
        log::install_subscriber();
        let session =
            on_runtime(async move { core::Session::start(&password, role.into(), config).await })
                .await??;
        Ok(Arc::new(Self {
            session: Arc::new(session),
        }))
    }

    /// Hex id of this end of the link.
    pub fn local_endpoint_id(&self) -> String {
        self.session.local_id().to_string()
    }

    /// Hex id of the other end: the only endpoint this session talks to.
    pub fn peer_endpoint_id(&self) -> String {
        self.session.peer_id().to_string()
    }

    /// Current connection state.
    pub fn state(&self) -> IrohConnectionState {
        self.session.state().into()
    }

    /// A snapshot of the connectivity, for logs and diagnostics screens. Cheap.
    pub fn diagnostics(&self) -> IrohDiagnostics {
        self.session.diagnostics().into()
    }

    /// Sends one message and waits until the peer confirms it. Fails at once with
    /// `NotConnected` when there is no connection.
    pub async fn send(&self, message: String) -> Result<(), IrohError> {
        let session = self.session.clone();
        on_runtime(async move { session.send(&message).await }).await??;
        Ok(())
    }

    /// Waits for the next event; `None` once the session is shut down. Taking a
    /// message confirms it to the peer: keep a loop calling this for the whole life
    /// of the session.
    ///
    /// Polled directly by the caller rather than on the runtime: receiving is
    /// cancel-safe, so a cancelled call never loses an event.
    pub async fn next_event(&self) -> Option<IrohSessionEvent> {
        loop {
            if let Some(event) = IrohSessionEvent::from_core(self.session.next_event().await?) {
                return Some(event);
            }
        }
    }

    /// Reports a change of the device's network, or the app returning to the
    /// foreground (call from connectivity callbacks and on resume): a waiting wallet
    /// dials at once, and the current connection is checked, dropped within seconds if
    /// the peer no longer answers.
    pub async fn network_changed(&self) {
        let session = self.session.clone();
        // Best effort: if the runtime is gone there is nothing to re-check.
        let _ = on_runtime(async move { session.network_changed().await }).await;
    }

    /// Wallet: tells the connector whether the app is in the background — call when it goes
    /// there and when it comes back. A connector racing several wallets for one request then
    /// sends it to the one the person opens. Best effort, and nothing changes for a connector
    /// that predates it.
    pub fn set_in_background(&self, in_background: bool) {
        self.session.set_in_background(in_background);
    }

    /// Closes the connection, telling the peer, and the endpoint. Idempotent.
    ///
    /// The shutdown runs to completion even if the caller is cancelled.
    pub async fn shutdown(&self) {
        let session = self.session.clone();
        let Ok(runtime) = runtime() else {
            return;
        };
        let _ = runtime.spawn(async move { session.close().await }).await;
    }
}

impl Drop for IrohSession {
    /// Freed without `shutdown()` (or with calls still running): close gracefully on
    /// the runtime, which also keeps iroh's resources from being dropped on a foreign
    /// thread outside of it. A no-op after `shutdown()`.
    fn drop(&mut self) {
        if let Ok(runtime) = runtime() {
            let session = self.session.clone();
            runtime.spawn(async move { session.close().await });
        }
    }
}

/// The URLs of n0's public relays, used when no custom relay is configured (for display).
#[uniffi::export]
pub fn iroh_public_relay_urls() -> Vec<String> {
    core::public_relay_urls()
        .into_iter()
        .map(|url| url.to_string())
        .collect()
}

/// Hex endpoint id of the `role` end of the link secured by `password`.
#[uniffi::export]
pub fn iroh_endpoint_id(password: Vec<u8>, role: IrohRole) -> Result<String, IrohError> {
    Ok(password_from(password)?
        .endpoint_id(role.into())
        .to_string())
}

/// Checks a relay URL the user typed, without starting anything. Returns why it is
/// not usable, or `None` when it is fine.
#[uniffi::export]
pub fn iroh_validate_relay_url(relay_url: String) -> Option<String> {
    match core::SessionConfig::new(&relay_url) {
        Ok(_) => None,
        Err(error) => Some(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_ids_match_the_core_test_vectors() {
        let password = [0xca, 0xfe].repeat(16);
        assert_eq!(
            iroh_endpoint_id(password.clone(), IrohRole::Wallet).unwrap(),
            "4d99dc649e722e88092356956cb78d87dd24bae70b8110f492a4e843fe91f178"
        );
        assert_eq!(
            iroh_endpoint_id(password, IrohRole::Connector).unwrap(),
            "efcc89cfbf2350783bcc70dd2908a034d765fa70abab6d00f62e236561d43aa8"
        );
    }

    #[test]
    fn rejects_short_passwords() {
        assert_eq!(
            iroh_endpoint_id(vec![1; 16], IrohRole::Wallet),
            Err(IrohError::InvalidPassword)
        );
    }

    #[test]
    fn validates_relay_urls() {
        for url in iroh_public_relay_urls() {
            assert_eq!(iroh_validate_relay_url(url), None);
        }
        assert!(iroh_validate_relay_url("ftp://example.com".to_owned()).is_some());
    }

    #[test]
    fn config_defaults_and_conversion() {
        let config = IrohSessionConfig {
            relay_url: Some("https://relay.example.com".to_owned()),
            ack_timeout_ms: 1500,
            max_message_size: 1024,
        };
        assert!(core::SessionConfig::try_from(config).is_ok());
        let invalid = IrohSessionConfig {
            relay_url: Some("nope".to_owned()),
            ack_timeout_ms: 1500,
            max_message_size: 1024,
        };
        assert!(matches!(
            core::SessionConfig::try_from(invalid),
            Err(IrohError::InvalidRelayUrl { .. })
        ));
    }

    #[test]
    fn a_session_starts_and_shuts_down() {
        let session = n0_future::future::block_on(IrohSession::start(
            vec![9; 32],
            IrohRole::Connector,
            IrohSessionConfig {
                // Never resolves (RFC 2606): the test stays offline.
                relay_url: Some("https://relay.invalid".to_owned()),
                ack_timeout_ms: 1000,
                max_message_size: 1024,
            },
        ))
        .unwrap();
        assert_eq!(session.state(), IrohConnectionState::Disconnected);
        let diagnostics = session.diagnostics();
        assert_eq!(diagnostics.role, IrohRole::Connector);
        assert_eq!(diagnostics.state, IrohConnectionState::Disconnected);
        assert_eq!(
            diagnostics.relay_url.as_deref(),
            Some("https://relay.invalid/")
        );
        assert!(!diagnostics.public_relays);
        assert!(!diagnostics.key_collision);
        assert!(diagnostics.summary.starts_with("connector "));
        assert_eq!(
            n0_future::future::block_on(session.send("{}".to_owned())),
            Err(IrohError::NotConnected)
        );
        n0_future::future::block_on(session.shutdown());
        assert_eq!(n0_future::future::block_on(session.next_event()), None);
    }
}
