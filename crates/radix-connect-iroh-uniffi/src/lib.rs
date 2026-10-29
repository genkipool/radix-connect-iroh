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

impl From<core::SessionEvent> for IrohSessionEvent {
    fn from(event: core::SessionEvent) -> Self {
        match event {
            core::SessionEvent::StateChanged(state) => Self::StateChanged {
                state: state.into(),
            },
            core::SessionEvent::Message(message) => Self::Message { message },
        }
    }
}

/// Settings of a session. Both ends of a link must use the same relay.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IrohSessionConfig {
    /// Relay server, e.g. `https://relay.example.com`.
    pub relay_url: String,
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
        Ok(core::SessionConfig::new(&config.relay_url)?
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
        self.session.next_event().await.map(Into::into)
    }

    /// Reports a change of the device's network (call from connectivity callbacks).
    pub async fn network_changed(&self) {
        let session = self.session.clone();
        // Best effort: if the runtime is gone there is nothing to re-check.
        let _ = on_runtime(async move { session.network_changed().await }).await;
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

/// The relay used when none is configured (n0's public EU relay, for development).
#[uniffi::export]
pub fn iroh_default_relay_url() -> String {
    core::DEFAULT_RELAY_URL.to_owned()
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
        assert_eq!(iroh_validate_relay_url(iroh_default_relay_url()), None);
        assert!(iroh_validate_relay_url("ftp://example.com".to_owned()).is_some());
    }

    #[test]
    fn config_defaults_and_conversion() {
        let config = IrohSessionConfig {
            relay_url: "https://relay.example.com".to_owned(),
            ack_timeout_ms: 1500,
            max_message_size: 1024,
        };
        assert!(core::SessionConfig::try_from(config).is_ok());
        let invalid = IrohSessionConfig {
            relay_url: "nope".to_owned(),
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
                relay_url: "https://relay.invalid".to_owned(),
                ack_timeout_ms: 1000,
                max_message_size: 1024,
            },
        ))
        .unwrap();
        assert_eq!(session.state(), IrohConnectionState::Disconnected);
        assert_eq!(
            n0_future::future::block_on(session.send("{}".to_owned())),
            Err(IrohError::NotConnected)
        );
        n0_future::future::block_on(session.shutdown());
        assert_eq!(n0_future::future::block_on(session.next_event()), None);
    }
}
