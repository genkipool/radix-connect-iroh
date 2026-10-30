//! Connectivity snapshots for logs and diagnostics screens.

use std::fmt;
use std::time::Duration;

use iroh::endpoint::{Connection, ConnectionError};
use iroh::{EndpointId, RelayUrl};

use crate::protocol::CloseCode;
use crate::{ConnectionState, Role};

/// How the connection to the peer currently travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    /// Directly between the two devices (UDP, after hole punching).
    Direct,
    /// Through the relay server.
    Relay,
}

/// A snapshot of a session's connectivity. It contains no secrets: endpoint ids are
/// public keys, and errors never include message contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostics {
    /// Which end of the link this session is.
    pub role: Role,
    /// This end's endpoint id.
    pub local_id: EndpointId,
    /// The peer's endpoint id.
    pub peer_id: EndpointId,
    /// The relay both ends must use.
    pub relay_url: RelayUrl,
    /// Whether this end is connected to the relay right now (or talks to the peer
    /// through it). While it is not, the peer cannot reach it.
    pub relay_connected: bool,
    /// The last error talking to the relay, if any.
    pub relay_error: Option<String>,
    /// State of the connection to the peer.
    pub state: ConnectionState,
    /// How the connection travels, while connected.
    pub path: Option<PathKind>,
    /// Round-trip time of the selected path, while connected.
    pub rtt: Option<Duration>,
    /// Failed attempts to reach the peer since the last successful connection.
    pub failed_attempts: u32,
    /// The last thing that went wrong (dialing, a handshake, a lost connection, a
    /// failed send...), kept until something else goes wrong.
    pub last_error: Option<String>,
    /// How long the current connection has been up.
    pub connected_for: Option<Duration>,
}

impl fmt::Display for Diagnostics {
    /// One line for logs, e.g.
    /// `wallet 4d99dc649e → efcc89cfbf state=connected path=relay rtt=42ms relay=https://… (connected)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let role = match self.role {
            Role::Wallet => "wallet",
            Role::Connector => "connector",
        };
        let state = match self.state {
            ConnectionState::Connecting => "connecting",
            ConnectionState::Connected => "connected",
            ConnectionState::Disconnected => "disconnected",
        };
        write!(
            f,
            "{role} {} → {} state={state}",
            self.local_id.fmt_short(),
            self.peer_id.fmt_short()
        )?;
        if let Some(path) = self.path {
            let path = match path {
                PathKind::Direct => "direct",
                PathKind::Relay => "relay",
            };
            write!(f, " path={path}")?;
        }
        if let Some(rtt) = self.rtt {
            write!(f, " rtt={}ms", rtt.as_millis())?;
        }
        let relay_state = if self.relay_connected {
            "connected"
        } else {
            "NOT connected"
        };
        write!(f, " relay={} ({relay_state})", self.relay_url)?;
        if let Some(error) = &self.relay_error {
            write!(f, " relay_error=\"{error}\"")?;
        }
        if self.failed_attempts > 0 {
            write!(f, " failed_attempts={}", self.failed_attempts)?;
        }
        if let Some(error) = &self.last_error {
            write!(f, " last_error=\"{error}\"")?;
        }
        Ok(())
    }
}

/// The path the connection currently uses and its round-trip time.
pub(crate) fn selected_path(connection: &Connection) -> (Option<PathKind>, Option<Duration>) {
    let paths = connection.paths();
    match paths.iter().find(|path| path.is_selected()) {
        Some(path) => {
            let kind = if path.is_relay() {
                PathKind::Relay
            } else {
                PathKind::Direct
            };
            (Some(kind), Some(path.rtt()))
        }
        None => (None, None),
    }
}

/// Explains why a connection ended, in the terms of this protocol.
pub(crate) fn describe_connection_end(error: &ConnectionError) -> String {
    match error {
        ConnectionError::ApplicationClosed(close) => {
            let reason = [
                (CloseCode::Normal, "the peer closed the session"),
                (
                    CloseCode::Unauthorized,
                    "the peer rejected this endpoint as unauthorized",
                ),
                (
                    CloseCode::Replaced,
                    "replaced by a newer connection from the peer",
                ),
            ]
            .into_iter()
            .find(|(code, _)| close.error_code == (*code).into())
            .map(|(_, reason)| reason);
            match reason {
                Some(reason) => reason.to_owned(),
                None => format!("closed by the peer with code {}", close.error_code),
            }
        }
        ConnectionError::TimedOut => "the peer stopped answering (idle timeout)".to_owned(),
        ConnectionError::LocallyClosed => "closed locally".to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnectionPassword;

    fn sample() -> Diagnostics {
        let password = ConnectionPassword::from_bytes([3; 32]);
        Diagnostics {
            role: Role::Wallet,
            local_id: password.endpoint_id(Role::Wallet),
            peer_id: password.endpoint_id(Role::Connector),
            relay_url: "https://relay.example.com".parse().unwrap(),
            relay_connected: true,
            relay_error: None,
            state: ConnectionState::Connected,
            path: Some(PathKind::Relay),
            rtt: Some(Duration::from_millis(42)),
            failed_attempts: 0,
            last_error: None,
            connected_for: Some(Duration::from_secs(5)),
        }
    }

    #[test]
    fn the_log_line_summarises_the_snapshot() {
        let line = sample().to_string();
        assert!(line.starts_with("wallet "), "{line}");
        assert!(
            line.contains("state=connected path=relay rtt=42ms"),
            "{line}"
        );
        assert!(
            line.contains("relay=https://relay.example.com/ (connected)"),
            "{line}"
        );
        assert!(!line.contains("last_error"), "{line}");
    }

    #[test]
    fn the_log_line_shows_problems() {
        let line = Diagnostics {
            state: ConnectionState::Connecting,
            path: None,
            rtt: None,
            relay_connected: false,
            relay_error: Some("dns lookup failed".to_owned()),
            failed_attempts: 3,
            last_error: Some("dial: timed out".to_owned()),
            ..sample()
        }
        .to_string();
        assert!(
            line.contains("(NOT connected) relay_error=\"dns lookup failed\""),
            "{line}"
        );
        assert!(
            line.contains("failed_attempts=3 last_error=\"dial: timed out\""),
            "{line}"
        );
    }
}
