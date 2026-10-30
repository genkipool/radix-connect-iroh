//! Connectivity snapshots for logs and diagnostics screens, and the vocabulary the logs
//! use to explain what happened.

use std::fmt;
use std::time::Duration;

use iroh::endpoint::{
    ConnectError, ConnectWithOptsError, ConnectingError, Connection, ConnectionError,
    TransportErrorCode,
};
use iroh::{EndpointId, RelayUrl};
use n0_future::time::Instant;

use crate::logging::Redacted;
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

impl PathKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// A snapshot of a session's connectivity. It contains no secrets: endpoint ids are
/// public keys, and errors never include message contents or IP addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostics {
    /// Which end of the link this session is.
    pub role: Role,
    /// This end's endpoint id.
    pub local_id: EndpointId,
    /// The peer's endpoint id.
    pub peer_id: EndpointId,
    /// The relay this end uses: the configured one, or the public relay it connected
    /// to (`None` while it has none yet).
    pub relay_url: Option<RelayUrl>,
    /// Whether this end uses n0's public relays (rather than a custom one).
    pub public_relays: bool,
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
    /// Another holder of this link's key (another device, or a second app instance,
    /// with the same link) connected to the relay after this end: the relay delivers to
    /// the newest holder only, so the peer cannot reach this end through it until the
    /// other one leaves or this end reconnects to the relay. Only the end that was
    /// displaced learns it, and only when both use the same relay.
    pub key_collision: bool,
}

impl fmt::Display for Diagnostics {
    /// One line for logs, e.g.
    /// `wallet 4d99dc649e → efcc89cfbf state=connected path=relay rtt=42ms relay=https://… (connected)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.state {
            ConnectionState::Connecting => "connecting",
            ConnectionState::Connected => "connected",
            ConnectionState::Disconnected => "disconnected",
        };
        write!(
            f,
            "{} {} → {} state={state}",
            self.role.as_str(),
            self.local_id.fmt_short(),
            self.peer_id.fmt_short()
        )?;
        if let Some(path) = self.path {
            write!(f, " path={}", path.as_str())?;
        }
        if let Some(rtt) = self.rtt {
            write!(f, " rtt={}ms", rtt.as_millis())?;
        }
        let relay_state = if self.relay_connected {
            "connected"
        } else {
            "NOT connected"
        };
        let kind = if self.public_relays { ", public" } else { "" };
        match &self.relay_url {
            Some(url) => write!(f, " relay={} ({relay_state}{kind})", Redacted(url))?,
            None => write!(f, " relay=none yet ({relay_state}{kind})")?,
        }
        if let Some(error) = &self.relay_error {
            write!(f, " relay_error=\"{error}\"")?;
        }
        if self.key_collision {
            f.write_str(
                " KEY COLLISION: another device or app instance with this link took over the relay",
            )?;
        }
        if self.failed_attempts > 0 {
            write!(f, " failed_attempts={}", self.failed_attempts)?;
        }
        if let Some(error) = &self.last_error {
            write!(f, " last_error=\"{error}\"")?;
        }
        if let Some(connected_for) = self.connected_for {
            write!(f, " connected_for={}s", connected_for.as_secs())?;
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
                // Only a wallet hears it: the connector closes the older connection.
                (
                    CloseCode::Replaced,
                    "the connector accepted a newer connection with this link's wallet key",
                ),
                (
                    CloseCode::Unresponsive,
                    "the peer got no answer to a liveness check and dropped the connection",
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
        other => Redacted(other).to_string(),
    }
}

/// TLS alert `no_application_protocol`: the two ends share no ALPN.
const NO_APPLICATION_PROTOCOL: u8 = 120;

/// Why an attempt to establish a connection failed, as a stable word for logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialFailure {
    /// Address lookup found nothing: the connector has not published where it is.
    NoAddress,
    /// No answer in time.
    Timeout,
    /// No answer, and this end is not connected to its relay either.
    RelayUnreachable,
    /// The other end closed the handshake as unauthorized (different password).
    Unauthorized,
    /// The other end does not speak this protocol version.
    AlpnMismatch,
    /// The QUIC/TLS handshake failed otherwise.
    HandshakeFailed,
    /// The local endpoint refused (a bug) or is closing.
    Local,
    /// Anything else.
    Other,
}

impl DialFailure {
    /// Classifies an error of [`Endpoint::connect`](iroh::Endpoint::connect).
    pub(crate) fn of_connect(error: &ConnectError) -> Self {
        match error {
            ConnectError::Connect { source, .. } => match source {
                ConnectWithOptsError::NoAddress { .. } => Self::NoAddress,
                ConnectWithOptsError::LocallyRejected { .. }
                | ConnectWithOptsError::EndpointClosed { .. }
                | ConnectWithOptsError::SelfConnect { .. }
                | ConnectWithOptsError::InvalidAlpn { .. } => Self::Local,
                _ => Self::Other,
            },
            ConnectError::Connecting { source, .. } => Self::of_connecting(source),
            ConnectError::Connection { source, .. } => Self::of_connection(source),
            _ => Self::Other,
        }
    }

    /// Classifies a failed handshake, outgoing or incoming.
    pub(crate) fn of_connecting(error: &ConnectingError) -> Self {
        match error {
            ConnectingError::ConnectionError { source, .. } => Self::of_connection(source),
            ConnectingError::HandshakeFailure { .. } => Self::HandshakeFailed,
            ConnectingError::LocallyRejected { .. } => Self::Local,
            _ => Self::Other,
        }
    }

    /// Classifies a connection error seen during a handshake.
    pub(crate) fn of_connection(error: &ConnectionError) -> Self {
        let no_alpn = TransportErrorCode::crypto(NO_APPLICATION_PROTOCOL);
        match error {
            ConnectionError::ApplicationClosed(close)
                if close.error_code == CloseCode::Unauthorized.into() =>
            {
                Self::Unauthorized
            }
            ConnectionError::ConnectionClosed(close) if close.error_code == no_alpn => {
                Self::AlpnMismatch
            }
            ConnectionError::TransportError(error) if error.code == no_alpn => Self::AlpnMismatch,
            ConnectionError::TimedOut => Self::Timeout,
            ConnectionError::ConnectionClosed(_)
            | ConnectionError::TransportError(_)
            | ConnectionError::VersionMismatch => Self::HandshakeFailed,
            ConnectionError::LocallyClosed => Self::Local,
            _ => Self::Other,
        }
    }

    /// Without its relay this end can reach nothing: say so rather than blame the peer.
    pub(crate) fn given_relay(self, relay_connected: bool) -> Self {
        match self {
            Self::Timeout | Self::NoAddress | Self::Other if !relay_connected => {
                Self::RelayUnreachable
            }
            other => other,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoAddress => "no_address",
            Self::Timeout => "timeout",
            Self::RelayUnreachable => "relay_unreachable",
            Self::Unauthorized => "unauthorized",
            Self::AlpnMismatch => "alpn_mismatch",
            Self::HandshakeFailed => "handshake_failed",
            Self::Local => "local",
            Self::Other => "other",
        }
    }

    /// What it usually means, for the people reading the logs.
    pub(crate) fn hint(self) -> &'static str {
        match self {
            Self::NoAddress => {
                "the connector has not published its address: is it running, with iroh enabled and the public relays?"
            }
            Self::Timeout => "is the connector running, with iroh, on the same relay?",
            Self::RelayUnreachable => {
                "this end is not connected to its relay (yet): no internet, or the relay is down or blocked"
            }
            Self::Unauthorized => {
                "the connector rejected this wallet: the two ends hold different passwords for the link (re-link)"
            }
            Self::AlpnMismatch => {
                "the connector speaks another version of the protocol: update the older side"
            }
            Self::HandshakeFailed => "the QUIC handshake failed",
            Self::Local => "the local endpoint refused or is closing",
            Self::Other => "unexpected error",
        }
    }
}

/// Traffic counters of a connection, for the line that reports its end.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Traffic {
    pub(crate) sent_bytes: u64,
    pub(crate) received_bytes: u64,
    pub(crate) lost_packets: u64,
    /// Times this end could not open a stream because the peer's limit of concurrent
    /// streams was reached.
    pub(crate) blocked_by_peer_stream_limit: u64,
    /// Times the peer could not open a stream because this end's limit was reached.
    pub(crate) peer_blocked_by_stream_limit: u64,
}

impl Traffic {
    pub(crate) fn of(connection: &Connection) -> Self {
        let stats = connection.stats();
        Self {
            sent_bytes: stats.udp_tx.bytes,
            received_bytes: stats.udp_rx.bytes,
            lost_packets: stats.lost_packets,
            blocked_by_peer_stream_limit: stats.frame_tx.streams_blocked_bidi,
            peer_blocked_by_stream_limit: stats.frame_rx.streams_blocked_bidi,
        }
    }
}

/// Milliseconds, for log fields.
pub(crate) fn ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// How long a [`Tally`] counts before it is summarised.
pub(crate) const TALLY_WINDOW: Duration = Duration::from_secs(60);

/// Counts an event that strangers or a faulty relay can repeat at will, so that it is
/// logged in full once a minute and summarised otherwise.
#[derive(Debug, Default)]
pub(crate) struct Tally {
    since: Option<Instant>,
    count: u64,
}

impl Tally {
    /// Counts one occurrence. Returns whether it is the first of its minute (the one
    /// to log in full).
    pub(crate) fn count(&mut self, now: Instant) -> bool {
        let first = self.since.is_none();
        if first {
            self.since = Some(now);
        }
        self.count = self.count.saturating_add(1);
        first
    }

    /// When the current minute ends, if anything was counted in it.
    pub(crate) fn ends_at(&self) -> Option<Instant> {
        self.since.map(|since| since + TALLY_WINDOW)
    }

    /// Closes the minute if it is over: returns how many were counted in it.
    pub(crate) fn take_if_over(&mut self, now: Instant) -> Option<u64> {
        let over = self.ends_at().is_some_and(|end| end <= now);
        over.then(|| {
            self.since = None;
            std::mem::take(&mut self.count)
        })
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
            relay_url: Some("https://relay.example.com".parse().unwrap()),
            public_relays: false,
            relay_connected: true,
            relay_error: None,
            state: ConnectionState::Connected,
            path: Some(PathKind::Relay),
            rtt: Some(Duration::from_millis(42)),
            failed_attempts: 0,
            last_error: None,
            connected_for: Some(Duration::from_secs(5)),
            key_collision: false,
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
        assert!(line.contains("connected_for=5s"), "{line}");
        assert!(!line.contains("last_error"), "{line}");
        assert!(!line.contains("COLLISION"), "{line}");
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
            connected_for: None,
            key_collision: true,
            ..sample()
        }
        .to_string();
        assert!(
            line.contains("(NOT connected) relay_error=\"dns lookup failed\""),
            "{line}"
        );
        assert!(line.contains("KEY COLLISION"), "{line}");
        assert!(
            line.contains("failed_attempts=3 last_error=\"dial: timed out\""),
            "{line}"
        );
    }

    #[test]
    fn the_log_line_has_no_ip_addresses() {
        let line = Diagnostics {
            relay_url: Some("http://192.168.1.20:3340".parse().unwrap()),
            ..sample()
        }
        .to_string();
        assert!(line.contains("relay=http://<ip>:3340/"), "{line}");
    }

    #[test]
    fn dial_failures_blame_the_relay_when_it_is_down() {
        assert_eq!(
            DialFailure::Timeout.given_relay(false),
            DialFailure::RelayUnreachable
        );
        assert_eq!(DialFailure::Timeout.given_relay(true), DialFailure::Timeout);
        assert_eq!(
            DialFailure::Unauthorized.given_relay(false),
            DialFailure::Unauthorized
        );
        let unauthorized = ConnectionError::ApplicationClosed(iroh::endpoint::ApplicationClose {
            error_code: CloseCode::Unauthorized.into(),
            reason: b"unauthorized".to_vec().into(),
        });
        assert_eq!(
            DialFailure::of_connection(&unauthorized),
            DialFailure::Unauthorized
        );
    }

    #[test]
    fn a_tally_reports_once_a_minute() {
        let start = Instant::now();
        let mut tally = Tally::default();
        assert_eq!(tally.ends_at(), None);
        assert!(tally.count(start));
        assert!(!tally.count(start + Duration::from_secs(1)));
        assert_eq!(tally.take_if_over(start + Duration::from_secs(59)), None);
        assert_eq!(tally.take_if_over(start + TALLY_WINDOW), Some(2));
        assert_eq!(tally.ends_at(), None);
        assert!(tally.count(start + Duration::from_secs(61)));
    }
}
