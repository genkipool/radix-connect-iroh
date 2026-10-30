use std::time::Duration;

use iroh::RelayUrl;

use crate::Error;

/// Which relay servers a session uses. Both ends of a link must use the same choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relays {
    /// n0's public relays (North America east and west, Europe, Asia-Pacific). Each end
    /// connects to its closest one and moves to another if it fails; the Connector
    /// Extension publishes which one it uses — the relay URL only, never an IP
    /// address — through n0's address lookup (pkarr/DNS), where the wallet finds it.
    /// Nothing to host or configure. The default.
    Public,
    /// One relay both ends are configured with, e.g. a self-hosted `iroh-relay`. Nothing
    /// is published anywhere.
    Custom(RelayUrl),
}

/// The URLs of n0's public relays used by [`Relays::Public`], for display.
pub fn public_relay_urls() -> Vec<RelayUrl> {
    iroh::endpoint::default_relay_mode().relay_map().urls()
}

/// How long a sender waits for the peer to confirm a message. Same value as the
/// WebRTC transport's `receiveMessageConfirmation` timeout.
pub const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest message accepted from the peer. Radix transactions are capped at 1 MiB on
/// ledger; a wallet interaction carrying one (plus blobs, hex encoded in JSON) stays
/// well under this bound, while a misbehaving peer cannot make us buffer more.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 8 * 1024 * 1024;

/// Upper bound for the time an incoming message may take to arrive completely once
/// the peer opened its stream. It keeps a stalled stream from blocking the link.
const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// First and maximum delay between two dial attempts of the wallet.
const DEFAULT_MIN_RECONNECT_DELAY: Duration = Duration::from_millis(500);
const DEFAULT_MAX_RECONNECT_DELAY: Duration = Duration::from_secs(15);

/// How long a single dial attempt may take, including the QUIC handshake.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Settings of a [`Session`](crate::Session). Both ends of a link must use the same
/// [`Relays`].
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub(crate) relays: Relays,
    pub(crate) ack_timeout: Duration,
    pub(crate) max_message_size: usize,
    pub(crate) receive_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) min_reconnect_delay: Duration,
    pub(crate) max_reconnect_delay: Duration,
    /// Tests run a relay with a self-signed certificate.
    #[cfg(test)]
    pub(crate) insecure_skip_relay_cert_verify: bool,
    /// Tests use it to reproduce the browser, where only the relay is reachable.
    #[cfg(test)]
    pub(crate) relay_only: bool,
    /// Tests run [`Relays::Public`] against a local relay and pkarr server.
    #[cfg(test)]
    pub(crate) test_public_infrastructure: Option<TestPublicInfrastructure>,
}

/// Local stand-ins for n0's public relays and address lookup (its test pkarr server
/// only accepts publishing, so lookups go through its DNS server).
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct TestPublicInfrastructure {
    pub(crate) relay_url: RelayUrl,
    pub(crate) lookup: std::sync::Arc<iroh::test_utils::DnsPkarrServer>,
}

impl Default for SessionConfig {
    /// [`SessionConfig::public`].
    fn default() -> Self {
        Self::public()
    }
}

impl SessionConfig {
    /// Default settings with n0's public relays ([`Relays::Public`]).
    pub fn public() -> Self {
        Self::with_relays(Relays::Public)
    }

    /// Default settings using the single relay server at `relay_url`
    /// ([`Relays::Custom`]).
    ///
    /// The URL must be an absolute `https://` URL without credentials. Plain `http://`
    /// is accepted only for loopback, private and link-local hosts (a development relay
    /// on this machine or the local network).
    pub fn new(relay_url: &str) -> Result<Self, Error> {
        Ok(Self::with_relays(Relays::Custom(parse_relay_url(
            relay_url,
        )?)))
    }

    /// [`SessionConfig::new`] for `Some(url)`, [`SessionConfig::public`] for `None`.
    pub fn for_relay(relay_url: Option<&str>) -> Result<Self, Error> {
        relay_url.map_or_else(|| Ok(Self::public()), Self::new)
    }

    fn with_relays(relays: Relays) -> Self {
        Self {
            relays,
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            receive_timeout: DEFAULT_RECEIVE_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            min_reconnect_delay: DEFAULT_MIN_RECONNECT_DELAY,
            max_reconnect_delay: DEFAULT_MAX_RECONNECT_DELAY,
            #[cfg(test)]
            insecure_skip_relay_cert_verify: false,
            #[cfg(test)]
            relay_only: false,
            #[cfg(test)]
            test_public_infrastructure: None,
        }
    }

    /// Overrides how long [`Session::send`](crate::Session::send) waits for the peer
    /// to confirm a message.
    pub fn with_ack_timeout(mut self, timeout: Duration) -> Self {
        self.ack_timeout = timeout;
        self
    }

    /// Overrides the largest message this side sends or accepts.
    pub fn with_max_message_size(mut self, bytes: usize) -> Self {
        self.max_message_size = bytes;
        self
    }

    /// The relays this session uses.
    pub fn relays(&self) -> &Relays {
        &self.relays
    }
}

fn parse_relay_url(input: &str) -> Result<RelayUrl, Error> {
    let invalid = |reason: &str| Error::InvalidRelayUrl(reason.to_owned());
    let url: RelayUrl = input
        .trim()
        .parse()
        .map_err(|_| invalid("not an absolute URL"))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(invalid("the scheme must be https or http"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid("the URL has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("the URL must not contain credentials"));
    }
    if url.scheme() == "http" && !url.host().is_some_and(|host| is_local(&host)) {
        return Err(invalid(
            "plain http is only allowed for relays on this machine or the local network",
        ));
    }
    Ok(url)
}

/// Loopback, private and link-local addresses, and `localhost`.
fn is_local(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.');
            domain.eq_ignore_ascii_case("localhost")
                || domain.to_ascii_lowercase().ends_with(".localhost")
        }
        url::Host::Ipv4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        url::Host::Ipv6(ip) => {
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_relays_are_the_default() {
        assert_eq!(SessionConfig::default().relays(), &Relays::Public);
        assert_eq!(
            SessionConfig::for_relay(None).unwrap().relays(),
            &Relays::Public
        );
        assert!(matches!(
            SessionConfig::for_relay(Some("https://relay.example.com"))
                .unwrap()
                .relays(),
            Relays::Custom(_)
        ));
        assert!(SessionConfig::for_relay(Some("ftp://relay.example.com")).is_err());
    }

    #[test]
    fn the_public_relays_cover_several_regions() {
        let urls = public_relay_urls();
        assert!(urls.len() >= 3, "{urls:?}");
        assert!(urls.iter().all(|url| url.scheme() == "https"));
    }

    #[test]
    fn accepts_https_and_local_http_relays() {
        assert!(SessionConfig::new("https://relay.example.com").is_ok());
        assert!(SessionConfig::new("http://192.168.1.20:3340").is_ok());
        assert!(SessionConfig::new("http://localhost:3340").is_ok());
        assert!(SessionConfig::new("http://127.0.0.1:3340").is_ok());
        assert!(SessionConfig::new("http://[::1]:3340").is_ok());
        assert!(SessionConfig::new("http://10.0.0.7:3340").is_ok());
        assert!(SessionConfig::new("  https://relay.example.com/  ").is_ok());
    }

    #[test]
    fn rejects_invalid_relay_urls() {
        for input in [
            "",
            "relay.example.com",
            "wss://relay.example.com",
            "ftp://relay.example.com",
            "https://user:secret@relay.example.com",
            "https://user@relay.example.com",
            "file:///etc/passwd",
            "http://relay.example.com",
            "http://8.8.8.8:3340",
            "http://[2001:db8::1]:3340",
        ] {
            assert!(
                matches!(SessionConfig::new(input), Err(Error::InvalidRelayUrl(_))),
                "{input} should be rejected"
            );
        }
    }
}
