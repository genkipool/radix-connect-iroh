use std::time::Duration;

use iroh::RelayUrl;

use crate::Error;

/// Relay used when the host application has no relay configured: n0's public EU relay.
///
/// Public n0 relays are meant for development and moderate use. A production
/// deployment should run its own `iroh-relay` (see the README), just as Radix runs its
/// own WebRTC signaling and TURN servers, and configure it on both sides of the link.
pub const DEFAULT_RELAY_URL: &str = "https://euc1-1.relay.n0.iroh.link./";

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
/// relay server.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub(crate) relay_url: RelayUrl,
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
}

impl SessionConfig {
    /// Default settings using the relay server at `relay_url`.
    ///
    /// The URL must be an absolute `https://` URL without credentials. Plain `http://`
    /// is accepted only for loopback, private and link-local hosts (a development relay
    /// on this machine or the local network).
    pub fn new(relay_url: &str) -> Result<Self, Error> {
        Ok(Self {
            relay_url: parse_relay_url(relay_url)?,
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
        })
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

    /// The relay server this session uses.
    pub fn relay_url(&self) -> &RelayUrl {
        &self.relay_url
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
    fn default_relay_url_is_valid() {
        assert!(SessionConfig::new(DEFAULT_RELAY_URL).is_ok());
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
