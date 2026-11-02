//! What a session remembers of its link between runs: one opaque, versioned string that the
//! host stores with the link and gives back when it starts the link's next session.
//!
//! Hosts never look inside. They read it with [`Session::link_memory`](crate::Session::link_memory)
//! (after a connection, and when they stop a session) and pass it to
//! [`SessionConfig::with_link_memory`](crate::SessionConfig::with_link_memory). What it holds
//! today:
//!
//! - the relay the peer was last seen on: a connector knocks there when it starts;
//! - when the peer was last connected, and since when the link is known: a wallet dials a link
//!   whose connector has not been connected for a long time (or never, since it is known) only
//!   now and then (see `RetryPolicy::dormant`), instead of again and again, and waits for the
//!   connector's knock.
//!
//! Only a relay URL and a time: no secret, no IP address.

use n0_future::time::SystemTime;
use serde_json::{Map, Value, json};

use iroh::RelayUrl;

use crate::Error;
use crate::config::parse_relay_url;

/// The format of the string, written in it as `v`. A string of another version is not
/// understood and is treated as no memory: the session works as for a new link.
const VERSION: u64 = 1;

/// What a session remembers of its link (see the module documentation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LinkMemory {
    /// The relay the peer was last seen on.
    pub(crate) peer_relay: Option<RelayUrl>,
    /// When the peer was last connected, in seconds since the Unix epoch.
    pub(crate) last_connected: Option<u64>,
    /// Since when this memory knows the link (its first session that kept one), in seconds
    /// since the Unix epoch: a link never connected since then is dormant all the same.
    pub(crate) known_since: Option<u64>,
}

impl LinkMemory {
    /// Reads a string from [`LinkMemory::to_text`]. An empty string, or one of a version this
    /// library does not know, is no memory. A malformed one is an error, so that a host that
    /// stores something else by mistake finds out.
    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(Self::default());
        }
        let invalid = |reason: &str| Error::InvalidLinkMemory(reason.to_owned());
        let value: Value = serde_json::from_str(text).map_err(|_| invalid("not JSON"))?;
        let object = value
            .as_object()
            .ok_or_else(|| invalid("not a JSON object"))?;
        if object.get("v").and_then(Value::as_u64) != Some(VERSION) {
            return Ok(Self::default());
        }
        let peer_relay = match object.get("peerRelay") {
            None | Some(Value::Null) => None,
            Some(Value::String(url)) => Some(parse_relay_url(url)?),
            Some(_) => return Err(invalid("peerRelay is not a string")),
        };
        let seconds = |key: &str| -> Result<Option<u64>, Error> {
            match object.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => value
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| invalid(&format!("{key} is not a number of seconds"))),
            }
        };
        Ok(Self {
            peer_relay,
            last_connected: seconds("lastConnected")?,
            known_since: seconds("knownSince")?,
        })
    }

    /// The string a host stores.
    pub(crate) fn to_text(&self) -> String {
        let mut object = Map::new();
        object.insert("v".to_owned(), json!(VERSION));
        if let Some(url) = &self.peer_relay {
            object.insert("peerRelay".to_owned(), json!(url.to_string()));
        }
        if let Some(at) = self.last_connected {
            object.insert("lastConnected".to_owned(), json!(at));
        }
        if let Some(at) = self.known_since {
            object.insert("knownSince".to_owned(), json!(at));
        }
        Value::Object(object).to_string()
    }

    /// How long ago the peer was last connected, or, if it never was, how long the link has
    /// been known; `None` when this memory knows neither.
    pub(crate) fn since_last_seen(&self, now: u64) -> Option<u64> {
        self.last_connected
            .or(self.known_since)
            .map(|at| now.saturating_sub(at))
    }
}

/// Seconds since the Unix epoch, or `None` when the clock is before it.
pub(crate) fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_round_trips_through_its_text() {
        let memory = LinkMemory {
            peer_relay: Some(parse_relay_url("https://euc1-1.relay.n0.iroh.link./").unwrap()),
            last_connected: Some(1_793_600_000),
            known_since: Some(1_793_000_000),
        };
        assert_eq!(LinkMemory::parse(&memory.to_text()).unwrap(), memory);
        assert_eq!(
            LinkMemory::parse(&LinkMemory::default().to_text()).unwrap(),
            LinkMemory::default()
        );
    }

    #[test]
    fn no_text_and_unknown_versions_are_no_memory() {
        assert_eq!(LinkMemory::parse("").unwrap(), LinkMemory::default());
        assert_eq!(LinkMemory::parse("  ").unwrap(), LinkMemory::default());
        assert_eq!(
            LinkMemory::parse(r#"{"v":2,"lastConnected":5}"#).unwrap(),
            LinkMemory::default()
        );
        assert_eq!(
            LinkMemory::parse(r#"{"lastConnected":5}"#).unwrap(),
            LinkMemory::default()
        );
    }

    #[test]
    fn malformed_memories_are_refused() {
        for text in [
            "not json",
            "[1]",
            r#"{"v":1,"peerRelay":5}"#,
            r#"{"v":1,"peerRelay":"ftp://relay.example.com"}"#,
            r#"{"v":1,"peerRelay":"http://8.8.8.8:3340"}"#,
            r#"{"v":1,"lastConnected":"yesterday"}"#,
            r#"{"v":1,"lastConnected":-1}"#,
            r#"{"v":1,"knownSince":"long ago"}"#,
        ] {
            assert!(
                matches!(
                    LinkMemory::parse(text),
                    Err(Error::InvalidLinkMemory(_)) | Err(Error::InvalidRelayUrl(_))
                ),
                "{text} should be refused"
            );
        }
    }

    #[test]
    fn a_link_is_last_seen_at_its_last_connection_or_since_it_is_known() {
        let connected = LinkMemory {
            peer_relay: None,
            last_connected: Some(100),
            known_since: Some(10),
        };
        assert_eq!(connected.since_last_seen(160), Some(60));
        // A clock set back: zero, not a wrap-around.
        assert_eq!(connected.since_last_seen(40), Some(0));
        let never_connected = LinkMemory {
            known_since: Some(10),
            ..LinkMemory::default()
        };
        assert_eq!(never_connected.since_last_seen(160), Some(150));
        assert_eq!(LinkMemory::default().since_last_seen(160), None);
    }
}
