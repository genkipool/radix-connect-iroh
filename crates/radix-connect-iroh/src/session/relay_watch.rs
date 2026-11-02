//! Follows the endpoint's home relay (connected, lost, changed) and the relay's own notices,
//! and logs what changes.

use super::Shared;
use crate::diagnostics::ms;
use crate::logging::Redacted;
use crate::relay_health::RelayNotice;
use iroh::{RelayUrl, Watcher};
use n0_future::StreamExt;
use n0_future::time::Instant;

/// Logs when this end gains or loses its relay (without it the peer cannot reach it,
/// the first thing to check when a link does not connect) and the relay's notices
/// that another holder of this link's key took over. Never returns.
pub(super) async fn watch_relay(shared: &Shared) {
    let mut statuses = shared.endpoint.home_relay_status().stream();
    let mut notices = shared.relay.notices();
    let mut relay = RelayLog {
        connected: false,
        warned: false,
        home: None,
        since: shared.started_at,
    };
    loop {
        tokio::select! {
            Some(statuses) = statuses.next() => relay.status(shared, &statuses),
            Ok(()) = notices.changed() => {
                let notice = *notices.borrow_and_update();
                if let Some(notice) = notice {
                    relay.notice(shared, notice);
                }
            }
            else => break,
        }
    }
    std::future::pending::<()>().await;
}

/// What [`watch_relay`] remembers between updates.
pub(super) struct RelayLog {
    connected: bool,
    /// Whether the current outage was already reported at `warn`.
    warned: bool,
    home: Option<RelayUrl>,
    /// Since when the relay has been connected, or not.
    since: Instant,
}

impl RelayLog {
    fn status(&mut self, shared: &Shared, statuses: &[iroh::endpoint::RelayStatus]) {
        let connected_to = statuses.iter().find(|relay| relay.is_connected());
        let connected = connected_to.is_some();
        let error = statuses
            .iter()
            .find_map(|relay| relay.last_error().map(|error| Redacted(error).to_string()));
        let auth_denied = statuses
            .iter()
            .find_map(|relay| relay.auth_denied_reason().map(str::to_owned));
        let url = connected_to
            .or(statuses.first())
            .map(|relay| relay.url().clone());
        let relay = url
            .as_ref()
            .map_or_else(|| "none".to_owned(), |url| Redacted(url).to_string());
        let now = Instant::now();
        if connected && !self.connected {
            tracing::info!(
                relay,
                after_ms = ms(now.duration_since(self.since)),
                "connected to the relay"
            );
            self.since = now;
            self.warned = false;
            // Back after an outage (it was home before): see `knock_when_relay_returns`.
            if self.home.is_some() {
                shared
                    .relay_regained
                    .send_modify(|regained| *regained = regained.wrapping_add(1));
            }
            // The relay delivers to its newest client: this end, now.
            if std::mem::take(&mut shared.trouble().key_collision) {
                tracing::info!(
                    "reconnected to the relay, which delivers to this end again: the other holder of this link's key no longer receives through it"
                );
            }
        } else if connected && url != self.home {
            tracing::info!(relay, "moved to another relay");
        } else if !connected && self.connected {
            tracing::warn!(
                relay,
                error = error.as_deref().unwrap_or("none"),
                connected_ms = ms(now.duration_since(self.since)),
                "lost the connection to the relay: the peer cannot reach this end until it reconnects"
            );
            self.since = now;
            self.warned = true;
        } else if !connected && (error.is_some() || auth_denied.is_some()) {
            if self.warned {
                tracing::debug!(
                    relay,
                    error = error.as_deref().unwrap_or("none"),
                    down_ms = ms(now.duration_since(self.since)),
                    "still not connected to the relay"
                );
            } else {
                tracing::warn!(
                    relay,
                    error = error.as_deref().unwrap_or("none"),
                    auth_denied = auth_denied.as_deref(),
                    "cannot connect to the relay: the peer cannot reach this end"
                );
                self.warned = true;
            }
        }
        self.connected = connected;
        if connected {
            self.home = url;
        }
    }

    fn notice(&mut self, shared: &Shared, notice: RelayNotice) {
        let relay = self
            .home
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |url| Redacted(url).to_string());
        match notice {
            RelayNotice::Displaced => {
                shared.trouble().key_collision = true;
                tracing::warn!(
                    relay,
                    "another device or app instance with this link's key connected to the relay; this end no longer receives through it (the relay delivers to the newest holder)"
                );
                shared.log_snapshot();
            }
            RelayNotice::Restored => {
                if std::mem::take(&mut shared.trouble().key_collision) {
                    tracing::info!(
                        relay,
                        "the relay delivers to this end again: the other holder of this link's key disconnected"
                    );
                } else {
                    tracing::debug!(relay, "the relay reports the connection healthy again");
                }
            }
        }
    }
}
