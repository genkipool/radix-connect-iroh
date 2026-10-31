use std::sync::{Arc, Mutex, PoisonError};

use iroh::endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks};
use iroh::{EndpointAddr, EndpointId};
use n0_future::time::Instant;

use crate::diagnostics::Tally;
use crate::protocol::{ALPN, CloseCode, KNOCK_ALPN};

/// Restricts an endpoint to the single peer of its link.
///
/// Every session endpoint has a key derived from one link's password, so it has
/// exactly one legitimate peer. This hook enforces that inside iroh, for both
/// directions: the endpoint refuses to dial anyone else, and any connection whose
/// authenticated remote id (proven by the TLS 1.3 handshake) is not the peer is
/// closed before the application ever sees it.
#[derive(Debug)]
pub(crate) struct PeerGuard {
    peer: EndpointId,
    /// Rejected connections: anyone can complete a direct handshake, so the warning is
    /// logged once a minute and the rest counted (the connector summarises them).
    rejected: Arc<Mutex<Tally>>,
}

impl PeerGuard {
    pub(crate) fn new(peer: EndpointId, rejected: Arc<Mutex<Tally>>) -> Self {
        Self { peer, rejected }
    }

    /// The peer only, with the protocol or a knock (each endpoint accepts only its role's).
    pub(crate) fn is_allowed(&self, remote: EndpointId, alpn: &[u8]) -> bool {
        remote == self.peer && (alpn == ALPN || alpn == KNOCK_ALPN)
    }
}

impl EndpointHooks for PeerGuard {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if self.is_allowed(remote_addr.id, alpn) {
            BeforeConnectOutcome::Accept
        } else {
            // The session only ever dials its peer: reaching this is a bug.
            tracing::error!(remote = %remote_addr.id.fmt_short(), "refused to dial an endpoint that is not the link's peer");
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if self.is_allowed(conn.remote_id(), conn.alpn()) {
            AfterHandshakeOutcome::accept()
        } else {
            let first = self
                .rejected
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .count(Instant::now());
            let remote = conn.remote_id().fmt_short();
            if first {
                tracing::warn!(%remote, "rejected a connection from an endpoint that is not the link's peer (unauthorized); repeats are summarised every minute");
            } else {
                tracing::debug!(%remote, "rejected a connection from an endpoint that is not the link's peer (unauthorized)");
            }
            AfterHandshakeOutcome::Reject {
                error_code: CloseCode::Unauthorized.into(),
                reason: b"unauthorized".to_vec(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionPassword, Role};

    #[test]
    fn only_the_link_peer_with_our_alpn_is_allowed() {
        let password = ConnectionPassword::from_bytes([7; 32]);
        let other_link = ConnectionPassword::from_bytes([8; 32]);
        let guard = PeerGuard::new(password.endpoint_id(Role::Wallet), Arc::default());

        assert!(guard.is_allowed(password.endpoint_id(Role::Wallet), ALPN));
        assert!(!guard.is_allowed(password.endpoint_id(Role::Connector), ALPN));
        assert!(!guard.is_allowed(other_link.endpoint_id(Role::Wallet), ALPN));
        assert!(!guard.is_allowed(password.endpoint_id(Role::Wallet), b"other/1"));
        assert!(guard.is_allowed(password.endpoint_id(Role::Wallet), KNOCK_ALPN));
        assert!(!guard.is_allowed(other_link.endpoint_id(Role::Wallet), KNOCK_ALPN));
    }
}
