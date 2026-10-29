use iroh::endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks};
use iroh::{EndpointAddr, EndpointId};

use crate::protocol::{ALPN, CloseCode};

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
}

impl PeerGuard {
    pub(crate) fn new(peer: EndpointId) -> Self {
        Self { peer }
    }

    pub(crate) fn is_allowed(&self, remote: EndpointId, alpn: &[u8]) -> bool {
        remote == self.peer && alpn == ALPN
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
            tracing::warn!(remote = %remote_addr.id.fmt_short(), "refusing to dial an endpoint that is not the link peer");
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if self.is_allowed(conn.remote_id(), conn.alpn()) {
            AfterHandshakeOutcome::accept()
        } else {
            tracing::warn!(remote = %conn.remote_id().fmt_short(), "rejecting a connection from an endpoint that is not the link peer");
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
        let guard = PeerGuard::new(password.endpoint_id(Role::Wallet));

        assert!(guard.is_allowed(password.endpoint_id(Role::Wallet), ALPN));
        assert!(!guard.is_allowed(password.endpoint_id(Role::Connector), ALPN));
        assert!(!guard.is_allowed(other_link.endpoint_id(Role::Wallet), ALPN));
        assert!(!guard.is_allowed(password.endpoint_id(Role::Wallet), b"other/1"));
    }
}
