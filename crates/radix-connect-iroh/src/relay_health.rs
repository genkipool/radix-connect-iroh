//! Health notices a relay sends to an endpoint, which iroh only logs.
//!
//! A relay forwards an endpoint id's traffic to the newest client holding that id. When
//! another client with the same key connects (another device, or a second app instance,
//! holding the same link), the relay tells the older one
//! (`SameEndpointIdConnected`: "no more messages will be received"), and tells it again
//! when the newer one leaves and it is promoted back (`Healthy`). iroh 1.4 logs these
//! notices from its relay actor but exposes them nowhere else, so the
//! [`DiagnosticsLayer`](crate::logging::DiagnosticsLayer) picks them out of its events
//! and hands them, through this registry, to the session whose span they happened in.

use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::sync::watch;

/// A health notice from the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayNotice {
    /// Another client with this endpoint's key connected to the relay, which now
    /// delivers to that one: this end no longer receives anything through it.
    Displaced,
    /// The relay delivers to this end again (the other holder left).
    Restored,
}

type Notices = watch::Sender<Option<RelayNotice>>;

/// Live sessions, by session number.
static SESSIONS: Mutex<Vec<(u64, Notices)>> = Mutex::new(Vec::new());

fn sessions() -> MutexGuard<'static, Vec<(u64, Notices)>> {
    // Nothing can leave the list inconsistent: recover from a poisoned lock.
    SESSIONS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A session's subscription to its relay notices; dropping it unsubscribes.
#[derive(Debug)]
pub(crate) struct Registration {
    session: u64,
    notices: watch::Receiver<Option<RelayNotice>>,
}

impl Registration {
    /// The notices for this session, as they arrive.
    pub(crate) fn notices(&self) -> watch::Receiver<Option<RelayNotice>> {
        self.notices.clone()
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        sessions().retain(|(session, _)| *session != self.session);
    }
}

/// Subscribes session number `session` to its relay notices.
pub(crate) fn register(session: u64) -> Registration {
    let (sender, notices) = watch::channel(None);
    sessions().push((session, sender));
    Registration { session, notices }
}

/// Hands `notice` to session number `session`, if it is still alive.
pub(crate) fn notify(session: u64, notice: RelayNotice) {
    if let Some((_, sender)) = sessions().iter().find(|(id, _)| *id == session) {
        sender.send_replace(Some(notice));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_reach_only_their_session_while_it_lives() {
        let first = register(u64::MAX - 1);
        let second = register(u64::MAX - 2);
        notify(u64::MAX - 1, RelayNotice::Displaced);
        assert_eq!(*first.notices().borrow(), Some(RelayNotice::Displaced));
        assert_eq!(*second.notices().borrow(), None);
        drop(first);
        assert!(!sessions().iter().any(|(id, _)| *id == u64::MAX - 1));
        notify(u64::MAX - 1, RelayNotice::Restored);
        drop(second);
    }
}
