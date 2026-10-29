/// Errors starting a [`Session`](crate::Session) or configuring one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The connection password is not 32 bytes (64 hex characters).
    #[error("the connection password must be 32 bytes")]
    InvalidPassword,
    /// The relay URL is not usable.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),
    /// The local iroh endpoint could not be created.
    #[error("could not start the iroh endpoint: {0}")]
    Bind(String),
}

/// Why a message could not be delivered by [`Session::send`](crate::Session::send).
///
/// The variants mirror the reasons the WebRTC transport reports, so hosts can map
/// them onto their existing retry logic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// There is no connection to the peer right now. Nothing was sent.
    #[error("not connected to the peer")]
    NotConnected,
    /// The peer did not confirm the message in time. It may or may not have
    /// received it.
    #[error("the peer did not confirm the message in time")]
    Timeout,
    /// The message is larger than the configured maximum. Nothing was sent.
    #[error("the message is {size} bytes, the maximum is {max}")]
    MessageTooLarge {
        /// Size of the rejected message in bytes.
        size: usize,
        /// Configured maximum in bytes.
        max: usize,
    },
    /// The peer refused the message (too large or not UTF-8); it was not delivered.
    #[error("the peer rejected the message")]
    Rejected,
    /// The connection broke while sending. As with a timeout, the peer may or may
    /// not have received the message.
    #[error("the connection was lost: {0}")]
    ConnectionLost(String),
    /// The session has been closed.
    #[error("the session is closed")]
    Closed,
}
