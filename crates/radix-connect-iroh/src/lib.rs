//! Radix Connect over [iroh](https://iroh.computer).
//!
//! A QUIC peer-to-peer transport between the Radix Wallet (mobile) and the Radix
//! Connector Extension (browser), alternative to the WebRTC data channel. It carries
//! exactly the same application messages (wallet interactions, `linkClient`,
//! `accountList`, ledger requests/responses) as the WebRTC transport, so the layers
//! above it do not change.
//!
//! The transport is keyed by the link's existing connection password: both endpoint
//! identities are derived from it ([`keys`]), so links created before this transport
//! existed work unchanged, nothing new has to be exchanged when linking, and only the
//! two parties holding the password can reach or impersonate each other. See
//! `docs/PROTOCOL.md` for the wire protocol and the security analysis.
//!
//! The entry point is [`Session`]: one per link, on each side.
//!
//! ```no_run
//! # async fn run() -> Result<(), radix_connect_iroh::Error> {
//! use radix_connect_iroh::{ConnectionPassword, Role, Session, SessionConfig, SessionEvent};
//!
//! let password = ConnectionPassword::from_hex(
//!     "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
//! )?;
//! // n0's public relays; `SessionConfig::new(url)` for a self-hosted one.
//! let config = SessionConfig::public();
//! let session = Session::start(&password, Role::Wallet, config).await?;
//! while let Some(event) = session.next_event().await {
//!     if let SessionEvent::Message(json) = event {
//!         println!("received {json}");
//!     }
//! }
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod config;
pub mod diagnostics;
mod error;
mod guard;
pub mod keys;
pub mod logging;
mod protocol;
mod relay_health;
mod session;

pub use config::{
    DEFAULT_ACK_TIMEOUT, DEFAULT_MAX_MESSAGE_SIZE, Relays, SessionConfig, public_relay_urls,
};
pub use diagnostics::{Diagnostics, PathKind};
pub use error::{Error, SendError};
pub use iroh::EndpointId;
pub use keys::{ConnectionPassword, Role};
pub use protocol::ALPN;
pub use session::{ConnectionState, Session, SessionEvent};
