//! Endpoint identities derived from the link's connection password.
//!
//! A Radix Connect link is identified by a 32-byte random connection password that
//! the Connector Extension generates and shows in the linking QR code, and that both
//! sides store. The WebRTC transport uses it to find each other on the signaling
//! server (`blake2b(password)`) and to encrypt the signaling messages.
//!
//! The iroh transport derives one Ed25519 endpoint key per role from it:
//!
//! ```text
//! wallet_secret    = BLAKE3-derive_key(WALLET_KEY_CONTEXT,    password)
//! connector_secret = BLAKE3-derive_key(CONNECTOR_KEY_CONTEXT, password)
//! ```
//!
//! Both sides can compute both public keys, so each side knows in advance exactly
//! which peer it may talk to, and the QUIC handshake (TLS 1.3 with raw public keys)
//! proves that the other side holds the matching secret. Someone who does not know
//! the password cannot learn it from an endpoint id (BLAKE3 is one-way) nor produce
//! a key the other side would accept.

use std::fmt;

use iroh::{EndpointId, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// BLAKE3 `derive_key` context for the wallet's endpoint key. Never change it: it is
/// part of the wire protocol (a new value is a new protocol version).
pub const WALLET_KEY_CONTEXT: &str = "Radix Connect over iroh 2026-10-29 wallet endpoint key v1";

/// BLAKE3 `derive_key` context for the Connector Extension's endpoint key. Never
/// change it: it is part of the wire protocol.
pub const CONNECTOR_KEY_CONTEXT: &str =
    "Radix Connect over iroh 2026-10-29 connector endpoint key v1";

/// Length in bytes of a Radix Connect connection password.
pub const PASSWORD_LENGTH: usize = 32;

/// The secret shared by the two ends of a Radix Connect link.
///
/// It is wiped from memory on drop and never printed: `Debug` is redacted.
/// It deliberately does not implement `PartialEq`, so that it is never compared in
/// variable time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ConnectionPassword([u8; PASSWORD_LENGTH]);

impl ConnectionPassword {
    /// Wraps the 32 raw password bytes.
    pub fn from_bytes(bytes: [u8; PASSWORD_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Parses the password from a byte slice, which must be exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; PASSWORD_LENGTH] = bytes.try_into().map_err(|_| Error::InvalidPassword)?;
        Ok(Self(bytes))
    }

    /// Parses the password from its 64-character hex encoding (the form used in the
    /// linking QR code and in storage).
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let mut bytes = [0u8; PASSWORD_LENGTH];
        hex::decode_to_slice(hex, &mut bytes).map_err(|_| Error::InvalidPassword)?;
        Ok(Self(bytes))
    }

    /// The secret key of the endpoint playing `role` on this link.
    pub fn secret_key(&self, role: Role) -> SecretKey {
        let mut seed = blake3::derive_key(role.key_context(), &self.0);
        let key = SecretKey::from_bytes(&seed);
        seed.zeroize();
        key
    }

    /// The public endpoint id of the endpoint playing `role` on this link.
    pub fn endpoint_id(&self, role: Role) -> EndpointId {
        self.secret_key(role).public()
    }
}

impl fmt::Debug for ConnectionPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionPassword(<redacted>)")
    }
}

/// Which end of a link an endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The Radix Wallet. It dials the Connector Extension.
    Wallet,
    /// The Radix Connector Extension. It waits for the wallet to dial in.
    Connector,
}

impl Role {
    /// The role of the other end of the link.
    pub fn peer(self) -> Self {
        match self {
            Self::Wallet => Self::Connector,
            Self::Connector => Self::Wallet,
        }
    }

    /// `wallet` or `connector`, for logs.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Connector => "connector",
        }
    }

    fn key_context(self) -> &'static str {
        match self {
            Self::Wallet => WALLET_KEY_CONTEXT,
            Self::Connector => CONNECTOR_KEY_CONTEXT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAFE: &str = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";

    #[test]
    fn hex_and_slice_parsing_agree() {
        let from_hex = ConnectionPassword::from_hex(CAFE).unwrap();
        let from_slice = ConnectionPassword::from_slice(&hex::decode(CAFE).unwrap()).unwrap();
        assert_eq!(
            from_hex.endpoint_id(Role::Wallet),
            from_slice.endpoint_id(Role::Wallet)
        );
    }

    #[test]
    fn rejects_malformed_passwords() {
        assert!(ConnectionPassword::from_hex("cafe").is_err());
        assert!(ConnectionPassword::from_hex(&"zz".repeat(32)).is_err());
        assert!(ConnectionPassword::from_slice(&[0u8; 31]).is_err());
        assert!(ConnectionPassword::from_slice(&[0u8; 33]).is_err());
    }

    #[test]
    fn debug_does_not_leak_the_password() {
        let password = ConnectionPassword::from_hex(CAFE).unwrap();
        let debug = format!("{password:?}");
        assert!(!debug.contains("cafe"));
        assert!(!debug.contains("202"));
    }

    #[test]
    fn roles_get_distinct_keys() {
        let password = ConnectionPassword::from_hex(CAFE).unwrap();
        assert_ne!(
            password.endpoint_id(Role::Wallet),
            password.endpoint_id(Role::Connector)
        );
    }

    #[test]
    fn links_get_distinct_keys() {
        let a = ConnectionPassword::from_bytes([1; 32]);
        let b = ConnectionPassword::from_bytes([2; 32]);
        assert_ne!(a.endpoint_id(Role::Wallet), b.endpoint_id(Role::Wallet));
        assert_ne!(
            a.endpoint_id(Role::Connector),
            b.endpoint_id(Role::Connector)
        );
    }

    #[test]
    fn peer_role_is_the_other_one() {
        assert_eq!(Role::Wallet.peer(), Role::Connector);
        assert_eq!(Role::Connector.peer(), Role::Wallet);
    }

    /// Fixed vectors so other implementations can check their derivation. They are
    /// also listed in `docs/PROTOCOL.md` and were cross-checked with an independent
    /// implementation (Python `blake3` + PyNaCl); changing them breaks every link.
    #[test]
    fn derivation_test_vectors() {
        let password = ConnectionPassword::from_hex(CAFE).unwrap();
        assert_eq!(
            password.endpoint_id(Role::Wallet).to_string(),
            WALLET_ID_FOR_CAFE
        );
        assert_eq!(
            password.endpoint_id(Role::Connector).to_string(),
            CONNECTOR_ID_FOR_CAFE
        );
    }

    const WALLET_ID_FOR_CAFE: &str =
        "4d99dc649e722e88092356956cb78d87dd24bae70b8110f492a4e843fe91f178";
    const CONNECTOR_ID_FOR_CAFE: &str =
        "efcc89cfbf2350783bcc70dd2908a034d765fa70abab6d00f62e236561d43aa8";
}
