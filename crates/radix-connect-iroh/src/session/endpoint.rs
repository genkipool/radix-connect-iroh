//! The local endpoint's relay setup: n0's public relays with address lookup (the connector
//! publishes its relay, the wallet looks it up) or a single custom relay, plus the settings
//! only tests and benchmarks use.

use crate::config::Relays;
use crate::logging::Redacted;
use crate::{Role, SessionConfig};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use iroh::address_lookup::DnsAddressLookup;
use iroh::address_lookup::{AddrFilter, PkarrPublisher, PkarrResolver};
use iroh::{RelayConfig, RelayMap, RelayMode, RelayUrl};
use std::fmt::Display;

/// The relay choice for the session's first line: `public`, or the custom relay's URL.
pub(super) struct RelaysField<'a>(pub(super) &'a Relays);

impl Display for RelaysField<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Relays::Public => f.write_str("public"),
            Relays::Custom(url) => write!(f, "{}", Redacted(url)),
        }
    }
}

/// Applies the relay choice. `Minimal` has no address lookup of its own: with a custom
/// relay the endpoint publishes nothing about itself and is found only through that
/// relay; with the public relays the connector publishes its relay URL (never its IP
/// addresses) and the wallet looks it up.
pub(super) fn with_relays(
    builder: iroh::endpoint::Builder,
    config: &SessionConfig,
    role: Role,
) -> iroh::endpoint::Builder {
    #[cfg(any(test, feature = "bench-utils"))]
    let builder = test_builder(builder, config);
    match &config.relays {
        Relays::Custom(url) => builder.relay_mode(custom_relay_mode(url)),
        Relays::Public => {
            #[cfg(test)]
            if let Some(test) = &config.test_public_infrastructure {
                return builder
                    .relay_mode(RelayMode::custom([test.relay_url.clone()]))
                    .preset(test.lookup.preset());
            }
            // `default_relay_mode` honours IROH_FORCE_STAGING_RELAYS, as n0's address
            // lookup does, so relays and lookup never point at different deployments.
            let builder = builder.relay_mode(iroh::endpoint::default_relay_mode());
            match role {
                Role::Connector => builder
                    .addr_filter(AddrFilter::relay_only())
                    .address_lookup(PkarrPublisher::n0_dns()),
                Role::Wallet => {
                    let builder = builder.address_lookup(PkarrResolver::n0_dns());
                    // Browsers cannot query DNS; elsewhere it is a second, independent
                    // way to find the connector.
                    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
                    let builder = builder.address_lookup(DnsAddressLookup::n0_dns());
                    builder
                }
            }
        }
    }
}

/// A single custom relay. A plain-http relay is a local development one, which serves
/// no QUIC address discovery: don't probe it for that.
pub(super) fn custom_relay_mode(url: &RelayUrl) -> RelayMode {
    if url.scheme() == "http" {
        RelayMode::Custom(RelayMap::from_iter([RelayConfig::new(url.clone(), None)]))
    } else {
        RelayMode::custom([url.clone()])
    }
}

/// Settings that only tests and benchmarks use. Skipping the relay's certificate check is
/// compiled into tests alone, never into a build with `bench-utils`.
#[cfg(any(test, feature = "bench-utils"))]
pub(super) fn test_builder(
    mut builder: iroh::endpoint::Builder,
    config: &SessionConfig,
) -> iroh::endpoint::Builder {
    #[cfg(test)]
    if config.insecure_skip_relay_cert_verify {
        builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
    }
    if config.relay_only {
        builder = builder.clear_ip_transports();
    }
    builder
}
