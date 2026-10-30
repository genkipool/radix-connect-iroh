# Radix Connect over iroh

A second transport for **Radix Connect**, the link between the Radix Wallet and the
Radix Connector Extension: QUIC over [iroh](https://iroh.computer) relays, as an
alternative to the WebRTC data channel. It carries exactly the same messages, so the
wallet and the extension keep all their logic and only gain a transport.

- Works with **existing links**: the endpoint identities are derived from the link's
  connection password, so the QR code, the stored links and the linking flow do not
  change.
- **End-to-end encrypted and mutually authenticated** (QUIC / TLS 1.3 with Ed25519 raw
  public keys); relays only forward ciphertext. With the default public relays the
  connector publishes which relay it uses (never its IP address); with a custom relay
  nothing is published.
- **One Rust implementation** for both ends: Kotlin bindings (uniffi) for the Android
  wallet, WebAssembly bindings (wasm-bindgen) for the browser extension.

> **Status:** community project, proposed to RDX Works for the Radix Wallet and the
> Radix Connector Extension; not an official Radix package. The `com.radixdlt` and
> `@radixdlt` package coordinates below are the proposed ones and are not published.
> Until the official wallet and extension support it, use it with development builds.

Specification and security analysis: [`docs/PROTOCOL.md`](docs/PROTOCOL.md). Binding
APIs: [`docs/BINDINGS.md`](docs/BINDINGS.md).

## Layout

| Path | What |
|---|---|
| `crates/radix-connect-iroh` | Protocol core: key derivation, admission, message exchange, session with reconnection |
| `crates/radix-connect-iroh-uniffi` | Kotlin/Swift bindings (`libradix_connect_iroh_uniffi`) |
| `crates/radix-connect-iroh-wasm` | Browser bindings |
| `jvm/` | Gradle project producing the Android library `com.radixdlt.connect:radix-connect-iroh-android` |
| `js/` | npm package `@radixdlt/radix-connect-iroh` |
| `scripts/` | wasm build and the cross-implementation end-to-end test |

## Building

Rust ≥ 1.91 with the `wasm32-unknown-unknown` and Android targets, `cargo-ndk`, an
Android SDK + NDK (r28 or newer, for 16 KB page alignment), JDK 17, and a clang able to
target wasm32 (ring compiles C).

```sh
cargo test --workspace                       # unit + integration tests (local relay)
./scripts/build-wasm.sh                      # js/dist (needs wasm-bindgen-cli 0.2.129)
cd jvm && ./gradlew publishToMavenLocal      # Android AAR into ~/.m2
./scripts/e2e.sh                             # wasm connector <-> native wallet via iroh-relay --dev
```

`./gradlew -PradixConnectIroh.abis=arm64-v8a ...` builds a single ABI for faster local
iterations.

## Trying it by hand

`peer` is a command-line end of a link, handy to test the real wallet or the real
extension without the other one:

```sh
export RADIX_CONNECT_PASSWORD=<password-hex>          # the link's connection password
cargo run --example peer -- wallet    [relay-url]   # pretend to be the wallet (no URL: public relays)
cargo run --example peer -- connector [relay-url]   # pretend to be the extension
```

Lines typed on stdin are sent as messages; events are printed.

## Diagnosing a link

Every session exposes `diagnostics()` (see [`docs/BINDINGS.md`](docs/BINDINGS.md#diagnostics)
for the fields and how to read them), and the library logs every step with its context
and why things fail: relay lost, dial attempts and their outcome, why a connection
ended, refused or timed-out messages, another device holding the same link (the events
are listed in [`docs/PROTOCOL.md`](docs/PROTOCOL.md#10-diagnostics); lines never contain
secrets, message contents or IP addresses). The `peer` example prints both
(`RADIX_CONNECT_LOG=debug` for every step; `/network` reports a network change), which
makes it the quickest way to check one end of a link by hand.

## Relays

By default both ends use **n0's public relays**: each end connects to its closest one
(North America, Europe, Asia-Pacific) and fails over to another, and the wallet finds
the connector's relay through n0's address lookup, which only ever stores the relay
URL. Nothing to host or configure, so it works in production without operating a
relay.

A **custom relay** (e.g. self-hosted) can be configured instead, on both ends:

```sh
cargo install iroh-relay --features server --locked
iroh-relay --dev                              # local, plain HTTP on :3340
iroh-relay --config-path relay.toml          # TLS (manual or Let's Encrypt), access control
```

Plain `http://` relays are accepted only on loopback, private and link-local
addresses (`scripts/dev-relay.sh` prints the URLs for each side). Use TLS for
anything else.

## License

Apache-2.0.
