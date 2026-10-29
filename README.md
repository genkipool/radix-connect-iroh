# Radix Connect over iroh

A second transport for **Radix Connect**, the link between the Radix Wallet and the
Radix Connector Extension: QUIC over [iroh](https://iroh.computer) relays, as an
alternative to the WebRTC data channel. It carries exactly the same messages, so the
wallet and the extension keep all their logic and only gain a transport.

- Works with **existing links**: the endpoint identities are derived from the link's
  connection password, so the QR code, the stored links and the linking flow do not
  change.
- **End-to-end encrypted and mutually authenticated** (QUIC / TLS 1.3 with Ed25519 raw
  public keys); relays only forward ciphertext and nothing is published to discovery
  services.
- **One Rust implementation** for both ends: Kotlin bindings (uniffi) for the Android
  wallet, WebAssembly bindings (wasm-bindgen) for the browser extension.

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
cargo run --example peer -- wallet    <password-hex> [relay-url]   # pretend to be the wallet
cargo run --example peer -- connector <password-hex> [relay-url]   # pretend to be the extension
```

Lines typed on stdin are sent as messages; events are printed.

## Relays

Both ends of a link must use the same relay, as both ends of a WebRTC link use the
same signaling server. The default is n0's public EU relay, fine for development.
Production should run its own:

```sh
cargo install iroh-relay --features server --locked
iroh-relay --dev                              # local, plain HTTP on :3340
iroh-relay --config-path relay.toml          # TLS (manual or Let's Encrypt), access control
```

Browsers can only reach relays over `https://` (except `localhost`); Android blocks
cleartext traffic by default, so use TLS for anything but local experiments.

## License

Apache-2.0.
