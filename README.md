# Radix Connect over iroh

A second transport for **Radix Connect**, the link between the Radix Wallet and the
Radix Connector Extension: QUIC over [iroh](https://iroh.computer) relays, as an
alternative to the WebRTC data channel. It carries the same Radix Connect messages, so
dApp requests and answers work the same over either transport.

- Works with **existing links**: the endpoint identities are derived from the link's
  connection password, so the QR code, the stored links and the linking flow do not
  change.
- **End-to-end encrypted and mutually authenticated** (QUIC / TLS 1.3 with Ed25519 raw
  public keys); relays only forward ciphertext. With the default public relays the
  connector publishes which relay it uses (never its IP address); with a custom relay
  nothing is published.
- **One Rust implementation** for both ends: Kotlin bindings (uniffi) for the Android
  wallet, WebAssembly bindings (wasm-bindgen) for the browser extension. uniffi can also
  generate Swift, but the library has not been built or tested for iOS yet (see [iOS](#ios)).

> **Status:** community project, proposed to the Radix maintainers for the Radix Wallet
> and the Radix Connector Extension; not an official Radix package. It is published under the
> author's coordinates (`io.github.genkipool`, `@genkipool`), see [Using it](#using-it).
> Until the official wallet and extension support it, use it with development builds.

## Try it

Test builds of the wallet (Android APK) and the extension (Chrome ZIP), with install steps:
**[docs/TESTERS.md](docs/TESTERS.md)**. They are community builds, not official Radix releases;
never import your main seed phrase into them.

Specification and security analysis: [`docs/PROTOCOL.md`](docs/PROTOCOL.md). Binding
APIs: [`docs/BINDINGS.md`](docs/BINDINGS.md). Proposal to the Radix maintainers:
[`docs/PROPOSAL.md`](docs/PROPOSAL.md).

## Why iroh

[iroh](https://iroh.computer) is a Rust library, developed by the company n0, that opens
QUIC connections between two endpoints identified by public keys (their *endpoint ids*).
It connects directly when the network allows it, and otherwise goes through a *relay*: a
server that forwards encrypted packets without being able to read them.

Using it for Radix Connect brings:

- **Fewer servers for this transport.** A WebRTC link needs a signaling server, STUN and often TURN.
  This transport needs a relay, plus n0's address lookup when the public relays are used.
  A self-hosted relay needs nothing else ([Relays](#relays)).
- **Wallet presence.** The wallet tells the connector when it goes to the background, and
  the connector then checks often whether it is still there. When the wallet app is
  closed from the recent apps screen, the extension notices within about 1–2 seconds and
  stops waiting for an answer; if the wallet could not say it left the foreground, within
  7–8 s.
- **Requests that come back.** On every connection the wallet lists the requests it still
  holds, and the connector sends again any request the wallet no longer has, for example
  after its process was killed ([PROTOCOL.md §7.2](docs/PROTOCOL.md#72-presence-and-request-inventory-datagrams)).
  Wallets that support it send the same list over WebRTC too, to extensions known to
  understand it.
- **Connectors that are not a browser.** A server, a desktop app, a command-line tool or an
  AI agent can reach the wallet with this native library over one outbound HTTPS connection
  to a relay: no signaling server, no STUN or TURN, no UDP ([Trying it by hand](#trying-it-by-hand)
  shows both ends).
- **One implementation of the transport.** The same Rust code runs in the wallet (uniffi)
  and in the extension (WebAssembly), so both ends follow the same rules.

It keeps what works today:

- **No new linking.** Endpoint keys are derived from the existing connection password,
  so the QR code and the links already stored work over it.
- **Same trust root as WebRTC.** Only the two holders of the password can connect, and
  all traffic is end-to-end encrypted with QUIC/TLS 1.3 ([PROTOCOL.md §8](docs/PROTOCOL.md#8-security-considerations)).
- **WebRTC stays.** Both transports can run for the same link. Each message goes over
  exactly one of them, with a fallback to WebRTC when iroh is not connected. The extension
  uses iroh only when it is turned on (WebRTC is its default). The wallet also uses WebRTC
  by default; in its Automatic mode it adds iroh for the links known to support it
  ([PROTOCOL.md §9](docs/PROTOCOL.md#9-compatibility-and-coexistence-with-webrtc)).

### Performance

Measured with the Android development wallet on a Motorola Edge 30 (Android 14, debug
build, Wi-Fi or LTE depending on the run) and the development Connector Extension in
Chrome, using n0's public relays.

| What | Result |
|---|---|
| Wallet closed from the recent apps screen, until the extension shows the link down | 1.2–1.7 s (5 runs) |
| Link back after 45 s in the background (iroh-only mode, 7 runs) | median 0.65–0.68 s, max 0.92 s |
| Link back after the extension's offscreen document restarts (previous connection up for at least 15 s) | median 0.62 s |
| Wallet started from scratch, until the link connects (5 runs) | median 5.4 s, of which 4–4.5 s is the app starting |
| Battery, 3 h 38 min of normal phone use with the app in the background | 0.92 mAh, about 0.03 % of the battery |

### Trade-offs

- **Relays run by a third party by default.** n0 runs the public relays and the address
  lookup. A relay sees which endpoint ids talk, their IP addresses and when they are
  online, as a signaling or TURN server does. The lookup stores which relay a connector
  uses, never its IP address. A self-hosted relay avoids both.
- **The browser is always relayed.** WebAssembly has no raw UDP sockets, so the
  extension never connects directly.
- **Slow networks.** When the phone's network is slow (round trips of 1.8–4.3 s), iroh can
  take long to connect: 17.0 s and 9.5 s in 2 of 5 cold starts. This is one reason the
  wallet's Automatic mode runs WebRTC too.
- **Data use while the app is open.** With 9 linked connectors (2 of them reachable), in
  Automatic mode, the wallet used about 64 MB per hour in the foreground (a 10-minute
  window, app idle, LTE, measured with an earlier library version). Sessions stop 30 s
  after the app goes to the background.

## Layout

| Path | What |
|---|---|
| `crates/radix-connect-iroh` | Protocol core: key derivation, admission, message exchange, session with reconnection |
| `crates/radix-connect-iroh-uniffi` | Kotlin bindings (`libradix_connect_iroh_uniffi`; Swift not built yet) |
| `crates/radix-connect-iroh-wasm` | Browser bindings |
| `jvm/` | Gradle project producing the Android library `io.github.genkipool:radix-connect-iroh-android` |
| `js/` | npm package `@genkipool/radix-connect-iroh` |
| `scripts/` | wasm build and the cross-implementation end-to-end test |

## Using it

Android (a plain Maven repository, no account needed):

```groovy
repositories {
    maven {
        url "https://raw.githubusercontent.com/genkipool/radix-connect-iroh/maven"
        content { includeGroup "io.github.genkipool" }
    }
}
dependencies { implementation "io.github.genkipool:radix-connect-iroh-android:0.2.0" }
```

Browser (npm package attached to the GitHub release):

```json
"@genkipool/radix-connect-iroh": "https://github.com/genkipool/radix-connect-iroh/releases/download/v0.2.0/genkipool-radix-connect-iroh-0.2.0.tgz"
```

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

## iOS

uniffi can generate Swift bindings for this library, but it has not been built or tested
for iOS yet: there is no iOS target, Swift package or CI. The intended way to ship it is
the one Sargon uses: an `xcframework` downloaded as a binary target, with the generated
Swift in a Swift package.

In the iOS Radix Wallet, `RadixConnectClient` already merges two transports (WebRTC and
deep links) and routes each answer on `P2P.Route`, so iroh would be one more route there.
Settings, link storage and app lifecycle handling would still be needed.

## License

Apache-2.0.
