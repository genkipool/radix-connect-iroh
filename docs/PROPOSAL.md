# Proposal: Radix Connect over iroh

*Status: proposal for RDX Works. Author: genkipool. Draft, 2026-11-18.*

## In one paragraph

Radix Connect links the Radix Wallet with the Connector Extension, and through it with every
dApp in the browser. Today that link is a WebRTC data channel, set up through RDX Works'
signaling server. This proposal **adds** [iroh](https://iroh.computer) as a second,
**opt-in** transport for the same link. It carries the same messages and keeps the existing QR
codes and linked connectors. WebRTC stays, and stays the default: a user who does not turn
iroh on sees no change.

## What iroh is

iroh is an open-source Rust networking library (MIT or Apache-2.0) made by the company n0. It
opens encrypted QUIC connections between two endpoints, each identified by a public key.

- When the network allows it, the connection is direct.
- Otherwise it goes through a **relay**: a server that forwards encrypted packets it cannot
  read. The phone and the browser reach the relay over a normal HTTPS connection.
- n0 runs free public relays. Anyone can run their own relay with the `iroh-relay` program.

This proposal uses iroh 1.4.1.

## Why the wallet should adopt it

### 1. A link that does not need the signaling server

Today, every WebRTC connection is set up through RDX Works' signaling server, with STUN and
often TURN servers to cross NATs. (STUN tells a device its public address; TURN forwards the
traffic when no direct path exists.) If the signaling server is down or blocked, no link can
be set up.

An iroh link needs only a relay, reached over HTTPS. This means:
- links keep working when the signaling server is down;
- links work on networks that block UDP, where WebRTC needs a TURN server;
- RDX Works, or any user, can run the whole path with one relay program.

What this depends on:
- This applies to links in **iroh only** mode. In **Automatic** mode WebRTC keeps running next
  to iroh.
- With n0's public relays, the dependency moves from RDX Works' servers to n0's. n0's address
  lookup then stores which relay a connector uses (never its IP address). With a self-hosted
  relay, nothing else is involved.
- The keys come from the link's existing password, so links created before iroh existed work
  too.

### 2. Native connectors with one outbound HTTPS connection

A server, a desktop app, a command-line tool or an AI agent can reach the user's wallet with
iroh's native library. It needs only one outbound HTTPS connection to a relay: no signaling
server, no STUN or TURN, no UDP. This makes it simple to run behind firewalls and in
containers.

This already works: a Rust SDK client and an MCP server (a local tool server that lets AI
agents ask the wallet to sign) pair with the phone over iroh. The user still approves every
request on the phone, as with the extension. (Both are by the same author; available on
request.)

### 3. The extension knows quickly that the wallet is gone

When the user closes the wallet from the recent apps screen while a dApp request is pending,
the extension shows the link down **within 1.2–1.7 s** (5 runs out of 5). The dApp can then
say that the wallet is not reachable instead of waiting. Without the notice, the link showed
down after 7.0–8.0 s in the same test; the official wallet over WebRTC takes about the same.

How it works:
- The wallet tells the extension when it leaves the front of the screen. Opening the recent
  apps screen counts.
- The extension then checks over iroh whether the wallet still answers: every 0.5 s for 8 s,
  and every 4 s at other times.

These checks are part of the iroh library, so the wallet and the extension run the same code.
They are not a property that only iroh could have: a similar check could be built on WebRTC.

### Other measurements, with iroh only

| What | Result |
|---|---|
| Link back after the extension's offscreen document (its hidden page that holds the connections) restarts | median 0.62 s |
| Link back after 45 s in the background (iroh only mode, 7 runs) | median 0.65–0.68 s, max 0.92 s |
| Wallet started from scratch until the link connects (5 runs) | median 5.4 s, of which 4–4.5 s is the app starting |

These were not measured side by side with WebRTC, so they are not a comparison.

## What the pull request contains

- The iroh transport in the wallet's Radix Connect layer (`peerdroid`), next to WebRTC.
- Settings to choose the transport and the relay.
- Each linked connector shows which transport it uses.
- Lifecycle handling: iroh sessions stop 30 s after the app goes to the background, and come
  back when it returns.
- Three messages for the extension: the **background notice**, the **request inventory** and
  **link removed**.
  - The request inventory is a list of the requests the wallet still holds, sent on every
    connection. The extension sends again any request the wallet lost, for example when
    Android ended its process.
  - Link removed tells the extension that the user removed the link in the wallet.
  - The background notice is needed for use case 3. The request inventory and link removed are
    separate improvements; they can be moved to their own pull request if preferred.

These messages go over iroh, and over WebRTC only on links that have connected over iroh at
least once. Such a link has the iroh build of the extension. The released extension expects an
interaction id on every message from the wallet, and these messages have none, so they are not
sent to it.

Size: 108 files changed, about 12,700 lines added, tests included. This includes the commits of
#1451 and #1453 (9 files, about 440 lines); once those are merged, the pull request contains only
the iroh work. Its commit message also lists the few changes that apply with WebRTC only.

## How it works

- **Identity.** Both ends derive their iroh keys from the link's connection password. No new
  pairing.
- **Security.** Only the two holders of the password can connect, as with WebRTC today.
  Traffic is end-to-end encrypted (QUIC with TLS 1.3, Ed25519 keys). Relays only forward
  ciphertext.
- **Coexistence.** Both transports can run for the same link. Each message goes over exactly
  one of them. If iroh is not connected, the message goes over WebRTC. Wallets and extensions
  without iroh never connect over it.
- **One implementation.** The protocol is a Rust library (`radix-connect-iroh`). It has Kotlin
  bindings, generated with uniffi as Sargon's are, and WebAssembly bindings for the browser. The
  Android wallet and the extension run the same code. uniffi can also generate Swift bindings
  for the iOS wallet.

Full specification and security analysis: [PROTOCOL.md](PROTOCOL.md).

## What changes for users

- **Nothing by default.** The wallet keeps using WebRTC only and never contacts an iroh relay.
- In **Settings → Preferences → Radix Connect** the user can choose:
  - **Automatic:** WebRTC, plus iroh for links whose extension supports it;
  - **iroh only**;
  - a custom relay instead of n0's public ones.
- The extension also keeps WebRTC as its default; iroh is turned on in its settings.
- **Rollback:** a user goes back by choosing WebRTC only. A release can turn iroh off for
  everyone by ignoring the stored choice (a one-line change), because the default is WebRTC
  only.

## Costs and trade-offs

- **Third-party relays by default.** n0 runs the public relays and the address lookup. A relay
  sees which endpoint ids (public keys) talk, their IP addresses and when they are online, as a
  signaling or TURN server does today. A self-hosted relay avoids this. n0's terms, limits and
  availability for its public relays would need to be checked by RDX Works.
- **The browser is always relayed,** because WebAssembly cannot use UDP directly.
- **App size.** The native library adds, per CPU architecture (ABI), uncompressed: arm64 8.7 MB, armeabi-v7a
  5.5 MB, x86_64 9.6 MB, x86 10.0 MB. Compressed, arm64 is 3.6 MB. Current Android packaging
  keeps native libraries uncompressed inside the APK.
- **Battery.** 0.92 mAh over 3 h 38 min of normal phone use with the app in the background,
  about 0.03 % of the battery.
- **Data while the app is open.** About 64 MB per hour in one 10-minute measurement on LTE, in
  Automatic mode, with 9 linked connectors of which 2 were reachable. This was measured with an
  earlier library version.
- **Slow networks.** With a slow phone network (round trips of 1.8–4.3 s), 2 of the 5 cold
  starts took 17.0 s and 9.5 s to connect over iroh. Automatic mode runs WebRTC too and uses
  whichever connects first.
- **Maintenance.** The library has to follow iroh's releases. Who does this is decision 2
  below.
- **iOS.** iOS users get nothing until the iOS wallet adds it.

Measured on a Motorola Edge 30 (Android 14, debug build) with the development extension in
Chrome and n0's public relays.

## What exists today

- `radix-connect-iroh` 0.2.0: the library, its tests, and an end-to-end test between the
  WebAssembly and the native builds.
- An Android wallet pull request, based on wallet 1.22.3. It also needs two open WebRTC fixes,
  #1451 and #1453.
- A Connector Extension pull request that adds only the iroh transport, WebRTC staying its
  default.

The library is published under the author's names (see decision 2), so both pull requests build
without anything local.

## Decisions for RDX Works

1. **Is iroh wanted as a second, opt-in transport?**
2. **Who publishes and maintains the library?** Today the author publishes it as
   `io.github.genkipool:radix-connect-iroh-android` (a Maven repository on GitHub) and
   `@genkipool/radix-connect-iroh` (a package on the GitHub release). Options:
   - RDX Works adopts the repository and publishes it under its own names;
   - the author keeps publishing it and keeps it up to date.
3. **Relays.** n0's public relays, relays run by RDX Works, or both.
4. **iOS.** The library has not been built for iOS yet. One option is to put the shared rules in
   Sargon and the library, so that the iOS wallet mostly adds platform code and UI.
5. **Review.** A security review of iroh and its dependencies.
