# Test builds: Radix Wallet and Connector Extension with Radix Connect over iroh

Community test builds of the Radix Wallet (Android) and the Radix Connector Extension (Chrome).
They are **not official Radix releases**: they are not reviewed or endorsed by RDX Works and
come with no warranty. See the [proposal](PROPOSAL.md) for what iroh adds.

> **Never import your main seed phrase into these builds.** Create a new wallet, or import a
> wallet that holds only small test amounts. Stokenet (the test network) is the best choice.

| Build | Where | File |
|---|---|---|
| Android wallet 1.22.3-iroh.2 | [genkipool/babylon-wallet-android releases](https://github.com/genkipool/babylon-wallet-android/releases/tag/tester-1.22.3-iroh.2) | `radix-wallet-iroh-test-1.22.3-iroh.2.apk` |
| Chrome extension 0.3.0 | [genkipool/connector-extension releases](https://github.com/genkipool/connector-extension/releases/tag/tester-0.3.0) | `connector-extension-iroh-test-0.3.0.zip` |

Each release lists the SHA-256 of its file and links the source branch it was built from.

## What is in them

**Wallet** (the official wallet 1.22.3 plus):
- **Radix Connect over iroh**: Settings → Preferences → Radix Connect: Automatic (the default
  in this build), WebRTC only or iroh only, and the relay. By default iroh goes through n0's
  public relays; you can set your own.
- **Badges for restricted tokens**: a transfer of a token that needs a badge shows the badge
  and attaches its proof automatically.
- Fixes: WebRTC messages no longer interleave or get lost, every data channel is read, a
  persona-only proof of ownership completes, sharing a persona without the data asked for no
  longer closes the app, transaction guarantees are inserted once, and rejecting queued dApp
  requests quickly no longer crashes.
- Linking a connector once however many times its button is tapped, and each connection gets
  the account list when it opens.

**Extension** (the official extension plus):
- **Radix Connect over iroh**: in the options, WebRTC and iroh (the default in this build: each
  message goes over iroh when it is connected, otherwise WebRTC), iroh only, or WebRTC only (the
  official way).
- The new popup and options pages, pending request cards with resend and cancel, and a
  diagnostics page.

## Install the wallet (Android)

The test wallet has its own package (`io.github.genkipool.radixwallet.iroh`) and is called
**Radix Wallet iroh test**. It installs next to the official Radix Wallet and does not touch
it. It never opens `radixwallet://` links or Radix's App Links; those keep going to the
official wallet.

1. On the phone, download the `.apk` from the wallet release above.
2. Optional, on a computer: check the file with `sha256sum <file>`; it must match the SHA-256
   in the release.
3. Open the file and allow installing from this source when Android asks.
4. Open **Radix Wallet iroh test** and create a new wallet.

Every test build is signed with the same certificate (SHA-256
`DC:A9:7F:AB:F5:AD:5B:14:37:A2:01:3A:98:CF:E0:C3:11:65:97:5A:ED:DE:F8:80:75:9C:25:82:5D:DA:C7:62`),
so a new version installs over the previous one and keeps your data. The app does not update
by itself: download each new version.

## Install the extension (Chrome)

1. Download the `.zip` from the extension release above and unzip it into a folder you keep
   (Chrome loads it from there).
2. Open `chrome://extensions` and turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose the folder. It appears as **Radix Wallet Connector (iroh
   test)**.
4. Turn off the official Radix Connector Extension while you test, so that only one extension
   answers dApps.
5. In the extension's options, the transport is already **WebRTC and iroh**; **iroh** alone is
   optional.
6. Link the test wallet: in the wallet, Settings → Linked Connectors → scan the QR code shown
   by the extension.

To update, unzip the new version into the same folder and click the reload button of the
extension in `chrome://extensions`.

## Reporting problems

Open an issue in [genkipool/radix-connect-iroh](https://github.com/genkipool/radix-connect-iroh/issues)
with what you did, what you expected and what happened (with the time). Do not include seed
phrases, passwords or the link's QR code.
