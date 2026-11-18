# Radix Connect over iroh: test builds

Community test builds of the Radix Wallet (Android) and the Radix Connector Extension (Chrome)
with **Radix Connect over iroh**, a second way for them to connect next to WebRTC. They are
**not official Radix releases**. See the [proposal](PROPOSAL.md)
for what iroh adds.

> **Never import your main seed phrase into these builds.** Create a new wallet, or import a
> wallet that holds only small test amounts. Stokenet (the test network) is the best choice.
>
> These builds are not reviewed or endorsed by RDX Works and come with no warranty.

## Android wallet

The test wallet has its own package (`io.github.genkipool.radixwallet.iroh`) and is called
**Radix Wallet iroh test** (version 1.22.3-iroh.1). It installs next to the official Radix Wallet and does not touch it.
It never opens `radixwallet://` links or Radix's App Links; those keep going to the official
wallet.

1. Download `radix-wallet-iroh-test-1.22.3-iroh.1.apk` from the [test release](https://github.com/genkipool/radix-connect-iroh/releases/tag/test-builds-1).
2. Check the file (optional but recommended):
   ```sh
   sha256sum radix-wallet-iroh-test-1.22.3-iroh.1.apk
   ```
   The result must match the SHA-256 listed in `SHA256SUMS.txt` in the release.
3. On the phone, open the file and allow installing from this source when Android asks.
4. Open **Radix Wallet iroh test** and create a new wallet.

Signing certificate SHA-256 of every test build:
`DC:A9:7F:AB:F5:AD:5B:14:37:A2:01:3A:98:CF:E0:C3:11:65:97:5A:ED:DE:F8:80:75:9C:25:82:5D:DA:C7:62`.
Updates are signed with the same certificate, so they install over the previous version and
keep your data.

In this build the Radix Connect setting is **Automatic** by default: WebRTC, plus iroh with
extensions that support it (Settings → Preferences → Radix Connect).

## Chrome extension

1. Download `connector-extension-iroh-test-1.zip` from the [test release](https://github.com/genkipool/radix-connect-iroh/releases/tag/test-builds-1) and check its SHA-256
   as above.
2. Unzip it into a folder you keep (Chrome loads it from there).
3. Open `chrome://extensions`, turn on **Developer mode** (top right), click **Load unpacked**
   and choose the folder.
4. Turn off the official Radix Connector Extension while you test, so that only one extension
   answers dApps.
5. In the extension's options, set the transport to **iroh** or **WebRTC and iroh**.
6. Link the test wallet: in the wallet, Settings → Linked Connectors → scan the QR code shown
   by the extension.

To update, download the new ZIP, replace the folder's contents, and click the reload button of
the extension in `chrome://extensions`.

## Reporting problems

Open an issue in [genkipool/radix-connect-iroh](https://github.com/genkipool/radix-connect-iroh/issues).
Include:
- what you did;
- what you expected;
- what happened, with the time.

Do not include seed phrases, passwords or the link's QR code.
