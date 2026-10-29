#!/usr/bin/env bash
# Runs a local iroh relay for development (plain HTTP on port 3340) and prints the URLs
# to configure on each side of a link. Both URLs reach the same relay server, which is
# all that matters: the relay routes by endpoint id, not by the URL used to reach it.
#
#   Connector Extension (same machine):  http://localhost:3340
#   Wallet on a phone in the same LAN:   http://<this machine's LAN IP>:3340
#
# The wallet's native library talks to the relay itself, so Android's cleartext-traffic
# policy does not apply. Never use a plain-HTTP relay outside a trusted network: the
# messages stay end-to-end encrypted, but the relay connection itself is not.
#
# Requires `iroh-relay` (cargo install iroh-relay --features server --locked).
set -euo pipefail

LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1)}')"
echo "Connector Extension relay URL: http://localhost:3340"
echo "Wallet relay URL:              http://${LAN_IP:-<LAN IP>}:3340"
echo
exec iroh-relay --dev
