#!/usr/bin/env bash
# Cross-implementation end-to-end test: the wasm build (as the Connector Extension, run
# by Node) and the native build (as the wallet) talk through a local `iroh-relay --dev`.
# Requires: node >= 22, `iroh-relay` (cargo install iroh-relay --features server) and
# the wasm-bindgen CLI (see build-wasm.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELAY_URL="${RELAY_URL:-http://localhost:3340}"
export RADIX_CONNECT_PASSWORD="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

"$ROOT/scripts/build-wasm.sh" nodejs >/dev/null
cargo build --manifest-path "$ROOT/Cargo.toml" --locked -p radix-connect-iroh --example peer 2>/dev/null

# RELAY_URL=https://... runs the test through a public relay instead of a local one.
if [[ "$RELAY_URL" == "http://localhost:3340" ]]; then
    iroh-relay --dev >"$WORK/relay.log" 2>&1 &
    for _ in $(seq 50); do curl -s -o /dev/null "$RELAY_URL" && break; sleep 0.1; done
fi

node "$ROOT/js/test/e2e-connector.mjs" "$RELAY_URL" >"$WORK/connector.out" 2>"$WORK/connector.err" &
CONNECTOR=$!
sleep 1

# The wallet sends one request once connected and prints the answer.
coproc WALLET { "$ROOT/target/debug/examples/peer" wallet "$RELAY_URL" 2>"$WORK/wallet.err"; }
while read -r -t 30 line <&"${WALLET[0]}"; do
    echo "wallet: $line"
    case "$line" in
        "state Connected") echo '{"interactionId":"e2e","items":{"discriminator":"ping"}}' >&"${WALLET[1]}" ;;
        message*wasm-connector*) break ;;
    esac
done

wait "$CONNECTOR"
cat "$WORK/connector.out" | sed 's/^/connector: /'
grep -q '"from":"wasm-connector"' <<<"$line" && grep -q answered "$WORK/connector.out" && echo "E2E OK"
