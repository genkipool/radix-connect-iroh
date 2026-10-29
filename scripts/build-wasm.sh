#!/usr/bin/env bash
# Builds the browser package in js/dist (wasm-bindgen `--target web`).
#
# Requires the wasm32-unknown-unknown Rust target, a clang that can target wasm32
# (ring compiles C code), and the `wasm-bindgen` CLI at exactly the version pinned in
# crates/radix-connect-iroh-wasm/Cargo.toml:
#   cargo install wasm-bindgen-cli --version 0.2.129 --locked
# `wasm-opt` (binaryen) is used when available to shrink the module further.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-web}"
OUT="$ROOT/js/dist"
[[ "$TARGET" == "web" ]] || OUT="$ROOT/js/dist-$TARGET"
WASM_BINDGEN="${WASM_BINDGEN:-wasm-bindgen}"

PINNED="$(sed -n 's/^wasm-bindgen = "=\(.*\)"/\1/p' "$ROOT/crates/radix-connect-iroh-wasm/Cargo.toml")"
INSTALLED="$("$WASM_BINDGEN" --version | awk '{print $2}')"
if [[ "$PINNED" != "$INSTALLED" ]]; then
    echo "wasm-bindgen CLI is $INSTALLED, the crate pins $PINNED" >&2
    exit 1
fi

cargo build --manifest-path "$ROOT/Cargo.toml" --locked -p radix-connect-iroh-wasm \
    --target wasm32-unknown-unknown --profile release-wasm

rm -rf "$OUT"
"$WASM_BINDGEN" --target "$TARGET" --out-dir "$OUT" --out-name radix_connect_iroh \
    "$ROOT/target/wasm32-unknown-unknown/release-wasm/radix_connect_iroh_wasm.wasm"

# `--target nodejs` emits CommonJS, while js/package.json declares ES modules.
[[ "$TARGET" == "nodejs" ]] && echo '{ "type": "commonjs" }' >"$OUT/package.json"

if command -v wasm-opt >/dev/null; then
    wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int \
        "$OUT/radix_connect_iroh_bg.wasm" -o "$OUT/radix_connect_iroh_bg.wasm"
fi

ls -l "$OUT"
