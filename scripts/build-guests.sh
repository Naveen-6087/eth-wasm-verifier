#!/usr/bin/env bash
# Builds the guest verifiers and copies them into verifiers/.
# With the pinned toolchain in guests/rust-toolchain.toml the output is
# byte-for-byte reproducible; CI rebuilds and diffs against the committed files.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Keep in sync with guests/.cargo/config.toml (RUSTFLAGS overrides it).
export RUSTFLAGS="-C link-arg=-zstack-size=262144 --remap-path-prefix=$root=/ewv --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
export CARGO_INCREMENTAL=0

cargo build --release --locked --target wasm32-unknown-unknown --manifest-path "$root/guests/Cargo.toml"

mkdir -p "$root/verifiers"
for name in sha256-preimage merkle-branch sha256-in-wasm; do
  cp "$root/guests/target/wasm32-unknown-unknown/release/${name//-/_}.wasm" "$root/verifiers/$name.wasm"
done
(cd "$root/verifiers" && sha256sum ./*.wasm)
