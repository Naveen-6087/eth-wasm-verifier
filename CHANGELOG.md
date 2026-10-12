# Changelog

## 0.1.0

First release on crates.io.

- Deterministic, fuel-metered WebAssembly runtime for proof verifiers, built
  on `wasmi` with strict pre-execution validation (no floats, SIMD, threads
  or non-deterministic imports; bounded memory, tables and globals).
- Verifier ABI v1: metadata, `verify(proof, public)` entry point and
  sandboxed host functions for SHA-256 and Keccak-256.
- Fuel budgets, memory page limits and call-depth limits, with identical
  results (including fuel used) across runs.
- Content-addressed verifier registry.
- Reproducibly built example verifiers: SHA-256 preimage, Merkle branch and
  SHA-256 computed in Wasm.
- `eth-wasm-verifier` CLI (feature `cli`, default): `inspect`, `list` and
  `verify`.
