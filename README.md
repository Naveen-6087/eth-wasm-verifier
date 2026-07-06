# eth-wasm-verifier

A deterministic, resource-bounded WebAssembly runtime for proof verifiers,
in Rust. Verifiers are small Wasm modules with a fixed ABI. The runtime
validates them strictly before running anything, executes each call in a
fresh sandbox under a fuel budget and memory limit, and reports a verdict
or a precise failure. For the same module, inputs and limits, every field of
the result (including fuel used) is the same on every run.

```console
$ eth-wasm-verifier verify merkle-branch --registry verifiers --proof @proof.bin --public @public.bin
{
  "fuel_limit": 50000000,
  "fuel_used": …,
  "logs": [],
  "memory_pages": 5,
  "outcome": "valid",
  "verifier": "merkle-branch"
}
```

## Why

Ethereum infrastructure keeps growing new proof systems: light-client
branches, blob inclusion proofs, zkVM receipts. Shipping each as native code
in every node, bridge or coprocessor is slow and risky. Packaging verifiers
as Wasm makes them portable and swappable, but only if running one is as
predictable as calling a native function:

- **Deterministic**: no floats, no clocks, no randomness, no ambient state.
  Each call starts from a fresh instance.
- **Bounded**: fuel caps computation, a page limit caps memory, a depth
  limit caps recursion, and inputs and logs are size-limited. A guest
  cannot hang or exhaust the host, and an unoptimized interpreter path
  cannot overflow the host's stack.
- **Checked up front**: every rule that can be checked before running is
  checked before running, and all violations are reported at once.

## Features

- **Static validation**: Wasm validation plus a deny-list of
  non-deterministic or unneeded features (floats, SIMD, multi-memory,
  memory64, start functions), an import allow-list with exact signatures,
  required exports with exact types, a memory ceiling, a module size limit,
  and metadata checks.
- **Metered execution** on the [wasmi](https://github.com/wasmi-labs/wasmi)
  interpreter: per-instruction fuel plus explicit fuel costs for host
  functions, so hashing 64 KiB on the host is still paid for.
- **Precise outcomes**: `valid`, `invalid`, `rejected(code)`, `out_of_fuel`,
  `stack_overflow`, `memory_limit`, `abi_mismatch`, `host_fault` and `trap`,
  plus fuel used, memory pages and guest logs.
- **Host crypto**: SHA-256 and Keccak-256 as metered host functions.
- **Registry**: load a directory of verifiers, address them by name, and
  identify each by the SHA-256 of its bytes.
- **Three real verifiers** (`verifiers/`), built reproducibly from
  `guests/`:
  - `merkle-branch`: SSZ Merkle branch for a generalized index
    (consensus-specs `is_valid_merkle_branch`). It verifies the official
    Deneb blob KZG commitment inclusion proof.
  - `sha256-preimage`: knowledge of a SHA-256 preimage, hashed on the host.
  - `sha256-in-wasm`: the same statement, hashed inside the guest, to
    compare metering.
- **CLI**: `inspect`, `list` and `verify`, with JSON output and exit codes.

## The verifier ABI (version 1)

A verifier module:

| Must export | Type | Meaning |
|-------------|------|---------|
| `memory` | memory | its linear memory |
| `ewv_abi_version` | `() -> i32` | returns `1` |
| `verify` | `() -> i32` | `0` valid, `1` invalid, anything else is a verifier-defined rejection code |

It may import only these functions from module `ewv`:

| Import | Signature | Fuel |
|--------|-----------|------|
| `input_len(kind) -> len` | `(i32) -> i32` | 20 |
| `read_input(kind, offset, dst, len) -> copied` | `(i32, i32, i32, i32) -> i32` | 20 + ⌈len/8⌉ |
| `sha256(src, len, dst)` | `(i32, i32, i32)` | 120 + 12·⌈len/32⌉ |
| `keccak256(src, len, dst)` | `(i32, i32, i32)` | 120 + 12·⌈len/32⌉ |
| `log(ptr, len)` | `(i32, i32)` | 20 + len |

`kind` is `0` for the proof and `1` for the public input. An unknown kind or
an offset past the end returns `-1`. Pointers outside guest memory and
logging past the log limit end the call with `host_fault`. Optional
metadata goes in a custom section `ewv.meta` as JSON:
`{"name": "...", "version": "...", "description": "..."}`.

Writing one in Rust takes about 20 lines with the helper crate in
`guests/abi`:

```rust
#![no_std]
use ewv_guest::{INPUT_PROOF, INPUT_PUBLIC, Verdict};

fn check() -> Verdict {
    let mut digest = [0u8; 32];
    if ewv_guest::read_exact(INPUT_PUBLIC, &mut digest).is_none() {
        return Verdict::Reject(2);
    }
    let mut buf = [0u8; 65536];
    let Some(preimage) = ewv_guest::read_into(INPUT_PROOF, &mut buf) else { return Verdict::Reject(3) };
    if ewv_guest::sha256(preimage) == digest { Verdict::Valid } else { Verdict::Invalid }
}

ewv_guest::verifier!(check, r#"{"name":"sha256-preimage","version":"0.1.0"}"#);
```

## Usage

```
eth-wasm-verifier [--fuel N] [--max-memory-pages P] [--max-call-depth D] <command>

  inspect <module.wasm>                        validate; print id, metadata, imports, exports
  list <dir>                                   list a directory of verifiers
  verify <module.wasm | name --registry dir>   run a verifier
         --proof <0x… | @file> --public <0x… | @file>
```

Exit status: `0` valid; `1` invalid, rejected, or `inspect` found
violations; `2` usage or load error; `3` the call failed (out of fuel,
trap, host fault…).

Library:

```rust
use eth_wasm_verifier::{Limits, Outcome, Runtime};

let runtime = Runtime::new(Limits { fuel: 1_000_000, ..Limits::default() });
let verifier = runtime.load(&wasm_bytes)?;           // validation errors list every violation
let run = runtime.verify(&verifier, &proof, &public)?;
match run.outcome {
    Outcome::Valid => println!("valid, {} fuel", run.fuel_used),
    other => println!("{other}"),
}
```

## Architecture

```
            CLI (inspect | list | verify)
                       |
                    Registry  ── directory of *.wasm, by name / sha256 id
                       |
   Runtime ── load: size check → wasmi validation (eager, floats/SIMD/start off)
      |                → ABI check (imports, exports, memory, ewv.meta)
      |
      └── verify: dedicated 8 MiB thread → fresh Store (fuel, StoreLimits)
                   → instantiate → ewv_abi_version → verify → Outcome
                                         │
                             host: input_len, read_input, sha256, keccak256, log
                                   (bounds-checked, fuel-charged)
```

| Module | Responsibility |
|--------|----------------|
| `abi` | Names, signatures, verdict codes and host fuel costs |
| `limits` | Resource bounds (`Limits::default()`: 50M fuel, 64 pages, depth 1024, 4 MiB modules, 1 MiB inputs, 4 KiB logs) |
| `validate` | ABI checks and `ewv.meta` parsing |
| `host` | Host functions, bounds checks, fuel charging, `HostFault` |
| `runtime` | Engine configuration, loading, execution and outcome classification |
| `registry` | Named verifier collections |

### Design decisions

- **An interpreter, not a JIT.** wasmi gives exact, platform-independent
  fuel accounting and no code generation to harden.
- **Loop dispatch** (`portable-dispatch`). wasmi's default tail-call
  dispatch only stays stack-bounded when the compiler eliminates the tail
  calls. In unoptimized builds, a long-running guest overflowed even a
  64 MiB native stack. The loop backend's native stack use doesn't depend
  on how many instructions run; a test runs a million-iteration guest loop
  in a debug build.
- **A fresh instance and a dedicated thread per call.** Globals and memory
  never leak between calls, and guest execution can't use the caller's
  stack. Verifiers loaded by one `Runtime` are rejected by another with an
  error, instead of the panic wasmi would raise.
- **Pull-based inputs.** The guest asks for bytes with `read_input`, so the
  host never has to trust a guest allocator or guest-provided buffers
  beyond bounds-checked ranges.
- **Fuel is charged per basic block.** When the next block does not fit,
  the call stops with up to one block's worth of fuel unused. `fuel_used`
  never exceeds the limit and is identical across runs. A property test
  checks this.
- **Reproducible guests.** `guests/` pins Rust 1.94.1 and builds with LTO,
  `panic=abort`, path remapping and a 256 KiB shadow stack. The committed
  modules contain no paths and rebuild byte for byte; CI diffs them. The
  smaller stack (rustc defaults to 1 MiB) cut the cost of a call by about
  70% (17 → 5 initial pages).

## Testing

```sh
cargo test                       # 39 tests
bash scripts/build-guests.sh     # rebuild verifiers/ (pinned toolchain, reproducible)
```

| Suite | Checks |
|-------|--------|
| `tests/validation.rs` (9) | Accepts a minimal module; rejects non-Wasm, oversized modules, floats (instructions and signatures), SIMD, start functions, unknown or mistyped imports, missing or mistyped exports, oversized memory and bad metadata, reporting every violation |
| `tests/execution.rs` (14) | Every verdict; out of fuel (Wasm loops and inside host calls); guest stack overflow; memory-growth cap; traps (unreachable, out-of-bounds, divide by zero); ABI mismatch; input reads and limits; host faults on bad pointers; SHA-256/Keccak-256 known digests; bounded logs; per-byte host metering; fresh instance per call; determinism across runs and runtimes; a million-iteration guest loop with flat host stack |
| `tests/verifiers.rs` (7) | `merkle-branch` accepts the **official Deneb blob KZG commitment inclusion proof** (consensus-spec-tests, generalized index 221184, 17-node branch) and rejects every tampered byte, a wrong generalized index and malformed inputs; preimage verifiers agree, including 64 KiB edge cases; host hashing is cheaper than guest hashing; verifiers are bound to their runtime; registry loading and duplicate detection |
| `tests/properties.rs` (proptest, 5) | Verdicts match native SHA-256; fuel is monotone (enough fuel gives the identical result, less gives out-of-fuel within the limit, deterministically); identical inputs give identical executions; arbitrary bytes never crash the loader; randomly mutated modules either fail to load or run to a defined outcome |
| `tests/cli.rs` (4) | `inspect`, `list`, `verify`, file inputs, and every exit code |

## Benchmarks

`cargo bench --bench verify`. One local sample on an Intel Core i5-12500H
(Windows, release build, Criterion median). Timings are indicative; fuel is
exact:

| Call | Time | Fuel |
|------|------|------|
| Load and validate `sha256-preimage` (889 B) / `sha256-in-wasm` (5.4 KB) | 35 µs / 229 µs | – |
| `sha256-preimage`, 64 B / 4 KiB / 64 KiB preimage (host hash) | 170 µs / 172 µs / 264 µs | 2,204 / 4,220 / 34,940 |
| `sha256-in-wasm`, 64 B / 4 KiB / 64 KiB preimage (guest hash) | 225 µs / 959 µs / 12.1 ms | 21,065 / 487,517 / 7,595,357 |
| `merkle-branch`, depth 17 | 177 µs | – |

Per-call overhead (thread, fresh instance, memory) is about 170 µs.
Interpreted hashing costs about 200× more fuel than the host function, which
is why the ABI exposes hashes as host functions.

## Security considerations

- The runtime defends the host against the guest: computation, memory,
  recursion, input, log and module sizes are all bounded, and every host
  function bounds-checks guest pointers. A verifier's *verdict* is only as
  trustworthy as the verifier: review or pin modules by their SHA-256 id.
- Determinism assumes the same runtime version and the same `Limits`.
  Fuel costs are part of the ABI version and may change in future versions.
- wasmi and this crate have not been audited for this use.

## Limitations

- Interpreted execution: heavy cryptography (pairings, STARK verification)
  should be exposed as host functions rather than run in the guest, as with
  the hashes.
- Only SHA-256 and Keccak-256 are provided. There are no precompiles for
  BLS12-381, BN254 or secp256k1 yet.
- One call per thread spawn. A pooled executor would cut per-call overhead
  for high throughput.
- The library needs Rust 1.86 (wasmi). Running the test suite needs 1.88
  (the `wat` dev-dependency).

## Development

```sh
cargo fmt --check && (cd guests && cargo fmt --check)
cargo clippy --all-targets -- -D warnings
(cd guests && cargo clippy --release --target wasm32-unknown-unknown -- -D warnings)
cargo test
cargo +1.86 check --lib --bins
cargo audit && cargo audit --file guests/Cargo.lock
```

## License

MIT, see [LICENSE](LICENSE). `testdata/deneb_blob_commitment_proof.json` is
taken from the Ethereum consensus-spec-tests (CC0).
