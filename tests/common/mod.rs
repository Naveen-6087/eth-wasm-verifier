#![allow(dead_code)]

use std::path::PathBuf;

use eth_wasm_verifier::{Limits, Runtime, Verifier};

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn runtime() -> Runtime {
    Runtime::new(Limits::default())
}

pub fn builtin(rt: &Runtime, name: &str) -> Verifier {
    rt.load_file(&root().join("verifiers").join(format!("{name}.wasm"))).expect("built-in verifier loads")
}

/// A verifier module in WAT: all host imports, one page of memory, ABI
/// version `abi`, `verify` returning whatever `body` leaves on the stack.
pub fn module(body: &str, extra: &str) -> Vec<u8> {
    module_with_abi(body, extra, 1)
}

pub fn module_with_abi(body: &str, extra: &str, abi: i32) -> Vec<u8> {
    let text = format!(
        r#"(module
            (import "ewv" "input_len" (func $input_len (param i32) (result i32)))
            (import "ewv" "read_input" (func $read_input (param i32 i32 i32 i32) (result i32)))
            (import "ewv" "sha256" (func $sha256 (param i32 i32 i32)))
            (import "ewv" "keccak256" (func $keccak256 (param i32 i32 i32)))
            (import "ewv" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (func (export "ewv_abi_version") (result i32) i32.const {abi})
            (func (export "verify") (result i32) {body})
            {extra})"#
    );
    wat::parse_str(text).expect("valid WAT")
}

pub fn wasm(text: &str) -> Vec<u8> {
    wat::parse_str(text).expect("valid WAT")
}

pub fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
