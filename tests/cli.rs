#![cfg(feature = "cli")]

mod common;

use std::process::{Command, Output};

use common::root;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_eth-wasm-verifier")).args(args).current_dir(root()).output().unwrap()
}

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
}

fn hex(bytes: &[u8]) -> String {
    format!("0x{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

#[test]
fn inspect_and_list() {
    let out = run(&["inspect", "verifiers/merkle-branch.wasm"]);
    assert!(out.status.success());
    let v = json(&out);
    assert_eq!(v["valid"], true);
    assert_eq!(v["meta"]["name"], "merkle-branch");
    assert_eq!(v["id"].as_str().unwrap().len(), 64);

    let out = run(&["list", "verifiers"]);
    let names: Vec<String> =
        json(&out).as_array().unwrap().iter().map(|v| v["name"].as_str().unwrap().to_owned()).collect();
    assert_eq!(names, ["merkle-branch", "sha256-in-wasm", "sha256-preimage"]);
}

#[test]
fn inspect_reports_violations() {
    let path = std::env::temp_dir().join(format!("ewv-bad-{}.wasm", std::process::id()));
    std::fs::write(&path, wat::parse_str("(module (memory (export \"memory\") 1))").unwrap()).unwrap();
    let out = run(&["inspect", &path.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(1));
    let v = json(&out);
    assert_eq!(v["valid"], false);
    assert_eq!(v["violations"].as_array().unwrap().len(), 2);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn verify_exit_codes() {
    let digest = Sha256::digest(b"abc");
    let ok =
        run(&["verify", "verifiers/sha256-preimage.wasm", "--proof", "0x616263", "--public", &hex(&digest)]);
    assert_eq!(ok.status.code(), Some(0));
    let v = json(&ok);
    assert_eq!(v["outcome"], "valid");
    assert_eq!(v["verifier"], "sha256-preimage");

    let bad = run(&[
        "verify",
        "sha256-preimage",
        "--registry",
        "verifiers",
        "--proof",
        "0x616264",
        "--public",
        &hex(&digest),
    ]);
    assert_eq!(bad.status.code(), Some(1));
    assert_eq!(json(&bad)["outcome"], "invalid");

    let rejected = run(&["verify", "sha256-preimage", "--registry", "verifiers", "--public", "0x00"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(json(&rejected)["detail"], 2);

    let starved = run(&[
        "verify",
        "sha256-in-wasm",
        "--registry",
        "verifiers",
        "--fuel",
        "100",
        "--proof",
        "0x616263",
        "--public",
        &hex(&digest),
    ]);
    assert_eq!(starved.status.code(), Some(3));
    assert_eq!(json(&starved)["outcome"], "out_of_fuel");
}

#[test]
fn file_inputs_and_usage_errors() {
    let proof = std::env::temp_dir().join(format!("ewv-proof-{}.bin", std::process::id()));
    std::fs::write(&proof, b"abc").unwrap();
    let digest = Sha256::digest(b"abc");
    let out = run(&[
        "verify",
        "verifiers/sha256-in-wasm.wasm",
        "--proof",
        &format!("@{}", proof.display()),
        "--public",
        &hex(&digest),
    ]);
    assert_eq!(out.status.code(), Some(0));
    std::fs::remove_file(proof).unwrap();

    for args in [
        vec!["verify", "verifiers/sha256-preimage.wasm", "--proof", "abc"],
        vec!["verify", "verifiers/sha256-preimage.wasm", "--proof", "0x123"],
        vec!["verify", "missing.wasm"],
        vec!["verify", "nope", "--registry", "verifiers"],
        vec!["list", "does-not-exist"],
    ] {
        assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
    }
}
