#![no_std]

use ewv_guest::{INPUT_PROOF, INPUT_PUBLIC, Verdict};

const MAX_PREIMAGE: usize = 64 * 1024;
const MALFORMED_DIGEST: i32 = 2;
const PREIMAGE_TOO_LARGE: i32 = 3;

// Proof: the preimage. Public input: its 32-byte SHA-256 digest.
fn check() -> Verdict {
    let mut digest = [0u8; 32];
    if ewv_guest::read_exact(INPUT_PUBLIC, &mut digest).is_none() {
        return Verdict::Reject(MALFORMED_DIGEST);
    }
    let mut buf = [0u8; MAX_PREIMAGE];
    let Some(preimage) = ewv_guest::read_into(INPUT_PROOF, &mut buf) else {
        return Verdict::Reject(PREIMAGE_TOO_LARGE);
    };
    if ewv_guest::sha256(preimage) == digest { Verdict::Valid } else { Verdict::Invalid }
}

ewv_guest::verifier!(
    check,
    r#"{"name":"sha256-preimage","version":"0.1.0","description":"SHA-256 preimage knowledge (host hash)"}"#
);
