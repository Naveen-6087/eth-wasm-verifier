#![no_std]

use ewv_guest::{INPUT_PROOF, INPUT_PUBLIC, Verdict};

const MALFORMED_PUBLIC: i32 = 2;
const MALFORMED_PROOF: i32 = 3;
const MAX_DEPTH: usize = 63;

// SSZ-style Merkle branch (consensus-specs `is_valid_merkle_branch` with a
// generalized index).
// Public input: root (32) || generalized index (u64 little-endian).
// Proof: leaf (32) || sibling nodes, leaf level first (32 each, one per level).
fn check() -> Verdict {
    let mut public = [0u8; 40];
    if ewv_guest::read_exact(INPUT_PUBLIC, &mut public).is_none() {
        return Verdict::Reject(MALFORMED_PUBLIC);
    }
    let root: [u8; 32] = public[..32].try_into().unwrap();
    let gindex = u64::from_le_bytes(public[32..].try_into().unwrap());
    if gindex == 0 {
        return Verdict::Reject(MALFORMED_PUBLIC);
    }
    let depth = (63 - gindex.leading_zeros()) as usize;

    let mut buf = [0u8; 32 * (MAX_DEPTH + 1)];
    let proof = match ewv_guest::read_into(INPUT_PROOF, &mut buf) {
        Some(p) if p.len() == 32 * (depth + 1) => p,
        _ => return Verdict::Reject(MALFORMED_PROOF),
    };

    let mut node: [u8; 32] = proof[..32].try_into().unwrap();
    let mut pair = [0u8; 64];
    for (level, sibling) in proof[32..].chunks_exact(32).enumerate() {
        if gindex >> level & 1 == 1 {
            pair[..32].copy_from_slice(sibling);
            pair[32..].copy_from_slice(&node);
        } else {
            pair[..32].copy_from_slice(&node);
            pair[32..].copy_from_slice(sibling);
        }
        node = ewv_guest::sha256(&pair);
    }
    if node == root { Verdict::Valid } else { Verdict::Invalid }
}

ewv_guest::verifier!(
    check,
    r#"{"name":"merkle-branch","version":"0.1.0","description":"SSZ Merkle branch for a generalized index"}"#
);
