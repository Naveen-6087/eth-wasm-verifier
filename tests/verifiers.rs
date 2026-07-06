mod common;

use common::{builtin, hex, root, runtime};
use eth_wasm_verifier::{Outcome, Registry, abi};
use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

#[test]
fn sha256_preimage_verdicts() {
    let rt = runtime();
    for name in ["sha256-preimage", "sha256-in-wasm"] {
        let v = builtin(&rt, name);
        let preimage = b"the quick brown fox".to_vec();
        let digest = sha256(&preimage);
        assert_eq!(rt.verify(&v, &preimage, &digest).unwrap().outcome, Outcome::Valid, "{name}");
        assert_eq!(rt.verify(&v, b"other", &digest).unwrap().outcome, Outcome::Invalid, "{name}");
        assert_eq!(
            rt.verify(&v, b"", &sha256(b"")).unwrap().outcome,
            Outcome::Valid,
            "{name}: empty preimage"
        );
        assert_eq!(rt.verify(&v, &preimage, &digest[..31]).unwrap().outcome, Outcome::Rejected(2), "{name}");
        let huge = vec![7u8; 64 * 1024 + 1];
        assert_eq!(rt.verify(&v, &huge, &sha256(&huge)).unwrap().outcome, Outcome::Rejected(3), "{name}");
        let max = vec![7u8; 64 * 1024];
        assert_eq!(rt.verify(&v, &max, &sha256(&max)).unwrap().outcome, Outcome::Valid, "{name}: 64 KiB");
    }
}

#[test]
fn host_hashing_is_cheaper_than_guest_hashing() {
    let rt = runtime();
    let preimage = vec![1u8; 4096];
    let digest = sha256(&preimage);
    let host = rt.verify(&builtin(&rt, "sha256-preimage"), &preimage, &digest).unwrap();
    let guest = rt.verify(&builtin(&rt, "sha256-in-wasm"), &preimage, &digest).unwrap();
    assert!(host.outcome.is_valid() && guest.outcome.is_valid());
    assert!(guest.fuel_used > 5 * host.fuel_used, "host {} vs guest {}", host.fuel_used, guest.fuel_used);
}

struct Vector {
    root: Vec<u8>,
    gindex: u64,
    leaf: Vec<u8>,
    branch: Vec<Vec<u8>>,
}

fn deneb_vector() -> Vector {
    let text = std::fs::read_to_string(root().join("testdata/deneb_blob_commitment_proof.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    Vector {
        root: hex(v["root"].as_str().unwrap()),
        gindex: v["gindex"].as_u64().unwrap(),
        leaf: hex(v["leaf"].as_str().unwrap()),
        branch: v["branch"].as_array().unwrap().iter().map(|h| hex(h.as_str().unwrap())).collect(),
    }
}

fn merkle_inputs(v: &Vector) -> (Vec<u8>, Vec<u8>) {
    let mut proof = v.leaf.clone();
    for node in &v.branch {
        proof.extend_from_slice(node);
    }
    let mut public = v.root.clone();
    public.extend_from_slice(&v.gindex.to_le_bytes());
    (proof, public)
}

#[test]
fn merkle_branch_accepts_official_deneb_proof() {
    let rt = runtime();
    let verifier = builtin(&rt, "merkle-branch");
    let v = deneb_vector();
    assert_eq!(v.branch.len(), 17);
    let (proof, public) = merkle_inputs(&v);
    let e = rt.verify(&verifier, &proof, &public).unwrap();
    assert_eq!(e.outcome, Outcome::Valid, "{e:?}");

    for i in [0, 16 * 32 + 5, proof.len() - 1] {
        let mut bad = proof.clone();
        bad[i] ^= 1;
        assert_eq!(rt.verify(&verifier, &bad, &public).unwrap().outcome, Outcome::Invalid, "byte {i}");
    }
    let mut wrong_index = public.clone();
    wrong_index[32] ^= 1;
    assert_eq!(rt.verify(&verifier, &proof, &wrong_index).unwrap().outcome, Outcome::Invalid);
}

#[test]
fn merkle_branch_rejects_malformed_inputs() {
    let rt = runtime();
    let verifier = builtin(&rt, "merkle-branch");
    let (proof, public) = merkle_inputs(&deneb_vector());
    assert_eq!(
        rt.verify(&verifier, &proof[..proof.len() - 32], &public).unwrap().outcome,
        Outcome::Rejected(3)
    );
    assert_eq!(rt.verify(&verifier, &proof, &public[..39]).unwrap().outcome, Outcome::Rejected(2));
    let mut zero_gindex = public.clone();
    zero_gindex[32..].fill(0);
    assert_eq!(rt.verify(&verifier, &proof, &zero_gindex).unwrap().outcome, Outcome::Rejected(2));
    // gindex 1: the leaf is the root, with an empty branch.
    let mut root_only = proof[..32].to_vec();
    let mut public1 = proof[..32].to_vec();
    public1.extend_from_slice(&1u64.to_le_bytes());
    assert_eq!(rt.verify(&verifier, &root_only, &public1).unwrap().outcome, Outcome::Valid);
    root_only[0] ^= 1;
    assert_eq!(rt.verify(&verifier, &root_only, &public1).unwrap().outcome, Outcome::Invalid);
}

#[test]
fn builtin_modules_declare_the_expected_interface() {
    let rt = runtime();
    for name in ["sha256-preimage", "sha256-in-wasm", "merkle-branch"] {
        let v = builtin(&rt, name);
        assert_eq!(v.name(), Some(name));
        assert!(v.exports().iter().any(|e| e == abi::EXPORT_VERIFY));
        assert!(v.imports().iter().all(|i| i.starts_with("ewv.")));
    }
    assert!(
        builtin(&rt, "sha256-in-wasm").imports().iter().all(|i| i != "ewv.sha256"),
        "hashes in the guest"
    );
}

#[test]
fn verifiers_are_bound_to_their_runtime() {
    let a = runtime();
    let b = runtime();
    let v = builtin(&a, "sha256-preimage");
    assert!(matches!(b.verify(&v, b"", b""), Err(eth_wasm_verifier::InputError::ForeignVerifier)));
}

#[test]
fn registry_loads_the_verifiers_directory() {
    let rt = runtime();
    let registry = Registry::load_dir(&rt, &root().join("verifiers")).unwrap();
    assert_eq!(
        registry.names().collect::<Vec<_>>(),
        vec!["merkle-branch", "sha256-in-wasm", "sha256-preimage"]
    );
    assert!(registry.get("missing").is_none());

    let dir = std::env::temp_dir().join(format!("ewv-registry-dup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let module = std::fs::read(root().join("verifiers/merkle-branch.wasm")).unwrap();
    std::fs::write(dir.join("a.wasm"), &module).unwrap();
    std::fs::write(dir.join("b.wasm"), &module).unwrap();
    let err = Registry::load_dir(&rt, &dir).unwrap_err();
    assert!(err.to_string().contains("merkle-branch"), "{err}");
    std::fs::write(dir.join("b.wasm"), b"junk").unwrap();
    assert!(Registry::load_dir(&rt, &dir).unwrap_err().to_string().contains("b.wasm"));
    std::fs::remove_dir_all(dir).unwrap();
}
