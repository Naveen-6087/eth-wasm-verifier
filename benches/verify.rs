use std::hint::black_box;
use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use eth_wasm_verifier::{Limits, Runtime};
use sha2::{Digest, Sha256};

fn module_bytes(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("verifiers").join(format!("{name}.wasm")))
        .unwrap()
}

fn load(c: &mut Criterion) {
    let rt = Runtime::new(Limits::default());
    let mut group = c.benchmark_group("load_and_validate");
    for name in ["sha256-preimage", "merkle-branch", "sha256-in-wasm"] {
        let bytes = module_bytes(name);
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &bytes, |b, bytes| {
            b.iter(|| rt.load(black_box(bytes)).unwrap());
        });
    }
    group.finish();
}

fn preimage(c: &mut Criterion) {
    let rt = Runtime::new(Limits::default());
    let host = rt.load(&module_bytes("sha256-preimage")).unwrap();
    let guest = rt.load(&module_bytes("sha256-in-wasm")).unwrap();
    let mut group = c.benchmark_group("sha256_preimage");
    for size in [64usize, 4096, 65536] {
        let data = vec![0xab; size];
        let digest = Sha256::digest(&data).to_vec();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("host_hash", size), &data, |b, data| {
            b.iter(|| assert!(rt.verify(&host, black_box(data), &digest).unwrap().outcome.is_valid()));
        });
        group.bench_with_input(BenchmarkId::new("guest_hash", size), &data, |b, data| {
            b.iter(|| assert!(rt.verify(&guest, black_box(data), &digest).unwrap().outcome.is_valid()));
        });
    }
    group.finish();
}

fn merkle(c: &mut Criterion) {
    let rt = Runtime::new(Limits::default());
    let verifier = rt.load(&module_bytes("merkle-branch")).unwrap();
    // Depth-17 branch over a synthetic tree (same shape as a Deneb blob inclusion proof).
    let leaf = [7u8; 32];
    let gindex: u64 = 221_184;
    let branch: Vec<[u8; 32]> = (0..17u8).map(|i| [i; 32]).collect();
    let mut node = leaf;
    for (level, sibling) in branch.iter().enumerate() {
        let mut h = Sha256::new();
        if gindex >> level & 1 == 1 {
            h.update(sibling);
            h.update(node);
        } else {
            h.update(node);
            h.update(sibling);
        }
        node = h.finalize().into();
    }
    let mut proof = leaf.to_vec();
    branch.iter().for_each(|s| proof.extend_from_slice(s));
    let mut public = node.to_vec();
    public.extend_from_slice(&gindex.to_le_bytes());
    c.bench_function("merkle_branch/depth_17", |b| {
        b.iter(|| assert!(rt.verify(&verifier, black_box(&proof), &public).unwrap().outcome.is_valid()));
    });
}

criterion_group!(benches, load, preimage, merkle);
criterion_main!(benches);
