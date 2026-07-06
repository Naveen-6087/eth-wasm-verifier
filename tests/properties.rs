mod common;

use common::{builtin, module, runtime};
use eth_wasm_verifier::{Outcome, Runtime};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn shared() -> &'static (Runtime, eth_wasm_verifier::Verifier, eth_wasm_verifier::Verifier) {
    static CELL: std::sync::OnceLock<(Runtime, eth_wasm_verifier::Verifier, eth_wasm_verifier::Verifier)> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        let rt = runtime();
        let host = builtin(&rt, "sha256-preimage");
        let guest = builtin(&rt, "sha256-in-wasm");
        (rt, host, guest)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn preimage_verdict_matches_native_sha256(preimage in prop::collection::vec(any::<u8>(), 0..2048),
                                               other in prop::collection::vec(any::<u8>(), 32),
                                               honest in any::<bool>()) {
        let (rt, host, guest) = shared();
        let digest = if honest { Sha256::digest(&preimage).to_vec() } else { other.clone() };
        let expected = if Sha256::digest(&preimage)[..] == digest[..] { Outcome::Valid } else { Outcome::Invalid };
        prop_assert_eq!(rt.verify(host, &preimage, &digest).unwrap().outcome, expected.clone());
        prop_assert_eq!(rt.verify(guest, &preimage, &digest).unwrap().outcome, expected);
    }

    #[test]
    fn fuel_is_monotone(preimage in prop::collection::vec(any::<u8>(), 0..512), fraction in 0.0f64..1.5) {
        let (rt, host, _) = shared();
        let digest = Sha256::digest(&preimage).to_vec();
        let full = rt.verify(host, &preimage, &digest).unwrap();
        let fuel = ((full.fuel_used as f64) * fraction) as u64;
        let limited = rt.verify_with_fuel(host, &preimage, &digest, fuel).unwrap();
        if fuel >= full.fuel_used {
            prop_assert_eq!(&limited.outcome, &full.outcome);
            prop_assert_eq!(limited.fuel_used, full.fuel_used);
        } else {
            // Fuel is charged per basic block before it runs, so execution can
            // stop with some fuel left over; it never uses more than the limit.
            prop_assert_eq!(&limited.outcome, &Outcome::OutOfFuel);
            prop_assert!(limited.fuel_used <= fuel);
            let again = rt.verify_with_fuel(host, &preimage, &digest, fuel).unwrap();
            prop_assert_eq!(again, limited);
        }
    }

    #[test]
    fn same_inputs_same_execution(proof in prop::collection::vec(any::<u8>(), 0..256),
                                  public in prop::collection::vec(any::<u8>(), 0..64)) {
        let (rt, host, guest) = shared();
        for v in [host, guest] {
            let a = rt.verify(v, &proof, &public).unwrap();
            let b = rt.verify(v, &proof, &public).unwrap();
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn arbitrary_bytes_never_crash_the_loader(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = runtime().load(&bytes);
    }

    #[test]
    fn mutated_modules_load_or_fail_cleanly(at in any::<prop::sample::Index>(), byte in any::<u8>(),
                                            input in prop::collection::vec(any::<u8>(), 0..64)) {
        let rt = runtime();
        let mut wasm = module("(call $sha256 (i32.const 0) (call $input_len (i32.const 0)) (i32.const 64)) i32.const 0", "");
        let i = at.index(wasm.len());
        wasm[i] = byte;
        if let Ok(v) = rt.load(&wasm) {
            // Whatever loads must run to a defined outcome without panicking.
            let e = rt.verify(&v, &input, &input).unwrap();
            prop_assert!(e.fuel_used <= e.fuel_limit);
        }
    }
}
