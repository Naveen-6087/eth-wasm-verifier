mod common;

use common::{module, module_with_abi, runtime};
use eth_wasm_verifier::{InputError, Limits, Outcome, Runtime};

fn run(body: &str, extra: &str) -> eth_wasm_verifier::Execution {
    run_with(&runtime(), body, extra, b"proof", b"public")
}

fn run_with(
    rt: &Runtime,
    body: &str,
    extra: &str,
    proof: &[u8],
    public: &[u8],
) -> eth_wasm_verifier::Execution {
    let v = rt.load(&module(body, extra)).unwrap();
    rt.verify(&v, proof, public).unwrap()
}

#[test]
fn verdicts() {
    assert_eq!(run("i32.const 0", "").outcome, Outcome::Valid);
    assert_eq!(run("i32.const 1", "").outcome, Outcome::Invalid);
    assert_eq!(run("i32.const 42", "").outcome, Outcome::Rejected(42));
    assert_eq!(run("i32.const -1", "").outcome, Outcome::Rejected(-1));
}

#[test]
fn infinite_loop_runs_out_of_fuel() {
    let rt = Runtime::new(Limits { fuel: 100_000, ..Limits::default() });
    let e = run_with(&rt, "(loop $l br $l) i32.const 0", "", b"", b"");
    assert_eq!(e.outcome, Outcome::OutOfFuel);
    assert!(e.fuel_used <= 100_000 && e.fuel_used > 99_000, "{}", e.fuel_used);
}

#[test]
fn long_running_guests_do_not_grow_the_host_stack() {
    // ~3 million interpreted instructions; host stack use must stay flat.
    let body = r#"
        (local $i i32)
        (loop $l
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $l (i32.lt_u (local.get $i) (i32.const 1000000))))
        i32.const 0"#;
    let e = run(body, "");
    assert_eq!(e.outcome, Outcome::Valid);
    assert!(e.fuel_used > 1_000_000);
}

#[test]
fn unbounded_recursion_overflows_the_guest_stack() {
    let e = run("call $rec", "(func $rec (result i32) call $rec)");
    assert_eq!(e.outcome, Outcome::StackOverflow);
}

#[test]
fn memory_growth_is_capped() {
    let rt = Runtime::new(Limits { max_memory_pages: 4, ..Limits::default() });
    let ok = run_with(&rt, "(drop (memory.grow (i32.const 3))) i32.const 0", "", b"", b"");
    assert_eq!(ok.outcome, Outcome::Valid);
    assert_eq!(ok.memory_pages, 4);
    let too_much = run_with(&rt, "(drop (memory.grow (i32.const 4))) i32.const 0", "", b"", b"");
    assert_eq!(too_much.outcome, Outcome::MemoryLimit);
}

#[test]
fn wasm_traps_are_reported() {
    let unreachable = run("unreachable", "");
    assert!(matches!(&unreachable.outcome, Outcome::Trap(m) if m.contains("unreachable")), "{unreachable:?}");
    let oob = run("(i32.load (i32.const 70000))", "");
    assert!(matches!(&oob.outcome, Outcome::Trap(m) if m.contains("out of bounds")), "{oob:?}");
    let div = run("(i32.div_u (i32.const 1) (i32.const 0))", "");
    assert!(matches!(div.outcome, Outcome::Trap(_)));
}

#[test]
fn abi_version_is_checked() {
    let rt = runtime();
    let v = rt.load(&module_with_abi("i32.const 0", "", 2)).unwrap();
    assert_eq!(rt.verify(&v, b"", b"").unwrap().outcome, Outcome::AbiMismatch(2));
}

#[test]
fn inputs_are_readable_and_bounded() {
    // Returns the proof length if public input is exactly "pub" (read via read_input).
    let body = r#"
        (if (i32.ne (call $input_len (i32.const 1)) (i32.const 3)) (then (return (i32.const 9))))
        (drop (call $read_input (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 3)))
        (if (i32.ne (i32.load8_u (i32.const 2)) (i32.const 98)) (then (return (i32.const 8))))
        (i32.add (call $input_len (i32.const 0)) (i32.const 100))"#;
    let e = run_with(&runtime(), body, "", b"12345", b"pub");
    assert_eq!(e.outcome, Outcome::Rejected(105));

    assert_eq!(run("(call $input_len (i32.const 7))", "").outcome, Outcome::Rejected(-1));
    let past_end = "(call $read_input (i32.const 0) (i32.const 999) (i32.const 0) (i32.const 1))";
    assert_eq!(run(past_end, "").outcome, Outcome::Rejected(-1));
    let partial = "(call $read_input (i32.const 0) (i32.const 3) (i32.const 0) (i32.const 64))";
    assert_eq!(run(partial, "").outcome, Outcome::Rejected(2), "only 2 of the 5 proof bytes remain");

    let rt = Runtime::new(Limits { max_input_bytes: 4, ..Limits::default() });
    let v = rt.load(&module("i32.const 0", "")).unwrap();
    assert!(matches!(rt.verify(&v, b"12345", b""), Err(InputError::TooLarge { which: "proof", .. })));
}

#[test]
fn host_faults_on_bad_pointers() {
    let e = run("(call $sha256 (i32.const 0) (i32.const 32) (i32.const 65530)) i32.const 0", "");
    assert!(matches!(&e.outcome, Outcome::HostFault(m) if m.contains("outside memory")), "{e:?}");
    let e = run("(call $sha256 (i32.const -1) (i32.const 4) (i32.const 0)) i32.const 0", "");
    assert!(matches!(e.outcome, Outcome::HostFault(_)));
    let e = run(
        "(drop (call $read_input (i32.const 0) (i32.const 0) (i32.const 65535) (i32.const 5))) i32.const 0",
        "",
    );
    assert!(matches!(e.outcome, Outcome::HostFault(_)));
}

#[test]
fn host_hashes_match_known_digests() {
    // sha256("abc") and keccak256("abc"), compared word by word in the guest.
    let check = |func: &str, digest: &str| {
        let words: Vec<String> = (0..4)
            .map(|i| {
                let w = u64::from_str_radix(&digest[16 * i..16 * (i + 1)], 16).unwrap().swap_bytes();
                format!(
                    "(if (i64.ne (i64.load (i32.const {})) (i64.const {})) (then (return (i32.const 1))))",
                    64 + 8 * i,
                    w as i64
                )
            })
            .collect();
        let body = format!(
            "(i32.store8 (i32.const 0) (i32.const 97)) (i32.store8 (i32.const 1) (i32.const 98)) \
             (i32.store8 (i32.const 2) (i32.const 99)) (call ${func} (i32.const 0) (i32.const 3) (i32.const 64)) \
             {} i32.const 0",
            words.join(" ")
        );
        run(&body, "").outcome
    };
    assert_eq!(
        check("sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        Outcome::Valid
    );
    assert_eq!(
        check("keccak256", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        Outcome::Valid
    );
}

#[test]
fn logs_are_captured_and_bounded() {
    let extra = r#"(data (i32.const 100) "hello")"#;
    let e = run(
        "(call $log (i32.const 100) (i32.const 5)) (call $log (i32.const 101) (i32.const 3)) i32.const 0",
        extra,
    );
    assert_eq!(e.logs, vec!["hello".to_string(), "ell".to_string()]);

    let rt = Runtime::new(Limits { max_log_bytes: 4, ..Limits::default() });
    let e = run_with(&rt, "(call $log (i32.const 100) (i32.const 5)) i32.const 0", extra, b"", b"");
    assert!(matches!(&e.outcome, Outcome::HostFault(m) if m.contains("log limit")));
}

#[test]
fn host_calls_are_metered() {
    let rt = Runtime::new(Limits { fuel: 1_000, ..Limits::default() });
    // Hashing 64 KiB costs far more than 1000 fuel; it must stop inside the host call.
    let e = run_with(
        &rt,
        "(call $sha256 (i32.const 0) (i32.const 65536) (i32.const 0)) i32.const 0",
        "",
        b"",
        b"",
    );
    assert_eq!(e.outcome, Outcome::OutOfFuel);
    assert_eq!(e.fuel_used, 1_000);

    let small = run("(call $sha256 (i32.const 0) (i32.const 32) (i32.const 0)) i32.const 0", "").fuel_used;
    let large = run("(call $sha256 (i32.const 0) (i32.const 32000) (i32.const 0)) i32.const 0", "").fuel_used;
    assert!(large > small + 10_000, "per-word hashing cost: {small} vs {large}");
}

#[test]
fn every_call_gets_a_fresh_instance() {
    // A global counter would leak state between calls if instances were reused.
    let extra = r#"(global $n (mut i32) (i32.const 0))"#;
    let body =
        "(global.set $n (i32.add (global.get $n) (i32.const 1))) (i32.add (global.get $n) (i32.const 100))";
    let rt = runtime();
    let v = rt.load(&module(body, extra)).unwrap();
    for _ in 0..3 {
        assert_eq!(rt.verify(&v, b"", b"").unwrap().outcome, Outcome::Rejected(101));
    }
}

#[test]
fn executions_are_deterministic() {
    let rt = runtime();
    let v = rt
        .load(&module("(call $sha256 (i32.const 0) (i32.const 1000) (i32.const 0)) i32.const 0", ""))
        .unwrap();
    let first = rt.verify(&v, b"x", b"y").unwrap();
    for _ in 0..20 {
        assert_eq!(rt.verify(&v, b"x", b"y").unwrap(), first);
    }
    let other = runtime();
    let v2 = other
        .load(&module("(call $sha256 (i32.const 0) (i32.const 1000) (i32.const 0)) i32.const 0", ""))
        .unwrap();
    assert_eq!(other.verify(&v2, b"x", b"y").unwrap(), first);
}
