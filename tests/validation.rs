mod common;

use common::{module, runtime, wasm};
use eth_wasm_verifier::{Limits, LoadError, Runtime, Violation};

fn violations(bytes: &[u8]) -> Vec<Violation> {
    violations_with(&runtime(), bytes)
}

fn violations_with(rt: &Runtime, bytes: &[u8]) -> Vec<Violation> {
    match rt.load(bytes) {
        Ok(_) => Vec::new(),
        Err(LoadError::Rejected(v)) => v,
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn minimal_module_is_accepted() {
    let v = runtime().load(&module("i32.const 0", "")).unwrap();
    assert_eq!(v.id().len(), 64);
    assert!(v.meta().is_none());
}

#[test]
fn rejects_non_wasm_and_oversized_modules() {
    assert!(matches!(violations(b"not wasm")[..], [Violation::Invalid(_)]));
    let small = Runtime::new(Limits { max_module_bytes: 16, ..Limits::default() });
    assert!(matches!(
        violations_with(&small, &module("i32.const 0", ""))[..],
        [Violation::ModuleTooLarge { .. }]
    ));
}

#[test]
fn rejects_floats_and_simd() {
    let floats = module("i32.const 0", r#"(func (export "f") (result f32) f32.const 1.5)"#);
    assert!(matches!(violations(&floats)[..], [Violation::Invalid(_)]), "floats must be rejected");
    let float_param = module("i32.const 0", r#"(func (param f64))"#);
    assert!(matches!(violations(&float_param)[..], [Violation::Invalid(_)]));
    let simd = module("i32.const 0", r#"(func (result i32) v128.const i64x2 0 0 drop i32.const 0)"#);
    assert!(matches!(violations(&simd)[..], [Violation::Invalid(_)]), "SIMD must be rejected");
}

#[test]
fn rejects_start_functions() {
    let start = module("i32.const 0", r#"(func $init) (start $init)"#);
    assert!(matches!(violations(&start)[..], [Violation::Invalid(_)]));
}

#[test]
fn rejects_unknown_and_mistyped_imports() {
    let unknown = wasm(
        r#"(module
            (import "env" "abort" (func))
            (import "ewv" "now" (func (result i64)))
            (memory (export "memory") 1)
            (func (export "ewv_abi_version") (result i32) i32.const 1)
            (func (export "verify") (result i32) i32.const 0))"#,
    );
    let v = violations(&unknown);
    assert_eq!(v.len(), 2);
    assert!(v.iter().all(|x| matches!(x, Violation::ForbiddenImport { .. })));

    let mistyped = wasm(
        r#"(module
            (import "ewv" "sha256" (func (param i32)))
            (import "ewv" "log" (global i32))
            (memory (export "memory") 1)
            (func (export "ewv_abi_version") (result i32) i32.const 1)
            (func (export "verify") (result i32) i32.const 0))"#,
    );
    let v = violations(&mistyped);
    assert_eq!(v.len(), 2, "{v:?}");
    assert!(v.iter().all(|x| matches!(x, Violation::ImportSignature { .. })));
}

#[test]
fn rejects_missing_and_mistyped_exports() {
    let v = violations(&wasm(r#"(module (func (export "verify") (result i64) i64.const 0))"#));
    assert!(v.contains(&Violation::MissingExport("memory")));
    assert!(v.contains(&Violation::MissingExport("ewv_abi_version")));
    assert!(v.iter().any(|x| matches!(x, Violation::ExportType { name: "verify", .. })));
}

#[test]
fn rejects_memory_above_the_limit() {
    let big = wasm(
        r#"(module
            (memory (export "memory") 65)
            (func (export "ewv_abi_version") (result i32) i32.const 1)
            (func (export "verify") (result i32) i32.const 0))"#,
    );
    assert_eq!(violations(&big), vec![Violation::MemoryTooLarge { initial_pages: 65, limit: 64 }]);
}

#[test]
fn reads_and_validates_metadata() {
    let meta = r#"(@custom "ewv.meta" "{\"name\":\"demo\",\"version\":\"1.2.3\"}")"#;
    let v = runtime().load(&module("i32.const 0", meta)).unwrap();
    assert_eq!(v.name(), Some("demo"));
    assert_eq!(v.meta().unwrap().version, "1.2.3");

    let bad = r#"(@custom "ewv.meta" "not json")"#;
    assert!(matches!(violations(&module("i32.const 0", bad))[..], [Violation::BadMeta(_)]));
    let unnamed = r#"(@custom "ewv.meta" "{\"name\":\"\"}")"#;
    assert!(matches!(violations(&module("i32.const 0", unnamed))[..], [Violation::BadMeta(_)]));
}

#[test]
fn violations_render_readably() {
    let err = runtime().load(&wasm("(module)")).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("missing export `memory`"), "{text}");
    assert!(text.contains("missing export `verify`"), "{text}");
}
