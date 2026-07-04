use std::fmt;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use wasmi::{CompilationMode, Config, Engine, Instance, Linker, Module, Store, StoreLimitsBuilder, TrapCode};

use crate::abi::{self, VERDICT_INVALID, VERDICT_VALID};
use crate::host::{self, HostFault, HostState};
use crate::limits::{Limits, PAGE_SIZE};
use crate::validate::{Meta, Violation, check_abi};

const EXECUTION_STACK_BYTES: usize = 8 << 20;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
    #[error("module rejected:\n  - {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n  - "))]
    Rejected(Vec<Violation>),
}

#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("{which} is {len} bytes, limit is {limit}")]
    TooLarge { which: &'static str, len: usize, limit: usize },
    #[error("verifier was loaded by a different Runtime")]
    ForeignVerifier,
}

/// How a `verify` call ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", content = "detail", rename_all = "snake_case")]
pub enum Outcome {
    Valid,
    Invalid,
    /// The verifier returned a code other than valid/invalid.
    Rejected(i32),
    OutOfFuel,
    StackOverflow,
    MemoryLimit,
    /// The module reports an ABI version this runtime does not implement.
    AbiMismatch(i32),
    /// A host function refused the guest's request.
    HostFault(String),
    Trap(String),
}

impl Outcome {
    pub fn is_valid(&self) -> bool {
        matches!(self, Outcome::Valid)
    }

    /// Whether the verifier ran to completion and produced a verdict.
    pub fn is_verdict(&self) -> bool {
        matches!(self, Outcome::Valid | Outcome::Invalid | Outcome::Rejected(_))
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Valid => f.write_str("valid"),
            Outcome::Invalid => f.write_str("invalid"),
            Outcome::Rejected(code) => write!(f, "rejected by verifier (code {code})"),
            Outcome::OutOfFuel => f.write_str("out of fuel"),
            Outcome::StackOverflow => f.write_str("call stack exhausted"),
            Outcome::MemoryLimit => f.write_str("memory limit exceeded"),
            Outcome::AbiMismatch(v) => {
                write!(f, "module implements ABI version {v}, runtime implements {}", abi::ABI_VERSION)
            }
            Outcome::HostFault(msg) => write!(f, "host fault: {msg}"),
            Outcome::Trap(msg) => write!(f, "trap: {msg}"),
        }
    }
}

/// The result of one `verify` call. Everything in it is a deterministic
/// function of the module bytes, the inputs and the limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Execution {
    #[serde(flatten)]
    pub outcome: Outcome,
    pub fuel_used: u64,
    pub fuel_limit: u64,
    pub memory_pages: u32,
    pub logs: Vec<String>,
}

/// An engine configured for deterministic, metered execution.
pub struct Runtime {
    engine: Engine,
    linker: Linker<HostState>,
    limits: Limits,
}

impl Runtime {
    pub fn new(limits: Limits) -> Self {
        let mut config = Config::default();
        config
            .consume_fuel(true)
            .floats(false)
            .wasm_multi_memory(false)
            .wasm_custom_page_sizes(false)
            .wasm_wide_arithmetic(false)
            .allow_start_fn(false)
            .set_max_recursion_depth(limits.max_call_depth)
            .compilation_mode(CompilationMode::Eager);
        let engine = Engine::new(&config);
        let mut linker = Linker::new(&engine);
        host::link(&mut linker).expect("host functions have unique names");
        Self { engine, linker, limits }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Validates a module and compiles it, collecting every ABI violation.
    pub fn load(&self, wasm: &[u8]) -> Result<Verifier, LoadError> {
        if wasm.len() > self.limits.max_module_bytes {
            return Err(LoadError::Rejected(vec![Violation::ModuleTooLarge {
                size: wasm.len(),
                limit: self.limits.max_module_bytes,
            }]));
        }
        let module = Module::new(&self.engine, wasm)
            .map_err(|e| LoadError::Rejected(vec![Violation::Invalid(e.to_string())]))?;
        let (violations, meta) = check_abi(&module, &self.limits);
        if !violations.is_empty() {
            return Err(LoadError::Rejected(violations));
        }
        let id = Sha256::digest(wasm).iter().map(|b| format!("{b:02x}")).collect();
        Ok(Verifier { module, id, meta, size: wasm.len() })
    }

    pub fn load_file(&self, path: &Path) -> Result<Verifier, LoadError> {
        let bytes = std::fs::read(path).map_err(|e| LoadError::Io(path.display().to_string(), e))?;
        self.load(&bytes)
    }

    /// Runs `verify` in a fresh instance with the configured fuel budget.
    pub fn verify(&self, verifier: &Verifier, proof: &[u8], public: &[u8]) -> Result<Execution, InputError> {
        self.verify_with_fuel(verifier, proof, public, self.limits.fuel)
    }

    pub fn verify_with_fuel(
        &self,
        verifier: &Verifier,
        proof: &[u8],
        public: &[u8],
        fuel: u64,
    ) -> Result<Execution, InputError> {
        if !Engine::same(verifier.module.engine(), &self.engine) {
            return Err(InputError::ForeignVerifier);
        }
        for (which, data) in [("proof", proof), ("public input", public)] {
            if data.len() > self.limits.max_input_bytes {
                return Err(InputError::TooLarge {
                    which,
                    len: data.len(),
                    limit: self.limits.max_input_bytes,
                });
            }
        }
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.max_memory_pages as usize * PAGE_SIZE)
            .trap_on_grow_failure(true)
            .build();
        let state = HostState {
            proof: proof.to_vec(),
            public: public.to_vec(),
            logs: Vec::new(),
            log_bytes: 0,
            max_log_bytes: self.limits.max_log_bytes,
            limits,
        };
        // Guest code runs on its own thread with a fixed, generous native
        // stack, so an interpreter path that is stack-hungry (notably in
        // unoptimized builds) cannot overflow the caller's thread.
        Ok(std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("ewv-guest".into())
                .stack_size(EXECUTION_STACK_BYTES)
                .spawn_scoped(scope, || self.execute(verifier, state, fuel))
                .expect("spawn guest thread")
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        }))
    }

    fn execute(&self, verifier: &Verifier, state: HostState, fuel: u64) -> Execution {
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store.set_fuel(fuel).expect("fuel metering is enabled");

        let (outcome, instance) = self.run(&mut store, verifier);
        let remaining = store.get_fuel().expect("fuel metering is enabled");
        let memory_pages = instance
            .and_then(|i| i.get_memory(&store, abi::EXPORT_MEMORY))
            .map_or(0, |m| u32::try_from(m.size(&store)).unwrap_or(u32::MAX));
        let state = store.into_data();
        Execution { outcome, fuel_used: fuel - remaining, fuel_limit: fuel, memory_pages, logs: state.logs }
    }

    fn run(&self, store: &mut Store<HostState>, verifier: &Verifier) -> (Outcome, Option<Instance>) {
        let instance = match self.linker.instantiate_and_start(&mut *store, &verifier.module) {
            Ok(i) => i,
            Err(e) => return (classify(&e), None),
        };
        (Self::call_verify(store, &instance), Some(instance))
    }

    fn call_verify(store: &mut Store<HostState>, instance: &Instance) -> Outcome {
        let call = |name: &str, store: &mut Store<HostState>| -> Result<i32, wasmi::Error> {
            instance.get_typed_func::<(), i32>(&*store, name)?.call(store, ())
        };
        match call(abi::EXPORT_ABI_VERSION, store) {
            Ok(abi::ABI_VERSION) => {}
            Ok(other) => return Outcome::AbiMismatch(other),
            Err(e) => return classify(&e),
        }
        match call(abi::EXPORT_VERIFY, store) {
            Ok(VERDICT_VALID) => Outcome::Valid,
            Ok(VERDICT_INVALID) => Outcome::Invalid,
            Ok(code) => Outcome::Rejected(code),
            Err(e) => classify(&e),
        }
    }
}

fn classify(err: &wasmi::Error) -> Outcome {
    if let Some(fault) = err.downcast_ref::<HostFault>() {
        return Outcome::HostFault(fault.0.clone());
    }
    match err.as_trap_code() {
        Some(TrapCode::OutOfFuel) => Outcome::OutOfFuel,
        Some(TrapCode::StackOverflow) => Outcome::StackOverflow,
        Some(TrapCode::GrowthOperationLimited) => Outcome::MemoryLimit,
        Some(code) => Outcome::Trap(code.to_string()),
        None => Outcome::Trap(err.to_string()),
    }
}

/// A validated, compiled verifier module.
#[derive(Clone)]
pub struct Verifier {
    module: Module,
    id: String,
    meta: Option<Meta>,
    size: usize,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("id", &self.id)
            .field("meta", &self.meta)
            .field("size", &self.size)
            .finish()
    }
}

impl Verifier {
    /// SHA-256 of the module bytes.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn meta(&self) -> Option<&Meta> {
        self.meta.as_ref()
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn name(&self) -> Option<&str> {
        self.meta.as_ref().map(|m| m.name.as_str())
    }

    pub fn imports(&self) -> Vec<String> {
        self.module.imports().map(|i| format!("{}.{}", i.module(), i.name())).collect()
    }

    pub fn exports(&self) -> Vec<String> {
        self.module.exports().map(|e| e.name().to_owned()).collect()
    }
}
