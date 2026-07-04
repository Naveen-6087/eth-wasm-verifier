use serde::Serialize;

/// Resource bounds for loading and running a verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Limits {
    /// Fuel available to one `verify` call, including instantiation.
    pub fuel: u64,
    /// Linear memory limit in 64 KiB pages, enforced at load and on growth.
    pub max_memory_pages: u32,
    /// Maximum Wasm call depth.
    pub max_call_depth: usize,
    /// Maximum size of a module binary.
    pub max_module_bytes: usize,
    /// Maximum size of each input (proof, public inputs).
    pub max_input_bytes: usize,
    /// Maximum total bytes a verifier may log per call.
    pub max_log_bytes: usize,
}

pub const PAGE_SIZE: usize = 64 * 1024;

impl Default for Limits {
    fn default() -> Self {
        Self {
            fuel: 50_000_000,
            max_memory_pages: 64,
            max_call_depth: 1024,
            max_module_bytes: 4 << 20,
            max_input_bytes: 1 << 20,
            max_log_bytes: 4096,
        }
    }
}
