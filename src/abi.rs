use wasmi::ValType;

pub const ABI_VERSION: i32 = 1;
pub const HOST_MODULE: &str = "ewv";
pub const META_SECTION: &str = "ewv.meta";

pub const EXPORT_MEMORY: &str = "memory";
pub const EXPORT_ABI_VERSION: &str = "ewv_abi_version";
pub const EXPORT_VERIFY: &str = "verify";

pub const VERDICT_VALID: i32 = 0;
pub const VERDICT_INVALID: i32 = 1;

pub const INPUT_PROOF: i32 = 0;
pub const INPUT_PUBLIC: i32 = 1;

/// Host functions available to verifiers: (name, params, results).
pub const HOST_FUNCTIONS: &[(&str, &[ValType], &[ValType])] = &[
    ("input_len", &[ValType::I32], &[ValType::I32]),
    ("read_input", &[ValType::I32, ValType::I32, ValType::I32, ValType::I32], &[ValType::I32]),
    ("sha256", &[ValType::I32, ValType::I32, ValType::I32], &[]),
    ("keccak256", &[ValType::I32, ValType::I32, ValType::I32], &[]),
    ("log", &[ValType::I32, ValType::I32], &[]),
];

/// Fuel charged by host functions, on top of the interpreter's per-instruction
/// fuel. Hashing is charged per started 32-byte word, copies per 8 bytes.
pub mod cost {
    pub const HOST_CALL: u64 = 20;
    pub const HASH_BASE: u64 = 100;
    pub const HASH_PER_WORD: u64 = 12;
    pub const COPY_PER_8_BYTES: u64 = 1;
    pub const LOG_PER_BYTE: u64 = 1;

    pub fn hash(len: usize) -> u64 {
        HOST_CALL + HASH_BASE + HASH_PER_WORD * (len as u64).div_ceil(32)
    }

    pub fn copy(len: usize) -> u64 {
        HOST_CALL + COPY_PER_8_BYTES * (len as u64).div_ceil(8)
    }

    pub fn log(len: usize) -> u64 {
        HOST_CALL + LOG_PER_BYTE * len as u64
    }
}
