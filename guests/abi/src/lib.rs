#![no_std]

pub const ABI_VERSION: i32 = 1;
pub const INPUT_PROOF: i32 = 0;
pub const INPUT_PUBLIC: i32 = 1;

/// What `verify` returns: 0 valid, 1 invalid, anything else is a
/// verifier-defined rejection code (for example malformed input).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    Invalid,
    Reject(i32),
}

impl Verdict {
    pub fn code(self) -> i32 {
        match self {
            Verdict::Valid => 0,
            Verdict::Invalid => 1,
            Verdict::Reject(code) => code,
        }
    }
}

mod sys {
    #[link(wasm_import_module = "ewv")]
    unsafe extern "C" {
        pub fn input_len(kind: i32) -> i32;
        pub fn read_input(kind: i32, offset: i32, dst: *mut u8, len: i32) -> i32;
        pub fn sha256(src: *const u8, len: i32, dst: *mut u8);
        pub fn keccak256(src: *const u8, len: i32, dst: *mut u8);
        pub fn log(ptr: *const u8, len: i32);
    }
}

pub fn input_len(kind: i32) -> usize {
    // SAFETY: plain host call without pointers.
    let n = unsafe { sys::input_len(kind) };
    usize::try_from(n).unwrap_or(0)
}

/// Copies input `kind` into `buf`; `None` if it does not fit exactly.
pub fn read_exact(kind: i32, buf: &mut [u8]) -> Option<()> {
    if input_len(kind) != buf.len() {
        return None;
    }
    // SAFETY: the host writes at most `buf.len()` bytes into `buf`.
    let n = unsafe { sys::read_input(kind, 0, buf.as_mut_ptr(), buf.len() as i32) };
    (n == buf.len() as i32).then_some(())
}

/// Copies input `kind` into the front of `buf` and returns the filled part,
/// or `None` if the input is larger than `buf`.
pub fn read_into(kind: i32, buf: &mut [u8]) -> Option<&[u8]> {
    let len = input_len(kind);
    if len > buf.len() {
        return None;
    }
    // SAFETY: the host writes at most `len <= buf.len()` bytes into `buf`.
    let n = unsafe { sys::read_input(kind, 0, buf.as_mut_ptr(), len as i32) };
    (n == len as i32).then_some(&buf[..len])
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: `data` and `out` are valid for the lengths passed.
    unsafe { sys::sha256(data.as_ptr(), data.len() as i32, out.as_mut_ptr()) };
    out
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: `data` and `out` are valid for the lengths passed.
    unsafe { sys::keccak256(data.as_ptr(), data.len() as i32, out.as_mut_ptr()) };
    out
}

pub fn log(message: &str) {
    // SAFETY: `message` is valid for its length.
    unsafe { sys::log(message.as_ptr(), message.len() as i32) };
}

/// Copies a string literal into a fixed-size array (for the meta section).
pub const fn bytes<const N: usize>(s: &str) -> [u8; N] {
    let src = s.as_bytes();
    assert!(src.len() == N, "length mismatch");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = src[i];
        i += 1;
    }
    out
}

/// Exports the ABI entry points for `$verify: fn() -> Verdict` and embeds
/// `$meta` (a JSON string literal) in the `ewv.meta` custom section.
#[macro_export]
macro_rules! verifier {
    ($verify:path, $meta:literal) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn ewv_abi_version() -> i32 {
            $crate::ABI_VERSION
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn verify() -> i32 {
            $verify().code()
        }

        #[unsafe(link_section = "ewv.meta")]
        #[used]
        static META: [u8; $meta.len()] = $crate::bytes($meta);
    };
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
