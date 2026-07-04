use std::fmt;

use sha2::Digest;
use wasmi::{Caller, Error, Extern, Linker, Memory, StoreLimits, TrapCode};

use crate::abi::{self, HOST_MODULE, INPUT_PROOF, INPUT_PUBLIC, cost};

/// Per-call state seen by host functions.
pub(crate) struct HostState {
    pub proof: Vec<u8>,
    pub public: Vec<u8>,
    pub logs: Vec<String>,
    pub log_bytes: usize,
    pub max_log_bytes: usize,
    pub limits: StoreLimits,
}

/// A host function rejected the guest's request (bad pointer, oversized log,
/// unknown input kind). Reported as a trap, never as a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFault(pub String);

impl fmt::Display for HostFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HostFault {}
impl wasmi::errors::HostError for HostFault {}

fn fault(msg: impl Into<String>) -> Error {
    Error::host(HostFault(msg.into()))
}

fn charge(caller: &mut Caller<'_, HostState>, amount: u64) -> Result<(), Error> {
    let fuel = caller.get_fuel()?;
    if fuel < amount {
        caller.set_fuel(0)?;
        return Err(TrapCode::OutOfFuel.into());
    }
    caller.set_fuel(fuel - amount)
}

fn memory(caller: &Caller<'_, HostState>) -> Result<Memory, Error> {
    match caller.get_export(abi::EXPORT_MEMORY) {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(fault("module has no exported memory")),
    }
}

fn range(ptr: i32, len: i32, mem_len: usize, what: &str) -> Result<std::ops::Range<usize>, Error> {
    let (Ok(ptr), Ok(len)) = (usize::try_from(ptr), usize::try_from(len)) else {
        return Err(fault(format!("{what}: negative pointer or length")));
    };
    let end = ptr.checked_add(len).filter(|end| *end <= mem_len);
    end.map(|end| ptr..end)
        .ok_or_else(|| fault(format!("{what}: range {ptr}+{len} is outside memory ({mem_len} bytes)")))
}

fn input(state: &HostState, kind: i32) -> Option<&[u8]> {
    match kind {
        INPUT_PROOF => Some(&state.proof),
        INPUT_PUBLIC => Some(&state.public),
        _ => None,
    }
}

fn hash_into<H: Digest>(
    mut caller: Caller<'_, HostState>,
    src: i32,
    len: i32,
    dst: i32,
    name: &str,
) -> Result<(), Error> {
    charge(&mut caller, cost::hash(usize::try_from(len).unwrap_or(0)))?;
    let mem = memory(&caller)?;
    let data = mem.data_mut(&mut caller);
    let src = range(src, len, data.len(), name)?;
    let dst = range(dst, 32, data.len(), name)?;
    let digest = H::digest(&data[src]);
    data[dst].copy_from_slice(&digest);
    Ok(())
}

pub(crate) fn link(linker: &mut Linker<HostState>) -> Result<(), Error> {
    linker.func_wrap(
        HOST_MODULE,
        "input_len",
        |mut caller: Caller<'_, HostState>, kind: i32| -> Result<i32, Error> {
            charge(&mut caller, cost::HOST_CALL)?;
            Ok(input(caller.data(), kind).map_or(-1, |b| b.len() as i32))
        },
    )?;

    linker.func_wrap(
        HOST_MODULE,
        "read_input",
        |mut caller: Caller<'_, HostState>,
         kind: i32,
         offset: i32,
         dst: i32,
         len: i32|
         -> Result<i32, Error> {
            charge(&mut caller, cost::copy(usize::try_from(len).unwrap_or(0)))?;
            let (Some(source), Ok(offset)) = (input(caller.data(), kind), usize::try_from(offset)) else {
                return Ok(-1);
            };
            if offset > source.len() {
                return Ok(-1);
            }
            let wanted = usize::try_from(len).unwrap_or(0);
            let chunk = source[offset..offset + wanted.min(source.len() - offset)].to_vec();
            let mem = memory(&caller)?;
            let data = mem.data_mut(&mut caller);
            let dst = range(dst, len, data.len(), "read_input")?;
            data[dst.start..dst.start + chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len() as i32)
        },
    )?;

    linker.func_wrap(
        HOST_MODULE,
        "sha256",
        |caller: Caller<'_, HostState>, src: i32, len: i32, dst: i32| {
            hash_into::<sha2::Sha256>(caller, src, len, dst, "sha256")
        },
    )?;

    linker.func_wrap(
        HOST_MODULE,
        "keccak256",
        |caller: Caller<'_, HostState>, src: i32, len: i32, dst: i32| {
            hash_into::<sha3::Keccak256>(caller, src, len, dst, "keccak256")
        },
    )?;

    linker.func_wrap(
        HOST_MODULE,
        "log",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> Result<(), Error> {
            charge(&mut caller, cost::log(usize::try_from(len).unwrap_or(0)))?;
            let mem = memory(&caller)?;
            let bytes = {
                let data = mem.data(&caller);
                data[range(ptr, len, data.len(), "log")?].to_vec()
            };
            let state = caller.data_mut();
            if state.log_bytes + bytes.len() > state.max_log_bytes {
                return Err(fault(format!("log limit of {} bytes exceeded", state.max_log_bytes)));
            }
            state.log_bytes += bytes.len();
            state.logs.push(String::from_utf8_lossy(&bytes).into_owned());
            Ok(())
        },
    )?;
    Ok(())
}
