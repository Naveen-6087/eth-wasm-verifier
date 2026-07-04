use std::fmt;

use serde::{Deserialize, Serialize};
use wasmi::{ExternType, Module};

use crate::abi::{self, HOST_FUNCTIONS, HOST_MODULE};
use crate::limits::Limits;

/// Optional metadata embedded in the `ewv.meta` custom section as JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
}

/// A reason a module is not an acceptable verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum Violation {
    ModuleTooLarge { size: usize, limit: usize },
    Invalid(String),
    ForbiddenImport { module: String, name: String },
    ImportSignature { name: String, expected: String, found: String },
    MissingExport(&'static str),
    ExportType { name: &'static str, expected: String, found: String },
    MemoryTooLarge { initial_pages: u64, limit: u32 },
    BadMeta(String),
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleTooLarge { size, limit } => write!(f, "module is {size} bytes, limit is {limit}"),
            Self::Invalid(why) => write!(f, "invalid or disallowed wasm: {why}"),
            Self::ForbiddenImport { module, name } => {
                write!(f, "import `{module}.{name}` is not provided by the host")
            }
            Self::ImportSignature { name, expected, found } => {
                write!(f, "import `{HOST_MODULE}.{name}` has type {found}, expected {expected}")
            }
            Self::MissingExport(name) => write!(f, "missing export `{name}`"),
            Self::ExportType { name, expected, found } => {
                write!(f, "export `{name}` is {found}, expected {expected}")
            }
            Self::MemoryTooLarge { initial_pages, limit } => {
                write!(f, "memory starts at {initial_pages} pages, limit is {limit}")
            }
            Self::BadMeta(why) => write!(f, "invalid `{}` section: {why}", abi::META_SECTION),
        }
    }
}

fn describe(ty: &ExternType) -> String {
    match ty {
        ExternType::Func(f) => format!("func{:?} -> {:?}", f.params(), f.results()),
        ExternType::Memory(_) => "memory".into(),
        ExternType::Table(_) => "table".into(),
        ExternType::Global(_) => "global".into(),
    }
}

/// Checks the verifier ABI on an already parsed (and Wasm-validated) module.
pub(crate) fn check_abi(module: &Module, limits: &Limits) -> (Vec<Violation>, Option<Meta>) {
    let mut violations = Vec::new();

    for import in module.imports() {
        let (m, name) = (import.module(), import.name());
        let allowed = HOST_FUNCTIONS.iter().find(|(n, _, _)| m == HOST_MODULE && *n == name);
        match (allowed, import.ty()) {
            (None, _) => violations.push(Violation::ForbiddenImport { module: m.into(), name: name.into() }),
            (Some((_, params, results)), ExternType::Func(f)) => {
                if f.params() != *params || f.results() != *results {
                    violations.push(Violation::ImportSignature {
                        name: name.into(),
                        expected: format!("func{params:?} -> {results:?}"),
                        found: format!("func{:?} -> {:?}", f.params(), f.results()),
                    });
                }
            }
            (Some(_), other) => violations.push(Violation::ImportSignature {
                name: name.into(),
                expected: "func".into(),
                found: describe(other),
            }),
        }
    }

    match module.get_export(abi::EXPORT_MEMORY) {
        None => violations.push(Violation::MissingExport(abi::EXPORT_MEMORY)),
        Some(ExternType::Memory(mem)) => {
            if mem.minimum() > u64::from(limits.max_memory_pages) {
                violations.push(Violation::MemoryTooLarge {
                    initial_pages: mem.minimum(),
                    limit: limits.max_memory_pages,
                });
            }
        }
        Some(other) => violations.push(Violation::ExportType {
            name: abi::EXPORT_MEMORY,
            expected: "memory".into(),
            found: describe(&other),
        }),
    }

    for name in [abi::EXPORT_ABI_VERSION, abi::EXPORT_VERIFY] {
        match module.get_export(name) {
            None => violations.push(Violation::MissingExport(name)),
            Some(ExternType::Func(f)) if f.params().is_empty() && f.results() == [wasmi::ValType::I32] => {}
            Some(other) => violations.push(Violation::ExportType {
                name,
                expected: "func[] -> [I32]".into(),
                found: describe(&other),
            }),
        }
    }

    let mut meta = None;
    for section in module.custom_sections() {
        if section.name() == abi::META_SECTION {
            match serde_json::from_slice::<Meta>(section.data()) {
                Ok(m) if !m.name.is_empty() => meta = Some(m),
                Ok(_) => violations.push(Violation::BadMeta("`name` must not be empty".into())),
                Err(e) => violations.push(Violation::BadMeta(e.to_string())),
            }
        }
    }
    (violations, meta)
}
