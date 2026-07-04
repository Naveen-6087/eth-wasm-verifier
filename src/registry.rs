use std::collections::BTreeMap;
use std::path::Path;

use crate::runtime::{LoadError, Runtime, Verifier};

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("{path}: {source}")]
    Load { path: String, source: LoadError },
    #[error("cannot read directory {0}: {1}")]
    Dir(String, std::io::Error),
    #[error("verifier name `{name}` is used by both {first} and {second}")]
    Duplicate { name: String, first: String, second: String },
}

/// Verifiers loaded from a directory, keyed by their `ewv.meta` name (or the
/// file stem when a module has no metadata).
#[derive(Debug, Default)]
pub struct Registry {
    verifiers: BTreeMap<String, (Verifier, String)>,
}

impl Registry {
    /// Loads every `*.wasm` file in `dir`. All modules must pass validation.
    pub fn load_dir(runtime: &Runtime, dir: &Path) -> Result<Self, RegistryError> {
        let entries = std::fs::read_dir(dir).map_err(|e| RegistryError::Dir(dir.display().to_string(), e))?;
        let mut paths: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "wasm"))
            .collect();
        paths.sort();

        let mut registry = Registry::default();
        for path in paths {
            let shown = path.display().to_string();
            let verifier = runtime
                .load_file(&path)
                .map_err(|source| RegistryError::Load { path: shown.clone(), source })?;
            let name = verifier
                .name()
                .map(str::to_owned)
                .unwrap_or_else(|| path.file_stem().unwrap_or_default().to_string_lossy().into_owned());
            if let Some((_, first)) = registry.verifiers.get(&name) {
                return Err(RegistryError::Duplicate { name, first: first.clone(), second: shown });
            }
            registry.verifiers.insert(name, (verifier, shown));
        }
        Ok(registry)
    }

    pub fn get(&self, name: &str) -> Option<&Verifier> {
        self.verifiers.get(name).map(|(v, _)| v)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.verifiers.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.verifiers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.verifiers.is_empty()
    }
}
