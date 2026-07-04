use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use eth_wasm_verifier::{Limits, LoadError, Outcome, Registry, Runtime};
use serde_json::json;

const EXIT_VALID: u8 = 0;
const EXIT_INVALID: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_FAILED: u8 = 3;

/// Deterministic, fuel-metered runtime for WebAssembly proof verifiers.
#[derive(Parser, Debug)]
#[command(name = "eth-wasm-verifier", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[command(flatten)]
    limits: LimitArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate a module and print its id, metadata, imports and exports.
    Inspect { module: PathBuf },
    /// List the verifiers in a directory.
    List { dir: PathBuf },
    /// Run a verifier. Inputs are 0x-prefixed hex or @path to a raw file.
    Verify {
        /// A module path, or a verifier name when --registry is given.
        verifier: String,
        /// Directory of verifier modules to resolve names from.
        #[arg(long)]
        registry: Option<PathBuf>,
        #[arg(long, default_value = "0x")]
        proof: String,
        #[arg(long, default_value = "0x")]
        public: String,
    },
}

#[derive(Args, Debug)]
struct LimitArgs {
    /// Fuel for one verify call.
    #[arg(long, global = true)]
    fuel: Option<u64>,
    /// Memory limit in 64 KiB pages.
    #[arg(long, global = true)]
    max_memory_pages: Option<u32>,
    /// Maximum call depth.
    #[arg(long, global = true)]
    max_call_depth: Option<usize>,
}

impl LimitArgs {
    fn limits(&self) -> Limits {
        let d = Limits::default();
        Limits {
            fuel: self.fuel.unwrap_or(d.fuel),
            max_memory_pages: self.max_memory_pages.unwrap_or(d.max_memory_pages),
            max_call_depth: self.max_call_depth.unwrap_or(d.max_call_depth),
            ..d
        }
    }
}

fn parse_input(s: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = s.strip_prefix('@') {
        return std::fs::read(path).map_err(|e| format!("{path}: {e}"));
    }
    let digits = s.strip_prefix("0x").ok_or_else(|| format!("`{s}`: expected 0x-prefixed hex or @file"))?;
    if digits.len() % 2 != 0 {
        return Err(format!("`{s}`: odd number of hex digits"));
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|_| format!("`{s}`: invalid hex")))
        .collect()
}

fn print(value: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&value).expect("serializable"));
}

fn run(cli: Cli) -> Result<u8, String> {
    let runtime = Runtime::new(cli.limits.limits());
    match cli.command {
        Command::Inspect { module } => match runtime.load_file(&module) {
            Ok(v) => {
                print(json!({
                    "valid": true,
                    "id": v.id(),
                    "size": v.size(),
                    "meta": v.meta(),
                    "imports": v.imports(),
                    "exports": v.exports(),
                }));
                Ok(EXIT_VALID)
            }
            Err(LoadError::Rejected(violations)) => {
                print(json!({"valid": false, "violations": violations}));
                Ok(EXIT_INVALID)
            }
            Err(e) => Err(e.to_string()),
        },
        Command::List { dir } => {
            let registry = Registry::load_dir(&runtime, &dir).map_err(|e| e.to_string())?;
            let list: Vec<_> = registry
                .names()
                .map(|n| {
                    let v = registry.get(n).expect("listed name");
                    json!({"name": n, "id": v.id(), "size": v.size(), "version": v.meta().map(|m| m.version.clone())})
                })
                .collect();
            print(json!(list));
            Ok(EXIT_VALID)
        }
        Command::Verify { verifier, registry, proof, public } => {
            let proof = parse_input(&proof)?;
            let public = parse_input(&public)?;
            let loaded = match registry {
                Some(dir) => {
                    let registry = Registry::load_dir(&runtime, &dir).map_err(|e| e.to_string())?;
                    registry.get(&verifier).cloned().ok_or_else(|| {
                        format!(
                            "no verifier `{verifier}` in {} (have: {})",
                            dir.display(),
                            registry.names().collect::<Vec<_>>().join(", ")
                        )
                    })?
                }
                None => runtime.load_file(Path::new(&verifier)).map_err(|e| e.to_string())?,
            };
            let execution = runtime.verify(&loaded, &proof, &public).map_err(|e| e.to_string())?;
            let code = match execution.outcome {
                Outcome::Valid => EXIT_VALID,
                Outcome::Invalid | Outcome::Rejected(_) => EXIT_INVALID,
                _ => EXIT_FAILED,
            };
            let mut out = serde_json::to_value(&execution).expect("serializable");
            out["verifier"] = json!(loaded.name().unwrap_or(loaded.id()));
            print(out);
            Ok(code)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("eth-wasm-verifier: {e}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
