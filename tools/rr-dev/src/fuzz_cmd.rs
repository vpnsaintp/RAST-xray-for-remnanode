//! CLI dispatch for `cargo dev fuzz` subcommands.
//!
//! Keeps typed clap command handling out of `main` so fuzz domain modules
//! (`fuzz::*`) stay focused on target discovery and smoke execution while this
//! module owns `ExitCode` mapping for the fuzz surface.

use std::{path::Path, process::ExitCode};

use crate::cli::FuzzCommand;
use crate::fuzz;

/// Dispatches a `cargo dev fuzz` subcommand.
///
/// `targets` prints the validated (optionally sharded) target list, one per line,
/// as the retired `fuzz-targets.py` did. `smoke` runs the deterministic libFuzzer
/// pass; with a shard it resolves that shard first, collapsing the shell pipeline
/// `security.yml` used into one invocation.
pub(crate) fn run_fuzz(repo: &Path, command: FuzzCommand) -> ExitCode {
    match command {
        FuzzCommand::Targets {
            shard_index,
            shard_count,
        } => {
            let names = match resolve_targets(repo, shard_index, shard_count) {
                Ok(names) => names,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            println!("{}", names.join("\n"));
            ExitCode::SUCCESS
        }
        FuzzCommand::Smoke {
            targets,
            shard_index,
            shard_count,
        } => {
            let selected = if shard_index.is_some() || shard_count.is_some() {
                if !targets.is_empty() {
                    eprintln!("fuzz smoke: pass either explicit targets or a shard, not both");
                    return ExitCode::FAILURE;
                }
                match resolve_targets(repo, shard_index, shard_count) {
                    Ok(names) => names,
                    Err(error) => {
                        eprintln!("{error}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                targets
            };
            match fuzz::smoke::smoke(repo, &selected) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// Resolves the full or sharded target list, requiring both shard arguments together.
fn resolve_targets(
    repo: &Path,
    shard_index: Option<usize>,
    shard_count: Option<usize>,
) -> Result<Vec<String>, String> {
    match (shard_index, shard_count) {
        (None, None) => fuzz::targets::all(repo).map_err(|error| error.to_string()),
        (Some(index), Some(count)) => {
            fuzz::targets::shard(repo, index, count).map_err(|error| error.to_string())
        }
        _ => Err("--shard-index and --shard-count must be supplied together".to_owned()),
    }
}
