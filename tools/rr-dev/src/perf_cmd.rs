//! CLI dispatch for `cargo dev perf` subcommands.
//!
//! Keeps typed clap command handling out of `main` so perf domain modules
//! (`perf::*`) stay focused on measurement and evidence while this module owns
//! `ExitCode` mapping for the perf surface.

use std::{path::Path, process::ExitCode};

use crate::cli::{EnvironmentTool, PerfCommand};
use crate::perf;

/// Dispatches a `cargo dev perf` subcommand.
#[allow(
    clippy::too_many_lines,
    reason = "each perf subcommand remains an explicit typed dispatch arm"
)]
pub(crate) fn run_perf(repo: &Path, command: PerfCommand) -> ExitCode {
    match command {
        PerfCommand::Evaluate { manifest, output } => {
            match perf::report::evaluate_to_file(&manifest, &output) {
                Ok(verdict) => {
                    println!("{}: {}", verdict.as_str(), output.display());
                    ExitCode::from(verdict.exit_code())
                }
                Err(error) => {
                    // An argument or write failure, distinct from inadmissible
                    // evidence: no report is produced at all.
                    eprintln!("perf evaluate: {error}");
                    ExitCode::from(2)
                }
            }
        }
        PerfCommand::Hotspot {
            binary,
            binary_sha256,
            expected_source_commit,
            pid,
            out_dir,
            run_id,
            record_seconds,
            event,
            frequency,
            call_graph,
        } => {
            match perf::hotspot::run(&perf::hotspot::Plan {
                binary,
                binary_sha256,
                expected_source_commit,
                server_pid: pid,
                out_dir,
                run_id,
                record_seconds,
                event,
                frequency,
                call_graph,
            }) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("perf hotspot: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        PerfCommand::Freeze { commit, out_dir } => {
            match perf::freeze::run(&perf::freeze::Plan {
                repo: repo.to_path_buf(),
                commit,
                out_dir,
            }) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("perf freeze: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        PerfCommand::HotspotBundle {
            run_dir,
            label,
            dso_offset,
            idalib_python,
            timeout_seconds,
            max_unmapped_period_percent,
            unmapped_period_explanation,
        } => match perf::hotspot::bundle::run(&perf::hotspot::bundle::Plan {
            run_dir,
            label,
            dso_offset,
            idalib_python,
            timeout_seconds,
            max_unmapped_period_percent,
            unmapped_period_explanation,
        }) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("perf hotspot-bundle: {error}");
                ExitCode::FAILURE
            }
        },
        PerfCommand::Environment {
            tool,
            output,
            binary,
            binary_sha256,
            command,
        } => {
            let kind = match tool {
                EnvironmentTool::Stat => perf::environment::Kind::Stat,
                EnvironmentTool::C2c => perf::environment::Kind::C2c,
            };
            match perf::environment::capture(
                kind,
                &perf::environment::Options {
                    output: &output,
                    binary: &binary,
                    binary_sha256: &binary_sha256,
                    command: &command,
                },
            ) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("perf environment: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
