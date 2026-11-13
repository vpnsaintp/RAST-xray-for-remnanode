//! `rr-dev` — the repository's development control plane.
//!
//! One typed entry point for repository policy that used to live scattered across
//! shell and Python programs. `rr-dev` orchestrates external tools; it does not
//! reimplement them, and it does not build shell command lines.
//!
//! Normal use is through the root cargo alias, so no one has to know where this
//! crate lives:
//!
//! ```text
//! cargo dev doctor
//! cargo dev check
//! cargo dev check --all
//! cargo dev repo check
//! ```

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;

mod bench;
mod bench_cmd;
mod check;
mod checks;
mod ci;
mod cli;
mod deploy;
mod deploy_cmd;
mod docs;
mod doctor;
mod fuzz;
mod fuzz_cmd;
mod hash;
mod perf;
mod perf_cmd;
mod process;
mod release;
mod release_cmd;
mod repo;

use cli::{CiCommand, Cli, Command, ConfigCommand, DocsCommand, RepoCommand};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let repo = cli.repo.unwrap_or_else(default_repo_root);

    match cli.command {
        Command::Doctor => run_doctor(),
        Command::Perf { command } => perf_cmd::run_perf(&repo, command),
        Command::Release { command } => release_cmd::run_release(&repo, command),
        Command::Fuzz { command } => fuzz_cmd::run_fuzz(&repo, command),
        Command::Config { command } => match command {
            ConfigCommand::Schema { output } => match rust_reality::config::node::schema_json() {
                Ok(schema) => {
                    if let Some(path) = output {
                        match std::fs::write(&path, &schema) {
                            Ok(()) => ExitCode::SUCCESS,
                            Err(error) => {
                                eprintln!("config schema: {error}");
                                ExitCode::FAILURE
                            }
                        }
                    } else {
                        print!("{schema}");
                        ExitCode::SUCCESS
                    }
                }
                Err(error) => {
                    eprintln!("config schema: {error}");
                    ExitCode::FAILURE
                }
            },
            ConfigCommand::Fingerprint { config, output } => {
                match checks::config_identity::report(&config) {
                    Ok(report) => {
                        let rendered = report.to_python_json();
                        if let Some(path) = output {
                            match std::fs::write(&path, &rendered) {
                                Ok(()) => ExitCode::SUCCESS,
                                Err(error) => {
                                    eprintln!("config fingerprint: {error}");
                                    ExitCode::FAILURE
                                }
                            }
                        } else {
                            print!("{rendered}");
                            ExitCode::SUCCESS
                        }
                    }
                    Err(error) => {
                        eprintln!("config fingerprint: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
        },
        Command::Bench { command } => bench_cmd::run_bench(&repo, &command),
        Command::Deploy { command } => deploy_cmd::run_deploy(&repo, command),
        Command::Docs { command } => match command {
            DocsCommand::Check => {
                let report = docs::check(&repo);
                if report.is_clean() {
                    println!("{}", report.render());
                    ExitCode::SUCCESS
                } else {
                    eprint!("{}", report.render());
                    ExitCode::FAILURE
                }
            }
        },
        Command::Repo { command } => match command {
            RepoCommand::Check => {
                let report = repo::check(&repo);
                if report.is_clean() {
                    println!("{}", report.render());
                    ExitCode::SUCCESS
                } else {
                    eprint!("{}", report.render());
                    ExitCode::FAILURE
                }
            }
        },
        Command::Ci { command } => run_ci(command),
        Command::Check {
            all,
            output,
            log_dir,
        } => {
            let scope = if all {
                check::Scope::All
            } else {
                check::Scope::Fast
            };
            if check::run(&repo, scope, output, log_dir.as_deref()) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Dispatches a `cargo-dev ci` subcommand.
fn run_ci(command: CiCommand) -> ExitCode {
    match command {
        CiCommand::GhaShell { script } => match ci::run_gha_shell(&script) {
            Ok(status) => {
                let code = ci::shell_exit_code(status);
                ExitCode::from(u8::try_from(code).unwrap_or(1))
            }
            Err(error) => {
                eprintln!("ci gha-shell: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Resolves the repository root from this crate's compile-time location.
///
/// `tools/rr-dev` sits two levels below the checkout root, so the tool works from
/// any current directory without an environment variable or a search heuristic.
fn default_repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// Prints the environment diagnosis and fails only on a blocking finding.
///
/// A restricted capability, such as an installed `perf` whose PMU is blocked by
/// `perf_event_paranoid`, is reported prominently but is not an error: it is a
/// true fact about the host that the developer needs, not a broken setup.
fn run_doctor() -> ExitCode {
    let findings = doctor::diagnose();
    let mut blocking = Vec::new();
    let mut restricted = Vec::new();

    println!("{:<14} {:<9} {:<12} detail", "capability", "need", "status");
    println!("{}", "-".repeat(80).as_str());
    for finding in &findings {
        println!("{finding}");
        if finding.availability.is_blocking() {
            blocking.push(finding.name);
        } else if finding.availability == doctor::Availability::Restricted {
            restricted.push(finding.name);
        }
    }

    if !restricted.is_empty() {
        println!("\nrestricted: {}", restricted.join(", "));
        println!(
            "a restricted capability is present but limited by policy or kernel settings. \
             Record the affected questions as pending; do not estimate the numbers it \
             would have produced."
        );
    }

    if blocking.is_empty() {
        println!("\nthis host can build, test and check the repository");
        return ExitCode::SUCCESS;
    }
    eprintln!("\nmissing requirements: {}", blocking.join(", "));
    ExitCode::FAILURE
}
