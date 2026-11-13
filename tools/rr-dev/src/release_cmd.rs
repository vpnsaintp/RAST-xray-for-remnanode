//! CLI dispatch for `cargo dev release` subcommands.
//!
//! Keeps typed clap command handling out of `main` so release domain modules
//! (`release::*`) stay focused on matrix, packaging, and verification while this
//! module owns `ExitCode` mapping for the release surface.

use std::{path::Path, process::ExitCode};

use crate::cli::ReleaseCommand;
use crate::release;

/// Dispatches a `cargo dev release` subcommand.
///
/// Each stage prints its own success line and maps a domain error onto a single
/// non-zero exit. Release stages are fail-closed: a stage that cannot prove its
/// invariant returns an error rather than a partial success.
pub(crate) fn run_release(repo: &Path, command: ReleaseCommand) -> ExitCode {
    let result = match command {
        ReleaseCommand::Matrix {
            github_matrix,
            tiers,
        } => {
            if github_matrix {
                println!("{}", release::matrix::github_matrix());
            } else if tiers {
                println!("{}", release::matrix::Tier::ids().join(" "));
            } else {
                for tier in &release::matrix::TIERS {
                    println!(
                        "{}\t{}\t{}\t{}",
                        tier.id, tier.target, tier.target_cpu, tier.runs_on
                    );
                }
            }
            Ok(String::new())
        }
        ReleaseCommand::VerifyTag { tag, main_ref } => {
            release::verify_tag::verify(repo, &tag, &main_ref)
        }
        ReleaseCommand::Build { tier, build_only } => {
            release::build::build(repo, &tier, build_only)
        }
        ReleaseCommand::Package { tag, tier, output } => {
            release::package::package(&release::package::Options {
                repo,
                tag: &tag,
                tier: &tier,
                output: &output,
                binary_override: std::env::var_os("RUST_REALITY_RELEASE_BIN").map(Into::into),
                cargo_features: std::env::var("RUST_REALITY_CARGO_FEATURES").ok(),
                measured_natively: std::env::var("RUST_REALITY_MEASURED_NATIVELY")
                    .ok()
                    .map(|value| value == "true"),
            })
            .map(|packaged| {
                format!(
                    "packaged {tier} -> {} (sha256 {}, fragment {})",
                    packaged.archive.display(),
                    packaged.sha256,
                    packaged.fragment.display()
                )
            })
        }
        ReleaseCommand::Smoke {
            tag,
            tier,
            assets,
            receipt_dir,
        } => release::smoke::smoke(repo, &tag, &tier, &assets, receipt_dir.as_deref()),
        ReleaseCommand::Aggregate { tag, dist } => release::aggregate::aggregate(&dist, &tag),
    };

    match result {
        Ok(message) => {
            if !message.is_empty() {
                println!("{message}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
