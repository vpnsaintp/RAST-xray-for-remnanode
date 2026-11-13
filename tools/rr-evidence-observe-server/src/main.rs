//! Evidence-only server wrapper for Idle vs Observed telemetry cost measurement.
//!
//! This binary is **not** a product artifact and **not** a network management
//! endpoint. It exists so a paired setup-rate run can compare:
//!
//! - **Idle:** `observe.hz` sidecar = `0` (no `TransportTelemetry::snapshot` calls)
//! - **Observed:** `observe.hz` sidecar = `1` (external-to-data-plane task calls
//!   `snapshot()` at 1 Hz)
//!
//! Both legs use **byte-identical copies** of this ELF. The freeze product ELF
//! cannot expose the in-process observer API; this harness links the same
//! `src/` as tip `d6a9ea0` (docs-only delta on the audit branch) and speaks the
//! operator `run --config` / `--version` surface the setup-rate suite already
//! drives. No production hot-path shortcut and no invented product CLI flag.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::OnceLock,
    time::Duration,
};

use clap::{Parser, Subcommand};
use rust_reality::{
    BUILD_COMMIT, config::load, runtime::machine::MachineReport,
    server::production::ProductionServer,
};

/// Sidecar filename next to this executable (`0` = Idle, `1` = Observed @ 1 Hz).
const OBSERVE_HZ_SIDECAR: &str = "observe.hz";

fn long_version() -> &'static str {
    static LONG_VERSION: OnceLock<String> = OnceLock::new();
    LONG_VERSION
        .get_or_init(|| format!("2.0.2\ncommit: {BUILD_COMMIT}"))
        .as_str()
}

#[derive(Debug, Parser)]
#[command(
    name = "rust-reality",
    version,
    long_version = long_version(),
    about = "Evidence harness: ProductionServer + optional TransportTelemetry::snapshot poller"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve traffic until SIGINT or SIGTERM (setup-rate slot entrypoint).
    #[command(alias = "serve")]
    Run {
        /// Path to a rust-reality configuration file.
        #[arg(long)]
        config: PathBuf,
    },
}

fn observe_hz() -> u32 {
    let Ok(exe) = std::env::current_exe() else {
        return 0;
    };
    read_observe_hz(&exe)
}

fn read_observe_hz(exe: &Path) -> u32 {
    let sidecar = exe.with_file_name(OBSERVE_HZ_SIDECAR);
    std::fs::read_to_string(&sidecar)
        .ok()
        .and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Some(0);
            }
            trimmed.parse::<u32>().ok()
        })
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { config } => match serve(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn serve(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let hz = observe_hz();
    // Evidence marker only — never a product log. Slot server.log proves Idle vs Observed.
    eprintln!("rr-evidence-observe-server: observe_hz={hz}");
    let config = load(&config_path)?;
    let machine = MachineReport::detect();
    let resource_mode = rust_reality::runtime::policy::resolve_resource_mode(
        config.node().runtime().profile(),
        &machine,
    );
    let topology = rust_reality::runtime::plan::RuntimeTopology::for_mode(
        resource_mode,
        machine.effective_cpus(),
    );
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(worker_threads) = topology.worker_threads {
        builder.worker_threads(worker_threads);
    }
    if let Some(max_blocking_threads) = topology.max_blocking_threads {
        builder.max_blocking_threads(max_blocking_threads);
    }
    let runtime = builder.enable_all().build()?;
    let server = ProductionServer::from_loaded(config, Some(config_path), machine)?;
    let observer = server.telemetry();

    let result = runtime.block_on(async move {
        let observe_task = if hz == 0 {
            None
        } else {
            let period = Duration::from_secs(1) / hz.max(1);
            // Cap: sidecar is documented as 0 or 1; refuse accidental busy loops.
            let period = period.max(Duration::from_millis(100));
            Some(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(period);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    // black_box keeps the snapshot call observable to the CPU
                    // under test; result is intentionally unused (secret-free).
                    std::hint::black_box(observer.snapshot());
                }
            }))
        };

        let run_result = server.run().await;
        if let Some(task) = observe_task {
            task.abort();
            let _ = task.await;
        }
        run_result
    });
    runtime.shutdown_timeout(Duration::from_secs(5));
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn missing_sidecar_means_idle() {
        let dir = tempfile_dir();
        let exe = dir.join("server");
        fs::write(&exe, b"x").unwrap();
        assert_eq!(read_observe_hz(&exe), 0);
    }

    #[test]
    fn sidecar_one_selects_observed() {
        let dir = tempfile_dir();
        let exe = dir.join("server");
        fs::write(&exe, b"x").unwrap();
        fs::write(dir.join(OBSERVE_HZ_SIDECAR), "1\n").unwrap();
        assert_eq!(read_observe_hz(&exe), 1);
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rr-evidence-observe-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
