//! Local accounting feed and authenticated-by-filesystem session control.
//!
//! Set `RUST_REALITY_MANAGEMENT_SOCKET` to an absolute path in a directory
//! accessible only to the node operator. Each Unix-socket connection receives
//! one newline-terminated JSON snapshot and closes. A separate `.control`
//! socket accepts bounded `dropUsers` commands. Counters are cumulative;
//! consumers use `bootId` and their own durable cursor to calculate deltas.
//! There is no unauthenticated TCP listener and no reset command that could
//! discard traffic on a lost response.

use std::{
    io,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Serialize;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    time::timeout,
};

use crate::{
    accounting::{UsageLedger, UsageSnapshot},
    revocation::SessionRevoker,
};

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_millis(150);
const MAX_COMMAND: usize = 8192;

/// Parse the one bounded local control command. Exposed for the fuzz harness;
/// the Unix socket itself still enforces private filesystem permissions.
pub fn parse_drop_users_command(command: &[u8]) -> Option<Vec<u64>> {
    if command.len() > MAX_COMMAND || command.last() != Some(&b'\n') {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(command).ok()?;
    if value.get("command")?.as_str()? != "dropUsers" {
        return None;
    }
    let values = value.get("userIds")?.as_array()?;
    if values.is_empty() || values.len() > 1000 {
        return None;
    }
    values
        .iter()
        .map(serde_json::Value::as_u64)
        .collect::<Option<Vec<_>>>()
        .filter(|ids| ids.iter().all(|id| *id > 0))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagementSnapshot {
    version: u8,
    boot_id: String,
    generation: u64,
    active_panel_ids: Vec<u64>,
    users: Vec<UsageSnapshot>,
}

/// Owns one private Unix socket and cleans its path on orderly shutdown.
pub struct ManagementSocket {
    listener: UnixListener,
    control_listener: UnixListener,
    path: PathBuf,
    control_path: PathBuf,
    device: u64,
    inode: u64,
    control_device: u64,
    control_inode: u64,
}

impl ManagementSocket {
    /// Bind only in an existing private directory; never replace a socket that
    /// might belong to a running daemon.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "management socket must be absolute",
            ));
        }
        let listener = UnixListener::bind(path)?;
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        let metadata = std::fs::metadata(path)?;
        let mut control_name = path.as_os_str().to_os_string();
        control_name.push(".control");
        let control_path = PathBuf::from(control_name);
        let control_listener = match UnixListener::bind(&control_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = std::fs::remove_file(path);
                return Err(error);
            }
        };
        if let Err(error) =
            std::fs::set_permissions(&control_path, std::fs::Permissions::from_mode(0o600))
        {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(&control_path);
            return Err(error);
        }
        let control_metadata = std::fs::metadata(&control_path)?;
        Ok(Self {
            listener,
            control_listener,
            path: path.to_path_buf(),
            control_path,
            device: metadata.dev(),
            inode: metadata.ino(),
            control_device: control_metadata.dev(),
            control_inode: control_metadata.ino(),
        })
    }

    /// Serve cumulative snapshots. A poisoned ledger or socket failure is
    /// fatal, so the service manager cannot mistake empty stats for zero usage.
    pub async fn serve(&self, ledger: UsageLedger, revoker: SessionRevoker) -> io::Result<()> {
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    self.write_snapshot(stream, &ledger).await?;
                }
                accepted = self.control_listener.accept() => {
                    let (stream, _) = accepted?;
                    self.handle_control(stream, &revoker).await?;
                }
            }
        }
    }

    async fn write_snapshot(&self, mut stream: UnixStream, ledger: &UsageLedger) -> io::Result<()> {
        let snapshot = ManagementSnapshot {
            version: 1,
            boot_id: ledger.boot_id(),
            generation: ledger.generation(),
            active_panel_ids: ledger.active_panel_ids(),
            users: ledger.snapshot(false),
        };
        let mut encoded = serde_json::to_vec(&snapshot)?;
        encoded.push(b'\n');
        let _ = timeout(WRITE_TIMEOUT, stream.write_all(&encoded)).await;
        Ok(())
    }

    async fn handle_control(
        &self,
        mut stream: UnixStream,
        revoker: &SessionRevoker,
    ) -> io::Result<()> {
        let mut command = Vec::new();
        let read = timeout(COMMAND_TIMEOUT, async {
            while command.last() != Some(&b'\n') && command.len() < MAX_COMMAND {
                let mut byte = [0_u8; 1];
                if stream.read(&mut byte).await? == 0 {
                    break;
                }
                command.push(byte[0]);
            }
            Ok::<(), io::Error>(())
        })
        .await;
        let ids = if matches!(read, Ok(Ok(()))) {
            parse_drop_users_command(&command)
        } else {
            None
        };
        let response = if let Some(ids) = ids {
            serde_json::json!({"version": 1, "droppedSessions": revoker.drop_users(&ids)})
        } else {
            serde_json::json!({"version": 1, "error": "invalid command"})
        };
        let mut encoded = serde_json::to_vec(&response)?;
        encoded.push(b'\n');
        let _ = timeout(WRITE_TIMEOUT, stream.write_all(&encoded)).await;
        Ok(())
    }
}

impl Drop for ManagementSocket {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
        if let Ok(metadata) = std::fs::symlink_metadata(&self.control_path)
            && metadata.dev() == self.control_device
            && metadata.ino() == self.control_inode
        {
            let _ = std::fs::remove_file(&self.control_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn private_socket_reports_one_cumulative_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "rust-reality-management-{}-{}.sock",
            std::process::id(),
            17
        ));
        let socket = ManagementSocket::bind(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(format!("{}.control", path.display()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let ledger = UsageLedger::default();
        let service =
            tokio::spawn(async move { socket.serve(ledger, SessionRevoker::default()).await });
        let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(body["version"], 1);
        assert_eq!(body["users"], serde_json::json!([]));
        assert_eq!(body["bootId"].as_str().unwrap().len(), 32);
        assert_eq!(body["generation"], 0);
        assert_eq!(body["activePanelIds"], serde_json::json!([]));
        service.abort();
        let _ = service.await;
        assert!(!path.exists());
        assert!(!PathBuf::from(format!("{}.control", path.display())).exists());
    }

    #[tokio::test]
    async fn drop_users_command_cancels_only_matching_active_session() {
        let path = std::env::temp_dir().join(format!(
            "rust-reality-revoke-{}-{}.sock",
            std::process::id(),
            18
        ));
        let socket = ManagementSocket::bind(&path).unwrap();
        let revoker = SessionRevoker::default();
        // The process registry is populated by a compiled config generation.
        let users = [
            crate::protocol::vless::UserId::new([1; 16]),
            crate::protocol::vless::UserId::new([2; 16]),
        ];
        revoker.publish_identities([(users[0], 10), (users[1], 20)].into_iter().collect());
        let mut first = revoker.register(users[0], 10).unwrap();
        let mut second = revoker.register(users[1], 20).unwrap();
        let service_revoker = revoker.clone();
        let service =
            tokio::spawn(
                async move { socket.serve(UsageLedger::default(), service_revoker).await },
            );
        let mut client = tokio::net::UnixStream::connect(format!("{}.control", path.display()))
            .await
            .unwrap();
        client
            .write_all(b"{\"command\":\"dropUsers\",\"userIds\":[10]}\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(body["droppedSessions"], 1);
        tokio::time::timeout(Duration::from_millis(50), first.cancelled())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), second.cancelled())
                .await
                .is_err()
        );
        service.abort();
        let _ = service.await;
    }
}
