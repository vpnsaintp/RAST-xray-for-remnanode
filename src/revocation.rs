//! Process-lifetime identity and live-session revocation for panel users.
//!
//! TCP peers are often a local HAProxy or a bridge, so kernel IP-based socket
//! destruction cannot identify one panel user. Each authenticated session
//! holds a cancellation lease keyed by its panel ID and VLESS UUID.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::sync::watch;

use crate::{config::node::NodeConfig, protocol::vless::UserId};

#[derive(Clone, Default)]
pub struct SessionRevoker(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    current: HashMap<UserId, u64>,
    sessions: HashMap<u64, HashMap<u64, watch::Sender<bool>>>,
    next_token: u64,
}

pub struct SessionLease {
    registry: SessionRevoker,
    panel_id: u64,
    token: u64,
    cancelled: watch::Receiver<bool>,
}

impl SessionRevoker {
    /// Publish the identities of a successfully compiled generation. Old
    /// snapshots cannot admit a removed or rotated UUID after this update.
    pub(crate) fn publish(&self, node: &NodeConfig) {
        let mut current = HashMap::new();
        match node {
            NodeConfig::Entry(entry) => {
                for user in &entry.users {
                    if let Some(panel_id) = user.panel_user_id
                        && let Ok(uuid) = uuid::Uuid::parse_str(&user.id)
                    {
                        current.insert(UserId::new(*uuid.as_bytes()), panel_id);
                    }
                }
            }
            NodeConfig::Landing(landing) => {
                for user in &landing.accounting_users {
                    if let Ok(uuid) = uuid::Uuid::parse_str(&user.id) {
                        current.insert(UserId::new(*uuid.as_bytes()), user.panel_user_id);
                    }
                }
            }
            NodeConfig::Client(_) => {}
        }
        self.publish_identities(current);
    }

    pub(crate) fn publish_identities(&self, current: HashMap<UserId, u64>) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = std::mem::replace(&mut state.current, current);
        let retired: Vec<u64> = state
            .sessions
            .keys()
            .copied()
            .filter(|id| {
                let old_uuid = previous
                    .iter()
                    .find_map(|(uuid, panel)| (*panel == *id).then_some(uuid));
                let new_uuid = state
                    .current
                    .iter()
                    .find_map(|(uuid, panel)| (*panel == *id).then_some(uuid));
                old_uuid != new_uuid
            })
            .collect();
        for id in retired {
            if let Some(sessions) = state.sessions.remove(&id) {
                for (_, sender) in sessions {
                    let _ = sender.send(true);
                }
            }
        }
    }

    /// Returns no lease if a session came from a retired config generation.
    pub(crate) fn register(&self, user: UserId, panel_id: u64) -> Option<SessionLease> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.current.get(&user) != Some(&panel_id) {
            return None;
        }
        state.next_token = state.next_token.checked_add(1)?;
        let token = state.next_token;
        let (sender, cancelled) = watch::channel(false);
        state
            .sessions
            .entry(panel_id)
            .or_default()
            .insert(token, sender);
        Some(SessionLease {
            registry: self.clone(),
            panel_id,
            token,
            cancelled,
        })
    }

    /// Cancel all existing sessions for the requested panel IDs. New sessions
    /// remain permitted only if their UUID is still in the current generation.
    pub fn drop_users(&self, ids: &[u64]) -> usize {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut count = 0;
        for id in ids {
            if let Some(sessions) = state.sessions.remove(id) {
                count += sessions.len();
                for (_, sender) in sessions {
                    let _ = sender.send(true);
                }
            }
        }
        count
    }
}

impl SessionLease {
    pub(crate) async fn cancelled(&mut self) {
        if *self.cancelled.borrow() {
            return;
        }
        let _ = self.cancelled.changed().await;
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        let mut state = self
            .registry
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(sessions) = state.sessions.get_mut(&self.panel_id) {
            sessions.remove(&self.token);
            if sessions.is_empty() {
                state.sessions.remove(&self.panel_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn cancels_only_selected_user_and_rejects_retired_identity() {
        let registry = SessionRevoker::default();
        let first = UserId::new([1; 16]);
        let second = UserId::new([2; 16]);
        {
            let mut state = registry.0.lock().unwrap();
            state.current.insert(first, 10);
            state.current.insert(second, 20);
        }
        let mut a = registry.register(first, 10).unwrap();
        let mut b = registry.register(second, 20).unwrap();
        assert_eq!(registry.drop_users(&[10]), 1);
        tokio::time::timeout(std::time::Duration::from_millis(50), a.cancelled())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), b.cancelled())
                .await
                .is_err()
        );
        assert!(registry.register(first, 10).is_some());
        registry.0.lock().unwrap().current.remove(&first);
        assert!(registry.register(first, 10).is_none());
    }

    #[tokio::test]
    async fn active_transfer_closes_and_new_auth_rejects_after_identity_retirement() {
        let registry = SessionRevoker::default();
        let user = UserId::new([3; 16]);
        registry.publish_identities([(user, 30)].into_iter().collect());
        let mut lease = registry.register(user, 30).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let relay = tokio::spawn(async move {
            tokio::select! {
                () = lease.cancelled() => {},
                () = async {
                    let mut byte = [0_u8; 1];
                    loop {
                        if server.read_exact(&mut byte).await.is_err() { break; }
                        if server.write_all(&byte).await.is_err() { break; }
                    }
                } => {},
            }
        });
        client.write_all(&[7]).await.unwrap();
        let mut echoed = [0_u8; 1];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, [7]);
        registry.publish_identities(HashMap::new());
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut echoed))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(registry.register(user, 30).is_none());
    }

    #[tokio::test]
    async fn rotate_and_remove_cancel_old_sessions_without_dropping_reused_panel_id() {
        let registry = SessionRevoker::default();
        let old = UserId::new([4; 16]);
        let new = UserId::new([5; 16]);
        registry.publish_identities([(old, 40)].into_iter().collect());
        let mut retired = registry.register(old, 40).unwrap();

        registry.publish_identities([(new, 40)].into_iter().collect());
        tokio::time::timeout(std::time::Duration::from_millis(50), retired.cancelled())
            .await
            .expect("rotated identity's live session must be revoked");
        assert!(registry.register(old, 40).is_none());

        let mut current = registry.register(new, 40).unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), current.cancelled())
                .await
                .is_err(),
            "new session using the same panel ID must remain live"
        );

        registry.publish_identities(HashMap::new());
        tokio::time::timeout(std::time::Duration::from_millis(50), current.cancelled())
            .await
            .expect("removing the identity must revoke its active session");
        assert!(registry.register(new, 40).is_none());
    }
}
