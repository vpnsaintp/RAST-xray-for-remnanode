//! Process-lifetime per-user traffic counters for a panel-managed entry node.
//!
//! A session holds one counter handle across immutable config generations. A
//! reload can revoke its UUID for new handshakes without losing bytes already
//! transferred by an old session. Hot-path increments never take the registry
//! mutex; only the first connection for a user and snapshot reads do.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::Serialize;

use crate::protocol::vless::UserId;

type UserCounterRegistry = HashMap<(UserId, String), Arc<UserCounter>>;

#[derive(Clone, Debug)]
pub struct UsageLedger {
    inner: Arc<Mutex<UserCounterRegistry>>,
    boot_id: Arc<[u8; 16]>,
    generation: Arc<AtomicU64>,
    active_panel_ids: Arc<Mutex<Vec<u64>>>,
}

#[derive(Debug)]
struct UserCounter {
    label: String,
    uplink: AtomicU64,
    downlink: AtomicU64,
    online: Mutex<HashMap<IpAddr, u32>>,
}

/// One authenticated user's counters. A missing label is deliberately not
/// published to a panel because a UUID is a credential, not an accounting ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageSnapshot {
    pub label: String,
    pub uplink: u64,
    pub downlink: u64,
    pub online_ips: Vec<IpAddr>,
}

impl Default for UsageLedger {
    fn default() -> Self {
        let mut boot_id = [0_u8; 16];
        crate::crypto::entropy::fill(&mut boot_id)
            .expect("accounting boot ID requires system entropy");
        Self {
            inner: Arc::default(),
            boot_id: Arc::new(boot_id),
            generation: Arc::new(AtomicU64::new(0)),
            active_panel_ids: Arc::default(),
        }
    }
}

/// One live authenticated session. Dropping it removes only its online mark;
/// accumulated bytes remain available through the process-lifetime ledger.
#[derive(Debug)]
pub struct UsageSession {
    counter: Arc<UserCounter>,
    peer: Option<IpAddr>,
}

impl UsageLedger {
    /// Identifies one counter epoch, including after a process restart.
    #[must_use]
    pub fn boot_id(&self) -> String {
        self.boot_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn set_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::Release);
    }

    #[must_use]
    pub fn active_panel_ids(&self) -> Vec<u64> {
        self.active_panel_ids
            .lock()
            .expect("active panel ID lock poisoned")
            .clone()
    }

    pub(crate) fn set_active_panel_ids(&self, ids: impl IntoIterator<Item = u64>) {
        let mut values: Vec<_> = ids.into_iter().filter(|id| *id > 0).collect();
        values.sort_unstable();
        values.dedup();
        *self
            .active_panel_ids
            .lock()
            .expect("active panel ID lock poisoned") = values;
    }

    /// Starts accounting only when the configuration supplies a positive
    /// decimal panel user ID. Never infer an ID from the secret UUID or a
    /// human-readable label, and canonicalize leading zeroes.
    #[must_use]
    pub fn start(
        &self,
        user_id: UserId,
        label: Option<&str>,
        peer: Option<IpAddr>,
    ) -> Option<UsageSession> {
        let panel_id = label?.parse::<u64>().ok().filter(|id| *id > 0)?;
        let label = panel_id.to_string();
        let counter = {
            let mut users = self.inner.lock().expect("usage registry lock poisoned");
            Arc::clone(users.entry((user_id, label.clone())).or_insert_with(|| {
                Arc::new(UserCounter {
                    label: label.clone(),
                    uplink: AtomicU64::new(0),
                    downlink: AtomicU64::new(0),
                    online: Mutex::new(HashMap::new()),
                })
            }))
        };
        if let Some(ip) = peer {
            let mut online = counter
                .online
                .lock()
                .expect("online registry lock poisoned");
            let active = online.entry(ip).or_default();
            *active = active.saturating_add(1);
        }
        Some(UsageSession { counter, peer })
    }

    /// Reads all known users. Reset uses atomic swaps so concurrent writes are
    /// assigned to exactly one polling window.
    #[must_use]
    pub fn snapshot(&self, reset: bool) -> Vec<UsageSnapshot> {
        let users = self.inner.lock().expect("usage registry lock poisoned");
        let mut grouped = BTreeMap::<String, UsageSnapshot>::new();
        for counter in users.values() {
            let read = |value: &AtomicU64| {
                if reset {
                    value.swap(0, Ordering::AcqRel)
                } else {
                    value.load(Ordering::Acquire)
                }
            };
            let mut online_ips = counter
                .online
                .lock()
                .expect("online registry lock poisoned")
                .keys()
                .copied()
                .collect::<Vec<_>>();
            online_ips.sort_unstable();
            let entry = grouped
                .entry(counter.label.clone())
                .or_insert_with(|| UsageSnapshot {
                    label: counter.label.clone(),
                    uplink: 0,
                    downlink: 0,
                    online_ips: Vec::new(),
                });
            entry.uplink = entry.uplink.saturating_add(read(&counter.uplink));
            entry.downlink = entry.downlink.saturating_add(read(&counter.downlink));
            entry.online_ips.append(&mut online_ips);
        }
        for snapshot in grouped.values_mut() {
            snapshot.online_ips.sort_unstable();
            snapshot.online_ips.dedup();
        }
        grouped.into_values().collect()
    }
}

impl UsageSession {
    pub fn uplink(&self, bytes: u64) {
        while self
            .counter
            .uplink
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(bytes))
            })
            .is_err()
        {}
    }

    pub fn downlink(&self, bytes: u64) {
        while self
            .counter
            .downlink
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(bytes))
            })
            .is_err()
        {}
    }
}

impl Drop for UsageSession {
    fn drop(&mut self) {
        if let Some(ip) = self.peer {
            let mut online = self
                .counter
                .online
                .lock()
                .expect("online registry lock poisoned");
            if let Some(active) = online.get_mut(&ip) {
                *active = active.saturating_sub(1);
                if *active == 0 {
                    online.remove(&ip);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UsageLedger;
    use crate::protocol::vless::UserId;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn reset_keeps_active_session_and_counts_each_window_once() {
        let ledger = UsageLedger::default();
        let user = UserId::new([7; 16]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let session = ledger.start(user, Some("5197"), Some(ip)).unwrap();
        session.uplink(64);
        session.downlink(128);
        assert_eq!(ledger.snapshot(true)[0].uplink, 64);
        assert_eq!(ledger.snapshot(true)[0].downlink, 0);
        assert_eq!(ledger.snapshot(false)[0].online_ips, [ip]);
        session.uplink(7);
        assert_eq!(ledger.snapshot(true)[0].uplink, 7);
        drop(session);
        assert!(ledger.snapshot(false)[0].online_ips.is_empty());
    }

    #[test]
    fn credential_without_panel_label_is_not_published() {
        let ledger = UsageLedger::default();
        assert!(ledger.start(UserId::new([9; 16]), None, None).is_none());
        assert!(ledger.snapshot(false).is_empty());
    }

    #[test]
    fn non_numeric_label_cannot_be_credited_to_a_panel_user() {
        let ledger = UsageLedger::default();
        let user = UserId::new([11; 16]);
        assert!(ledger.start(user, Some("customer-a"), None).is_none());
        assert!(ledger.start(user, Some("0"), None).is_none());
        let session = ledger.start(user, Some("00042"), None).unwrap();
        session.uplink(5);
        assert_eq!(ledger.snapshot(false)[0].label, "42");
    }

    #[test]
    fn changed_label_keeps_old_session_accounted() {
        let ledger = UsageLedger::default();
        let user = UserId::new([10; 16]);
        let old = ledger.start(user, Some("101"), None).unwrap();
        let new = ledger.start(user, Some("202"), None).unwrap();
        old.downlink(5);
        new.downlink(7);
        let snapshot = ledger.snapshot(true);
        assert_eq!(snapshot.len(), 2);
        assert_eq!(
            (snapshot[0].label.as_str(), snapshot[0].downlink),
            ("101", 5)
        );
        assert_eq!(
            (snapshot[1].label.as_str(), snapshot[1].downlink),
            ("202", 7)
        );
    }

    #[test]
    fn multiple_credentials_for_one_panel_user_are_grouped() {
        let ledger = UsageLedger::default();
        let first = ledger
            .start(UserId::new([1; 16]), Some("5197"), None)
            .unwrap();
        let second = ledger
            .start(UserId::new([2; 16]), Some("5197"), None)
            .unwrap();
        first.uplink(11);
        second.uplink(23);
        assert_eq!(ledger.snapshot(true)[0].uplink, 34);
        assert_eq!(ledger.snapshot(true)[0].uplink, 0);
    }

    #[test]
    fn concurrent_sessions_for_one_user_do_not_lose_bytes() {
        use std::sync::{Arc, Barrier};

        const WORKERS: usize = 8;
        const WRITES: u64 = 20_000;
        let ledger = UsageLedger::default();
        let barrier = Arc::new(Barrier::new(WORKERS));
        let user = UserId::new([3; 16]);
        std::thread::scope(|scope| {
            for _ in 0..WORKERS {
                let barrier = Arc::clone(&barrier);
                let ledger = &ledger;
                scope.spawn(move || {
                    let session = ledger.start(user, Some("5197"), None).unwrap();
                    barrier.wait();
                    for _ in 0..WRITES {
                        session.uplink(1);
                        session.downlink(2);
                    }
                });
            }
        });
        let snapshot = ledger.snapshot(true);
        assert_eq!(snapshot[0].uplink, WORKERS as u64 * WRITES);
        assert_eq!(snapshot[0].downlink, WORKERS as u64 * WRITES * 2);
    }
}
