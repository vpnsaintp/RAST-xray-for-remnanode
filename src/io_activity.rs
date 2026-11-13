//! Connection activity, independent of either stream direction.
//!
//! A successful I/O event is one relaxed store, never a clock read, timer reset,
//! allocation, or wakeup. One coordinator samples the flag at idle-window
//! boundaries. Thus fully observed inactivity is reclaimed within two windows,
//! not an exact per-operation deadline. Writes have a separate stall deadline.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use crate::accounting::UsageSession;

/// Zero-config authenticated-session write-stall bound, unrelated to fallback.
pub const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Authenticated framed-session inactivity sampling window.
pub const SESSION_IDLE_WINDOW: Duration = Duration::from_secs(300);

/// Shared activity for one authenticated connection.
#[derive(Debug, Default)]
pub struct SessionActivity {
    progressed: AtomicBool,
    raw: AtomicBool,
    usage: Option<UsageSession>,
}

impl SessionActivity {
    /// Attaches one authenticated user's process-lifetime counters.
    #[must_use]
    pub fn with_usage(usage: Option<UsageSession>) -> Self {
        Self {
            usage,
            ..Self::default()
        }
    }

    /// Counts unpadded bytes delivered toward the destination.
    pub fn account_uplink(&self, bytes: u64) {
        if let Some(usage) = &self.usage {
            usage.uplink(bytes);
        }
    }

    /// Counts destination bytes delivered toward the client.
    pub fn account_downlink(&self, bytes: u64) {
        if let Some(usage) = &self.usage {
            usage.downlink(bytes);
        }
    }

    /// Records one successful nonempty read, write, or copy operation.
    pub fn progress(&self) {
        self.progressed.store(true, Ordering::Relaxed);
    }

    /// Raw transfer delegates quiet-connection lifetime to TCP keepalive and
    /// peer termination. This is monotonic and includes the still-framed peer:
    /// a Direct transition must never leave a short timer on half the session.
    pub fn enter_raw(&self) {
        self.raw.store(true, Ordering::Relaxed);
    }

    /// Waits for whole-session inactivity, never for one quiet direction.
    ///
    /// After raw transfer begins there is deliberately no user-space read-idle
    /// deadline. Admission/FD limits bound occupancy and kernel keepalive detects
    /// dead peers. A healthy quiet socket is not a resource leak.
    pub async fn expired(&self, window: Duration) {
        loop {
            tokio::time::sleep(window).await;
            if self.raw.load(Ordering::Relaxed) {
                std::future::pending::<()>().await;
            }
            if !self.progressed.swap(false, Ordering::Relaxed) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, pin::Pin, task::Poll};

    async fn ready(future: Pin<&mut impl Future<Output = ()>>) -> bool {
        let mut future = future;
        std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_ready())).await
    }

    #[tokio::test(start_paused = true)]
    async fn only_whole_session_inactivity_expires() {
        let activity = SessionActivity::default();
        let window = Duration::from_millis(20);
        let expired = activity.expired(window);
        tokio::pin!(expired);
        assert!(!ready(expired.as_mut()).await);
        for _ in 0..8 {
            activity.progress();
            tokio::time::advance(window).await;
            assert!(!ready(expired.as_mut()).await);
        }
        tokio::time::advance(window).await;
        assert!(
            ready(expired.as_mut()).await,
            "fully idle framed sessions are bounded"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn raw_transition_disarms_shared_inactivity_for_both_directions() {
        let activity = SessionActivity::default();
        let window = Duration::from_millis(20);
        let expired = activity.expired(window);
        tokio::pin!(expired);
        assert!(!ready(expired.as_mut()).await);
        activity.enter_raw();
        for _ in 0..8 {
            tokio::time::advance(window).await;
            assert!(!ready(expired.as_mut()).await);
        }
    }

    #[test]
    fn progress_has_no_per_event_allocation() {
        let activity = SessionActivity::default();
        let measured = allocation_counter::measure(|| {
            for _ in 0..10_000 {
                std::hint::black_box(&activity).progress();
            }
        });
        assert_eq!(measured.count_total, 0);
        assert!(activity.progressed.load(Ordering::Relaxed));
    }
}
