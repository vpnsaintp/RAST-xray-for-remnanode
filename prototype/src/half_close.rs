use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::time::{Instant, interval};

pub const IDLE_AFTER_FIN: Duration = Duration::from_secs(120);

#[derive(Clone, Default)]
pub struct Progress(Arc<AtomicU64>);

impl Progress {
    pub fn reader<R>(&self, inner: R) -> ProgressReader<R> {
        ProgressReader { inner, progress: self.clone() }
    }
    pub fn add(&self, bytes: usize) {
        if bytes != 0 { self.0.fetch_add(bytes as u64, Ordering::Relaxed); }
    }
    fn load(&self) -> u64 { self.0.load(Ordering::Relaxed) }
}

pub struct ProgressReader<R> { inner: R, progress: Progress }

impl<R: AsyncRead + Unpin> AsyncRead for ProgressReader<R> {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = &result { self.progress.add(buffer.filled().len().saturating_sub(before)); }
        result
    }
}
pub async fn join<E, U, D>(uplink: U, downlink: D, progress: Progress) -> Result<(), E>
where E: From<io::Error>, U: Future<Output = Result<(), E>>, D: Future<Output = Result<(), E>> {
    tokio::pin!(uplink); tokio::pin!(downlink);
    tokio::select! {
        result = &mut uplink => { result?; wait_for_remaining(downlink.as_mut(), progress).await }
        result = &mut downlink => { result?; wait_for_remaining(uplink.as_mut(), progress).await }
    }
}

async fn wait_for_remaining<E, F>(mut remaining: Pin<&mut F>, progress: Progress) -> Result<(), E>
where E: From<io::Error>, F: Future<Output = Result<(), E>> {
    let mut observed = progress.load();
    let mut deadline = Instant::now() + IDLE_AFTER_FIN;
    let mut check = interval(Duration::from_secs(1)); check.tick().await;
    loop {
        tokio::select! {
            result = &mut remaining => return result,
            _ = check.tick() => {
                let current = progress.load();
                if current != observed { observed = current; deadline = Instant::now() + IDLE_AFTER_FIN; }
                else if Instant::now() >= deadline { return Err(io::Error::new(io::ErrorKind::TimedOut, "remaining TCP direction was idle for 120 seconds after FIN").into()); }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    #[tokio::test(start_paused = true)]
    async fn a_finished_half_waits_for_the_configured_idle_window() {
        let progress=Progress::default(); let (_sender,receiver)=oneshot::channel::<()>();
        let joined=join::<io::Error,_,_>(async{Ok(())},async{receiver.await.map_err(io::Error::other)},progress); tokio::pin!(joined);
        tokio::time::advance(IDLE_AFTER_FIN-Duration::from_secs(1)).await;
        assert!(tokio::time::timeout(Duration::ZERO,&mut joined).await.is_err());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(joined.await.expect_err("idle half must time out").kind(),io::ErrorKind::TimedOut);
    }
    #[tokio::test(start_paused = true)]
    async fn progress_resets_the_post_fin_idle_window() {
        let progress=Progress::default(); let task_progress=progress.clone();
        let remaining=async move { tokio::time::sleep(Duration::from_secs(119)).await; task_progress.add(1); tokio::time::sleep(Duration::from_secs(119)).await; Ok::<(),io::Error>(()) };
        join(async{Ok::<(),io::Error>(())},remaining,progress).await.expect("active half retained");
    }
    #[tokio::test]
    async fn the_second_fin_completes_without_waiting() {
        join::<io::Error,_,_>(async{Ok(())},async{Ok(())},Progress::default()).await.expect("both halves completed");
    }
}
