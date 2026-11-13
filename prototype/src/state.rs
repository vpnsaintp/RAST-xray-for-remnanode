use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, ensure};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use uuid::Uuid;

pub const VISION: &str = "xtls-rprx-vision";
pub type Users = RwLock<HashMap<Uuid, User>>;

#[derive(Clone)]
pub struct User {
    pub email: String,
    pub vision: bool,
    enabled: watch::Sender<bool>,
}

impl User {
    pub fn new(email: String, flow: &str) -> Result<Self> {
        ensure!(matches!(flow, "" | VISION), "unsupported client flow");
        ensure!(!email.contains(">>>"), "invalid client email");
        Ok(Self {
            email,
            vision: flow == VISION,
            enabled: watch::channel(true).0,
        })
    }

    pub fn cancel(&self) {
        self.enabled.send_replace(false);
    }

    pub async fn revoked(&self) {
        let _ = self.enabled.subscribe().wait_for(|enabled| !*enabled).await;
    }
}

pub struct State {
    pub inbounds: HashMap<String, Arc<Users>>,
    pub shadowsocks: HashMap<String, Arc<crate::shadowsocks::Users>>,
    pub stats: Arc<Traffic>,
    pub started: Instant,
}

#[derive(Default)]
pub struct Traffic {
    pub counters: Mutex<HashMap<String, Arc<Counter>>>,
    online: Mutex<HashMap<String, HashMap<IpAddr, i64>>>,
    clock: AtomicI64,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Traffic {
    pub fn start_clock(self: &Arc<Self>) {
        self.clock.store(now(), Relaxed);
        let stats = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let Some(stats) = stats.upgrade() else {
                    break;
                };
                stats.clock.store(now(), Relaxed);
            }
        });
    }

    fn touch(&self, email: &str, ip: IpAddr, time: i64) {
        if !email.is_empty() {
            let mut online = self.online.lock().unwrap();
            let ips = online.entry(email.to_owned()).or_default();
            ips.retain(|_, seen| time - *seen < 300);
            ips.insert(ip, time);
        }
    }

    pub fn remove_online(&self, email: &str) {
        self.online.lock().unwrap().remove(email);
    }

    pub fn online(&self) -> HashMap<String, HashMap<String, i64>> {
        let mut online = self.online.lock().unwrap();
        let time = now();
        online.retain(|_, ips| {
            ips.retain(|_, seen| time - *seen < 300);
            !ips.is_empty()
        });
        online
            .iter()
            .map(|(email, ips)| {
                (
                    email.clone(),
                    ips.iter()
                        .map(|(ip, seen)| (ip.to_string(), *seen))
                        .collect(),
                )
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct Meter(Arc<MeterInner>);

struct MeterInner {
    stats: Arc<Traffic>,
    email: String,
    ip: IpAddr,
    inbound: String,
    outbound: Option<String>,
    up: OnceLock<Vec<Arc<Counter>>>,
    down: OnceLock<Vec<Arc<Counter>>>,
    next_touch: AtomicI64,
    shard: usize,
}

const ONLINE_UPDATE_INTERVAL: i64 = 5;
const SHARDS: usize = 8;
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

// Separate the hot shared counters from each other at cache-line granularity.
#[repr(align(64))]
#[derive(Default)]
struct CounterShard(AtomicI64);

pub struct Counter {
    value: AtomicI64,
    shards: Option<Box<[CounterShard; SHARDS]>>,
}

impl Counter {
    fn new(shared: bool) -> Self {
        Self {
            value: AtomicI64::new(0),
            shards: shared.then(|| Box::new(std::array::from_fn(|_| CounterShard::default()))),
        }
    }

    fn add(&self, shard: usize, size: i64) {
        let counter = self
            .shards
            .as_ref()
            .map_or(&self.value, |shards| &shards[shard].0);
        let mut value = counter.load(Relaxed);
        while let Err(current) =
            counter.compare_exchange_weak(value, value.saturating_add(size), Relaxed, Relaxed)
        {
            value = current;
        }
    }
}

pub fn read_counter(counter: &Counter, reset: bool) -> i64 {
    let read = |value: &AtomicI64| {
        if reset {
            value.swap(0, Relaxed)
        } else {
            value.load(Relaxed)
        }
    };
    counter.shards.as_ref().map_or_else(
        || read(&counter.value),
        |shards| {
            shards
                .iter()
                .fold(0_i64, |total, shard| total.saturating_add(read(&shard.0)))
        },
    )
}

impl Meter {
    pub fn new(
        stats: Arc<Traffic>,
        inbound: &str,
        outbound: Option<&str>,
        email: &str,
        ip: IpAddr,
    ) -> Self {
        let time = now();
        stats.touch(email, ip, time);
        Self(Arc::new(MeterInner {
            stats,
            email: email.to_owned(),
            ip,
            inbound: inbound.to_owned(),
            outbound: outbound.map(str::to_owned),
            up: OnceLock::new(),
            down: OnceLock::new(),
            next_touch: AtomicI64::new(time + ONLINE_UPDATE_INTERVAL),
            shard: NEXT_SHARD.fetch_add(1, Relaxed) % SHARDS,
        }))
    }

    pub fn add(&self, size: usize, uplink: bool) {
        if size == 0 {
            return;
        }
        let inner = &self.0;
        let (handles, direction) = if uplink {
            (&inner.up, "uplink")
        } else {
            (&inner.down, "downlink")
        };
        let handles = handles.get_or_init(|| {
            let mut registry = inner.stats.counters.lock().unwrap();
            let mut handles = Vec::with_capacity(3);
            let mut register = |kind, tag| {
                let name = format!("{kind}>>>{tag}>>>traffic>>>{direction}");
                handles.push(
                    registry
                        .entry(name)
                        .or_insert_with(|| Arc::new(Counter::new(kind != "user")))
                        .clone(),
                );
            };
            register("inbound", inner.inbound.as_str());
            if let Some(tag) = inner.outbound.as_deref() {
                register("outbound", tag);
            }
            if !inner.email.is_empty() {
                register("user", inner.email.as_str());
            }
            handles
        });
        for counter in handles {
            counter.add(inner.shard, size as i64);
        }
        if !inner.email.is_empty() {
            let time = inner.stats.clock.load(Relaxed);
            let next = inner.next_touch.load(Relaxed);
            if time >= next
                && inner
                    .next_touch
                    .compare_exchange(next, time + ONLINE_UPDATE_INTERVAL, Relaxed, Relaxed)
                    .is_ok()
            {
                inner.stats.touch(&inner.email, inner.ip, time);
            }
        }
    }
}

pub struct Metered<T>(pub T, pub Meter);

impl<T: AsyncRead + Unpin> AsyncRead for Metered<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let previous = buffer.filled().len();
        let result = Pin::new(&mut self.0).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.1.add(buffer.filled().len() - previous, false);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Metered<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.0).poll_write(cx, bytes);
        if let Poll::Ready(Ok(size)) = result {
            self.1.add(size, true);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn concurrent_shared_counter_resets_keep_every_byte() {
        let counter = Counter::new(true);
        let finished = AtomicUsize::new(0);
        let mut collected = 0;
        thread::scope(|scope| {
            for shard in 0..SHARDS {
                let counter = &counter;
                let finished = &finished;
                scope.spawn(move || {
                    for _ in 0..10_000 {
                        counter.add(shard, 17);
                    }
                    finished.fetch_add(1, Relaxed);
                });
            }
            while finished.load(Relaxed) != SHARDS {
                collected += read_counter(&counter, true);
                thread::yield_now();
            }
        });
        collected += read_counter(&counter, true);
        assert_eq!(collected, SHARDS as i64 * 10_000 * 17);
        assert_eq!(read_counter(&counter, false), 0);
    }
}
