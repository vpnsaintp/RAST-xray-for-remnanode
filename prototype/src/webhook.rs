use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use crate::backend::Flow;
use crate::go_router::connect_abstract;
use crate::routing::Target;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    url: String,
    #[serde(default)]
    deduplication: u64,
}

pub struct Webhook {
    address: String,
    path: String,
    dedup: Duration,
    seen: Mutex<HashMap<String, Instant>>,
    slots: Arc<Semaphore>,
}

impl Webhook {
    pub fn compile(config: WebhookConfig) -> Result<Self> {
        let (address, path) = config
            .url
            .strip_prefix('@')
            .and_then(|url| url.split_once(':'))
            .context("expected Remnanode webhook socket")?;
        ensure!(
            !address.is_empty()
                && path.starts_with("/internal/webhook?")
                && !path.contains(['\r', '\n', ' ']),
            "invalid Remnanode webhook path"
        );
        Ok(Self {
            address: address.into(),
            path: path.into(),
            dedup: Duration::from_secs(config.deduplication),
            seen: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(64)),
        })
    }

    pub fn fire(
        &self,
        flow: Flow<'_>,
        protocol: &str,
        network: &str,
        original: &Target,
        route: &Target,
        tag: &str,
    ) {
        let Ok(slot) = self.slots.clone().try_acquire_owned() else {
            return;
        };
        if !self.dedup.is_zero() {
            let now = Instant::now();
            let mut seen = self.seen.lock().unwrap();
            if seen.len() >= 4096 {
                seen.retain(|_, last| now.duration_since(*last) < self.dedup);
            }
            if seen
                .get(flow.email)
                .is_some_and(|last| now.duration_since(*last) < self.dedup)
            {
                return;
            }
            if seen.len() < 4096 {
                seen.insert(flow.email.into(), now);
            }
        }
        let body = json!({
            "email": flow.email, "level": 0, "protocol": protocol, "network": network,
            "source": format!("{network}:{}", flow.peer),
            "destination": format!("{network}:{}", route.authority()),
            "originalTarget": format!("{network}:{}", original.authority()),
            "routeTarget": format!("{network}:{}", route.authority()),
            "inboundTag": flow.inbound, "inboundName": "vless",
            "inboundLocal": format!("{network}:{}", flow.listener),
            "outboundTag": tag,
            "ts": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        })
        .to_string();
        let address = self.address.clone();
        let path = self.path.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let send = async {
                let mut stream = connect_abstract(&address).await?;
                let header = format!(
                    "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(body.as_bytes()).await?;
                let mut response = [0; 12];
                stream.read_exact(&mut response).await?;
                ensure!(
                    &response[..7] == b"HTTP/1." && response[9] == b'2',
                    "Remnanode rejected webhook"
                );
                Ok::<_, anyhow::Error>(())
            };
            if !matches!(
                tokio::time::timeout(Duration::from_secs(5), send).await,
                Ok(Ok(()))
            ) {
                eprintln!("Remnanode route webhook failed");
            }
        });
    }
}
