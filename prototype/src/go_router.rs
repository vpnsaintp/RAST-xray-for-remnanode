use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::linux::net::SocketAddrExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use tonic::transport::{Channel, Endpoint};
use uuid::Uuid;

use crate::routing::Target;
use crate::vless::put_target;

pub const TORRENT_OUTBOUND: &str = "RW_TB_OUTBOUND_BLOCK";

pub struct GoRouter {
    inbounds: HashMap<String, String>,
    pub channel: Channel,
    pub torrent_rule_tag: String,
}

pub async fn connect_abstract(name: &str) -> Result<UnixStream> {
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let stream =
        tokio::task::spawn_blocking(move || std::os::unix::net::UnixStream::connect_addr(&address))
            .await??;
    stream.set_nonblocking(true)?;
    Ok(UnixStream::from_std(stream)?)
}

impl GoRouter {
    pub async fn start(path: &Path, mut profile: Value) -> Result<(Self, Child)> {
        ensure!(
            path.is_absolute(),
            "router executable path must be absolute"
        );
        let base = format!("nightvpn-route-{}", Uuid::new_v4().simple());
        let api_name = format!("{base}-api");
        let torrent_rule_tag = format!("{base}-torrent");
        let mut names = HashMap::new();
        let mut inbounds = vec![
            json!({"tag":"REMNAWAVE_API_INBOUND","listen":format!("@{api_name}"),"protocol":"tunnel"}),
        ];
        let original = profile["inbounds"].as_array().context("inbounds missing")?;
        for inbound in original
            .iter()
            .filter(|inbound| inbound["protocol"] == "vless")
        {
            let tag = inbound["tag"].as_str().context("inbound tag missing")?;
            let name = format!("{base}-{}", names.len());
            names.insert(tag.to_owned(), name.clone());
            let clients = inbound["settings"]["clients"]
                .as_array()
                .context("clients missing")?;
            let clients: Vec<_> = clients.iter().map(|user| json!({"id": user["id"], "email": user["email"].as_str().unwrap_or_default()})).collect();
            inbounds.push(json!({
                "listen": format!("@{name}"), "tag": tag, "protocol": "vless",
                "settings": {"clients": clients, "decryption":"none"},
                "streamSettings": {"network": "raw", "rawSettings": {"acceptProxyProtocol": true}},
                "sniffing": inbound.get("sniffing").cloned().unwrap_or_else(|| json!({"enabled": false})),
            }));
        }
        profile["inbounds"] = json!(inbounds);
        profile["api"] = json!({"tag":"REMNAWAVE_API","services":["HandlerService","StatsService","RoutingService"]});
        profile["stats"] = json!({});
        profile["policy"]["system"]["statsOutboundUplink"] = true.into();
        profile["policy"]["system"]["statsOutboundDownlink"] = true.into();
        profile["log"] = json!({"loglevel":"warning", "access":"none", "error":"none"});
        if profile["routing"].is_null() {
            profile["routing"] = json!({});
        }
        let rules = profile["routing"]
            .as_object_mut()
            .context("routing section missing")?
            .entry("rules")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .context("routing rules must be an array")?;
        rules.retain(|rule| rule["outboundTag"] != "REMNAWAVE_API");
        // Remnanode's generated rule is anonymous. Give it a tag for live removal.
        for rule in rules.iter_mut().filter(|rule| {
            rule["outboundTag"] == TORRENT_OUTBOUND
                && rule["protocol"] == json!(["bittorrent"])
                && rule["webhook"].is_object()
                && rule["ruleTag"].as_str().unwrap_or_default().is_empty()
        }) {
            rule["ruleTag"] = torrent_rule_tag.clone().into();
        }
        rules.insert(
            0,
            json!({"inboundTag":["REMNAWAVE_API_INBOUND"],"outboundTag":"REMNAWAVE_API"}),
        );

        let mut command = Command::new(path);
        command
            .args(["run", "-config", "stdin:", "-format", "json"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let parent = std::process::id() as libc::pid_t;
        // This closure runs between fork and exec. Only async-signal-safe syscalls are used.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let mut input = child.stdin.take().context("router input missing")?;
        timeout(
            Duration::from_secs(5),
            input.write_all(&serde_json::to_vec(&profile)?),
        )
        .await??;
        drop(input);
        let channel = timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.try_wait()? {
                    anyhow::bail!("routing companion exited during startup ({status})");
                }
                if let Ok(channel) = connect_grpc(api_name.clone()).await {
                    return Ok::<_, anyhow::Error>(channel);
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("routing companion failed readiness check")??;
        Ok((
            Self {
                inbounds: names,
                channel,
                torrent_rule_tag,
            },
            child,
        ))
    }

    pub async fn open(
        &self,
        inbound: &str,
        id: Uuid,
        source: SocketAddr,
        listener: SocketAddr,
        target: &Target,
        command: u8,
    ) -> Result<UnixStream> {
        let name = self
            .inbounds
            .get(inbound)
            .context("routing companion inbound missing")?;
        let mut socket = connect_abstract(name).await?;
        let family = if source.is_ipv4() { "TCP4" } else { "TCP6" };
        let proxy = format!(
            "PROXY {family} {} {} {} {}\r\n",
            source.ip(),
            listener.ip(),
            source.port(),
            listener.port()
        );
        let mut header = proxy.into_bytes();
        header.push(0);
        header.extend_from_slice(id.as_bytes());
        header.extend_from_slice(&[0, command]);
        put_target(&mut header, target);
        socket.write_all(&header).await?;
        Ok(socket)
    }
}

// For UDP, Xray can send the response header after the first packet. Wait on the
// receive side, independently of the writer.
pub async fn read_response(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<()> {
    ensure!(
        stream.read_u8().await? == 0,
        "invalid routing companion response"
    );
    let mut addons = vec![0; usize::from(stream.read_u8().await?)];
    stream.read_exact(&mut addons).await?;
    ensure!(
        addons.is_empty(),
        "unexpected routing companion response addons"
    );
    Ok(())
}

async fn connect_grpc(name: String) -> Result<Channel> {
    let endpoint = Endpoint::from_static("http://[::]:50051")
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3));
    let service = tower::service_fn(move |_| {
        let name = name.clone();
        async move {
            Ok::<_, std::io::Error>(TokioIo::new(
                connect_abstract(&name)
                    .await
                    .map_err(std::io::Error::other)?,
            ))
        }
    });
    Ok(endpoint.connect_with_connector(service).await?)
}
