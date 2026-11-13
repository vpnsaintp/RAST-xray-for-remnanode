use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, SimplexStream, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::timeout;
use uuid::Uuid;

use crate::backend::{Backend, Flow};
use crate::config::Inbound;
use crate::routing::Target;
use crate::sniff::Detected;
use crate::state::{Traffic, User};
use crate::udp::{self, ContextInfo, Packet};
use crate::vless::{put_target, read_target, vision_first};

const NEW: u8 = 1;
const KEEP: u8 = 2;
const END: u8 = 3;
const HEARTBEAT: u8 = 4;
const DATA: u8 = 1;
const ERROR: u8 = 2;
const TCP: u8 = 1;
const UDP: u8 = 2;
const MAX_SESSIONS: usize = 128;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Context {
    pub inbound: Arc<Inbound>,
    pub backend: Arc<Backend>,
    pub traffic: Arc<Traffic>,
    pub user: User,
    pub id: Uuid,
    pub peer: SocketAddr,
    pub listener: SocketAddr,
}

impl Context {
    fn flow(&self) -> Flow<'_> {
        Flow {
            inbound: &self.inbound.tag,
            email: &self.user.email,
            id: self.id,
            peer: self.peer,
            listener: self.listener,
        }
    }
}

struct Frame {
    id: u16,
    status: u8,
    network: Option<u8>,
    target: Option<Target>,
    payload: Option<Vec<u8>>,
}

impl Frame {
    async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<Self>> {
        let high = match reader.read_u8().await {
            Ok(byte) => byte,
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let length = usize::from(u16::from_be_bytes([high, reader.read_u8().await?]));
        ensure!((4..=512).contains(&length), "invalid Mux metadata length");
        let mut storage = [0; 512];
        reader.read_exact(&mut storage[..length]).await?;
        let mut metadata = &storage[..length];
        let id = metadata.read_u16().await?;
        let status = metadata.read_u8().await?;
        let options = metadata.read_u8().await?;
        ensure!(options & !(DATA | ERROR) == 0, "invalid Mux options");
        let (network, target) = match status {
            NEW => {
                let network = metadata.read_u8().await?;
                ensure!(matches!(network, TCP | UDP), "invalid Mux network");
                let target = read_target(&mut metadata).await?;
                // XUDP includes an optional global ID. Each connection has its
                // own UDP state, as with the previous XUDP implementation.
                ensure!(
                    metadata.is_empty() || network == UDP && metadata.len() == 8,
                    "unexpected Mux start metadata"
                );
                (Some(network), Some(target))
            }
            KEEP if !metadata.is_empty() => {
                ensure!(metadata.read_u8().await? == UDP, "invalid Mux UDP target");
                let target = read_target(&mut metadata).await?;
                ensure!(metadata.is_empty(), "unexpected Mux UDP metadata");
                (Some(UDP), Some(target))
            }
            KEEP | END | HEARTBEAT => (None, None),
            _ => bail!("invalid Mux status"),
        };
        let payload = if options & DATA != 0 {
            let length = usize::from(reader.read_u16().await?);
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).await?;
            Some(bytes)
        } else {
            None
        };
        Ok(Some(Self {
            id,
            status,
            network,
            target,
            payload,
        }))
    }
}

fn response(id: u16, target: Option<&Target>, payload: Option<&[u8]>, failed: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(32 + payload.map_or(0, <[u8]>::len));
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&id.to_be_bytes());
    if payload.is_some() {
        frame.extend_from_slice(&[KEEP, DATA]);
    } else {
        frame.extend_from_slice(&[END, if failed { ERROR } else { 0 }]);
    }
    if let Some(target) = target {
        frame.push(UDP);
        put_target(&mut frame, target);
    }
    let metadata_len = (frame.len() - 2) as u16;
    frame[..2].copy_from_slice(&metadata_len.to_be_bytes());
    if let Some(data) = payload {
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
    }
    frame
}

enum Input {
    Tcp(WriteHalf<SimplexStream>),
    Udp {
        packets: mpsc::Sender<Packet>,
        target: Target,
    },
}

impl Input {
    async fn send(&mut self, target: Option<Target>, data: Vec<u8>) -> Result<()> {
        match self {
            Self::Tcp(stream) => {
                ensure!(target.is_none(), "UDP target on a TCP Mux stream");
                timeout(WRITE_TIMEOUT, stream.write_all(&data)).await??;
            }
            Self::Udp {
                packets,
                target: default,
            } => {
                ensure!(data.len() <= 65_507, "oversized UDP packet");
                let packet = Packet {
                    target: target.unwrap_or_else(|| default.clone()),
                    data,
                };
                timeout(WRITE_TIMEOUT, packets.send(packet)).await??;
            }
        }
        Ok(())
    }
}

struct Session {
    input: Input,
    worker: AbortHandle,
}

async fn tcp(
    id: u16,
    mut input: impl AsyncRead + Unpin,
    context: &Context,
    target: &Target,
    replies: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let backend = &context.backend;
    let sniffing = &context.inbound.sniffing;
    let flow = context.flow();
    let traffic = context.traffic.clone();
    let origin = if matches!(backend.as_ref(), Backend::Native(_)) && sniffing.enabled {
        crate::open_sniffed_tcp(&mut input, backend, target, sniffing, flow, traffic).await?
    } else {
        crate::open_metered_tcp(
            backend,
            target,
            sniffing,
            flow,
            traffic,
            &Detected::default(),
        )
        .await?
    };
    let (mut read, mut write) = tokio::io::split(origin);
    let upload = async {
        tokio::io::copy(&mut input, &mut write).await?;
        write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        let mut data = [0; 8192];
        loop {
            let size = read.read(&mut data).await?;
            if size == 0 {
                return Ok(());
            }
            replies
                .send(response(id, None, Some(&data[..size]), false))
                .await?;
        }
    };
    tokio::pin!(download);
    tokio::select! {
        result = &mut download => result,
        result = upload => {
            result?;
            download.await
        }
    }
}

async fn udp(
    id: u16,
    packets: mpsc::Receiver<Packet>,
    context: &Context,
    replies: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let info = ContextInfo {
        backend: &context.backend,
        traffic: context.traffic.clone(),
        flow: context.flow(),
        sniffing: &context.inbound.sniffing,
    };
    let (sender, mut receiver) = mpsc::channel::<Packet>(16);
    let read = async {
        while let Some(packet) = receiver.recv().await {
            replies
                .send(response(
                    id,
                    Some(&packet.target),
                    Some(&packet.data),
                    false,
                ))
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(read, udp::relay_packets(packets, sender, &info))?;
    Ok(())
}

fn start(
    workers: &mut JoinSet<u16>,
    context: &Arc<Context>,
    replies: &mpsc::Sender<Vec<u8>>,
    id: u16,
    network: u8,
    target: Target,
) -> Session {
    let context = context.clone();
    let replies = replies.clone();
    let (input, worker) = if network == TCP {
        let (read, write) = tokio::io::simplex(16 * 1024);
        let worker = workers.spawn(async move {
            let result = tcp(id, read, &context, &target, &replies).await;
            let _ = replies
                .send(response(id, None, None, result.is_err()))
                .await;
            id
        });
        (Input::Tcp(write), worker)
    } else {
        let (sender, receiver) = mpsc::channel(16);
        let worker = workers.spawn(async move {
            let result = udp(id, receiver, &context, &replies).await;
            let _ = replies
                .send(response(id, None, None, result.is_err()))
                .await;
            id
        });
        (
            Input::Udp {
                packets: sender,
                target,
            },
            worker,
        )
    };
    Session { input, worker }
}

async fn dispatch(
    mut reader: impl AsyncRead + Unpin,
    replies: mpsc::Sender<Vec<u8>>,
    context: Arc<Context>,
) -> Result<()> {
    let mut sessions = HashMap::<u16, Session>::new();
    let mut workers = JoinSet::new();
    loop {
        let read = Frame::read(&mut reader);
        tokio::pin!(read);
        let Frame {
            id,
            status,
            network,
            mut target,
            payload,
        } = loop {
            tokio::select! {
                frame = &mut read => match frame? {
                    Some(frame) => break frame,
                    None => return Ok(()),
                },
                finished = workers.join_next_with_id(), if !workers.is_empty() => {
                    if let Some(Ok((task, id))) = finished {
                        if sessions.get(&id).is_some_and(|entry| entry.worker.id() == task) {
                            sessions.remove(&id);
                        }
                    }
                }
            }
        };
        if status == HEARTBEAT {
            continue;
        }
        if status == END {
            if let Some(session) = sessions.remove(&id) {
                session.worker.abort();
            }
            continue;
        }
        if status == NEW {
            if let Some(old) = sessions.remove(&id) {
                old.worker.abort();
                replies.send(response(id, None, None, true)).await?;
                continue;
            }
            if sessions.len() >= MAX_SESSIONS {
                replies.send(response(id, None, None, true)).await?;
                continue;
            }
            let session = start(
                &mut workers,
                &context,
                &replies,
                id,
                network.context("missing Mux network")?,
                target.take().context("missing Mux destination")?,
            );
            sessions.insert(id, session);
        }
        if let Some(data) = payload {
            if let Some(session) = sessions.get_mut(&id) {
                if session.input.send(target, data).await.is_ok() {
                    continue;
                }
            }
            if let Some(session) = sessions.remove(&id) {
                session.worker.abort();
            }
            replies.send(response(id, None, None, true)).await?;
        }
    }
}

pub async fn relay(
    reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    context: Context,
    mut vision: Option<Uuid>,
) -> Result<()> {
    let (replies, mut output) = mpsc::channel::<Vec<u8>>(32);
    let write = async {
        while let Some(frame) = output.recv().await {
            if let Some(id) = vision.take() {
                vision_first(&mut writer, id, &frame).await?;
            } else {
                writer.write_all(&frame).await?;
                writer.flush().await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = dispatch(reader, replies, Arc::new(context)) => result,
        result = write => result,
    }
}
