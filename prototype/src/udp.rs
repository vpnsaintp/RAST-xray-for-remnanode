use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use uuid::Uuid;

use crate::backend::{Backend, Flow, Tunnel, vision_cascade};
use crate::egress::{Egress, VlessStream, put_socks_target, read_socks_target};
use crate::go_router::read_response;
use crate::routing::{Host, Target};
use crate::sniff::{Detected, QuicProbe, Sniffing};
use crate::state::{Meter, Traffic};
use crate::vless::{put_target, read_target, vision_first};

const UDP_IDLE: Duration = Duration::from_secs(120);
const MAX_DATAGRAM: usize = 65_507;
const MAX_DESTINATIONS: usize = 32;

pub struct ContextInfo<'a> {
    pub backend: &'a Backend,
    pub traffic: Arc<Traffic>,
    pub flow: Flow<'a>,
    pub sniffing: &'a Sniffing,
}

enum Sender {
    Datagram(Arc<UdpSocket>),
    Socks(Arc<UdpSocket>, Target),
    Stream(Box<dyn AsyncWrite + Send + Unpin>, Option<(Target, bool)>),
}

impl Sender {
    async fn send(&mut self, payload: &[u8]) -> Result<usize> {
        match self {
            Self::Datagram(socket) => Ok(socket.send(payload).await?),
            Self::Socks(socket, target) => {
                let mut packet = vec![0, 0, 0];
                put_socks_target(&mut packet, target)?;
                packet.extend(payload);
                socket.send(&packet).await?;
                Ok(payload.len())
            }
            Self::Stream(socket, xudp) => {
                if let Some((target, first)) = xudp {
                    let mut meta = vec![0, 0, if *first { 1 } else { 2 }, 1];
                    if *first {
                        meta.push(2);
                        put_target(&mut meta, target);
                        *first = false;
                    }
                    socket.write_u16(meta.len() as u16).await?;
                    socket.write_all(&meta).await?;
                }
                socket.write_u16(payload.len() as u16).await?;
                socket.write_all(payload).await?;
                socket.flush().await?;
                Ok(payload.len())
            }
        }
    }
}

pub(crate) struct Packet {
    pub target: Target,
    pub data: Vec<u8>,
}

struct PendingQuic {
    probe: QuicProbe,
    packets: Vec<Vec<u8>>,
    deadline: Instant,
}

pub async fn relay(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    mut target: Option<Target>,
    ctx: ContextInfo<'_>,
    vision: Option<Uuid>,
) -> Result<()> {
    let xudp = target.is_none();
    let (sender, mut replies) = mpsc::channel::<Packet>(32);
    let (input, packets) = mpsc::channel::<Packet>(16);
    let read = async move {
        while let Some(packet) =
            timeout(UDP_IDLE, read_packet(&mut reader, xudp, &mut target)).await??
        {
            if input.send(packet).await.is_err() {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    let receive = async {
        let mut first = vision;
        while let Some(packet) = replies.recv().await {
            let mut frame = Vec::new();
            if xudp {
                let mut metadata = vec![0, 0, 2, 1, 2];
                put_target(&mut metadata, &packet.target);
                frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
                frame.extend(metadata);
            }
            frame.extend_from_slice(&(packet.data.len() as u16).to_be_bytes());
            frame.extend(packet.data);
            if let Some(user) = first.take() {
                vision_first(&mut writer, user, &frame).await?;
            } else {
                writer.write_all(&frame).await?;
                writer.flush().await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = async { tokio::try_join!(read, relay_packets(packets, sender, &ctx)).map(|_| ()) } => result,
        result = receive => result,
    }
}

pub(crate) async fn relay_packets(
    mut packets: mpsc::Receiver<Packet>,
    sender: mpsc::Sender<Packet>,
    ctx: &ContextInfo<'_>,
) -> Result<()> {
    let mut sockets = HashMap::<Target, (Sender, Meter)>::new();
    let mut torrent_sockets = HashMap::<Target, (Sender, Meter)>::new();
    let mut pending = HashMap::<Target, PendingQuic>::new();
    let mut receivers = JoinSet::new();
    loop {
        let route_count = sockets.len() + torrent_sockets.len();
        let deadline = pending
            .iter()
            .min_by_key(|(_, entry)| entry.deadline)
            .map(|(target, entry)| (target.clone(), entry.deadline));
        let (target, frames, detected) = match deadline {
            Some((target, deadline)) => match timeout_at(deadline, packets.recv()).await {
                Ok(packet) => match packet {
                    Some(packet) => {
                        classify(packet, ctx, &mut sockets, &mut pending, route_count).await?
                    }
                    None => return Ok::<_, anyhow::Error>(()),
                },
                Err(_) => {
                    let frames = pending
                        .remove(&target)
                        .expect("pending QUIC target")
                        .packets;
                    (
                        target,
                        frames,
                        Detected {
                            protocol: "quic",
                            domain: None,
                        },
                    )
                }
            },
            None => match packets.recv().await {
                Some(packet) => {
                    classify(packet, ctx, &mut sockets, &mut pending, route_count).await?
                }
                None => return Ok(()),
            },
        };
        if frames.is_empty() {
            continue;
        }
        let routes = if detected.protocol == "bittorrent" {
            &mut torrent_sockets
        } else {
            &mut sockets
        };
        if !routes.contains_key(&target) {
            ensure!(
                route_count + pending.len() < MAX_DESTINATIONS,
                "too many UDP destinations"
            );
            let route = timeout(
                Duration::from_secs(5),
                open(ctx, &target, &detected, &mut receivers, sender.clone()),
            )
            .await??;
            routes.insert(target.clone(), route);
        }
        let (socket, meter) = routes.get_mut(&target).expect("UDP route exists");
        for data in frames {
            meter.add(socket.send(&data).await?, true);
        }
    }
}

async fn classify(
    packet: Packet,
    ctx: &ContextInfo<'_>,
    sockets: &mut HashMap<Target, (Sender, Meter)>,
    pending: &mut HashMap<Target, PendingQuic>,
    route_count: usize,
) -> Result<(Target, Vec<Vec<u8>>, Detected)> {
    let Packet { target, data } = packet;
    let native = matches!(ctx.backend, Backend::Native(_));
    // A prior datagram may have created a route without a protocol match.
    if native && ctx.sniffing.udp_bittorrent(&data) {
        return Ok((
            target,
            vec![data],
            Detected {
                protocol: "bittorrent",
                domain: None,
            },
        ));
    }
    if let Some((socket, meter)) = sockets.get_mut(&target) {
        meter.add(socket.send(&data).await?, true);
        return Ok((target, Vec::new(), Detected::default()));
    }
    if let Some(entry) = pending.get_mut(&target) {
        let result = entry.probe.push(&data).unwrap_or(Detected {
            protocol: "quic",
            domain: None,
        });
        entry.packets.push(data);
        if result.domain.is_some() || entry.packets.len() >= 4 {
            let frames = pending
                .remove(&target)
                .expect("pending QUIC target")
                .packets;
            return Ok((target, frames, result));
        }
        return Ok((target, Vec::new(), result));
    }
    let (detected, probe) = if native {
        ctx.sniffing.udp_quic(&data)
    } else {
        (Detected::default(), None)
    };
    if let Some(probe) = probe {
        ensure!(
            route_count + pending.len() < MAX_DESTINATIONS,
            "too many UDP destinations"
        );
        pending.insert(
            target.clone(),
            PendingQuic {
                probe,
                packets: vec![data],
                deadline: Instant::now() + Duration::from_millis(200),
            },
        );
        return Ok((target, Vec::new(), detected));
    }
    Ok((target, vec![data], detected))
}

async fn open(
    ctx: &ContextInfo<'_>,
    target: &Target,
    detected: &Detected,
    tasks: &mut JoinSet<()>,
    replies: mpsc::Sender<Packet>,
) -> Result<(Sender, Meter)> {
    let flow = ctx.flow;
    let target = target.clone();
    match ctx.backend {
        Backend::Native(router) => {
            let route = router
                .route(&target, "udp", flow, ctx.sniffing, detected)
                .await?;
            let meter = Meter::new(
                ctx.traffic.clone(),
                flow.inbound,
                Some(&route.tag),
                flow.email,
                flow.peer.ip(),
            );
            let sender = match route.egress {
                Egress::Direct(_) => {
                    let addr = *route.addresses.first().context("no UDP destination")?;
                    let socket = udp_socket(addr).await?;
                    tasks.spawn(receive_udp(
                        socket.clone(),
                        None,
                        target,
                        meter.clone(),
                        replies,
                    ));
                    Sender::Datagram(socket)
                }
                Egress::Socks(proxy) => {
                    let any = Target {
                        host: Host::Ip(std::net::Ipv4Addr::UNSPECIFIED.into()),
                        port: 0,
                    };
                    let (control, bound) = proxy.socks_request(3, &any).await?;
                    let addr = *bound
                        .addresses()
                        .await?
                        .first()
                        .context("no SOCKS UDP relay")?;
                    let socket = udp_socket(addr).await?;
                    tasks.spawn(receive_udp(
                        socket.clone(),
                        Some(control),
                        target,
                        meter.clone(),
                        replies,
                    ));
                    Sender::Socks(socket, route.target)
                }
                Egress::Vless(proxy) => {
                    let stream = proxy
                        .open(router, &route.target, if proxy.vision { 3 } else { 2 })
                        .await?;
                    let stream: Box<dyn Tunnel> = match stream {
                        VlessStream::Plain(stream) => Box::new(stream),
                        VlessStream::Tls(stream) if proxy.vision => {
                            Box::new(vision_cascade(stream, proxy.id))
                        }
                        VlessStream::Tls(stream) => Box::new(stream),
                    };
                    let (reader, writer) = tokio::io::split(stream);
                    tasks.spawn(receive_stream(
                        reader,
                        !proxy.vision,
                        proxy.vision,
                        target,
                        meter.clone(),
                        replies,
                    ));
                    Sender::Stream(
                        Box::new(writer),
                        proxy.vision.then_some((route.target, true)),
                    )
                }
                _ => bail!("outbound does not support UDP"),
            };
            Ok((sender, meter))
        }
        Backend::Go(router) => {
            let stream = router
                .open(flow.inbound, flow.id, flow.peer, flow.listener, &target, 2)
                .await?;
            let (reader, writer) = stream.into_split();
            let meter = Meter::new(
                ctx.traffic.clone(),
                flow.inbound,
                None,
                flow.email,
                flow.peer.ip(),
            );
            tasks.spawn(receive_stream(
                reader,
                true,
                false,
                target,
                meter.clone(),
                replies,
            ));
            Ok((Sender::Stream(Box::new(writer), None), meter))
        }
    }
}

async fn udp_socket(address: std::net::SocketAddr) -> Result<Arc<UdpSocket>> {
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(address).await?;
    Ok(Arc::new(socket))
}

async fn receive_udp(
    socket: Arc<UdpSocket>,
    mut control: Option<tokio::net::TcpStream>,
    target: Target,
    meter: Meter,
    replies: mpsc::Sender<Packet>,
) {
    let mut bytes = vec![0; MAX_DATAGRAM];
    loop {
        let received = if let Some(control) = &mut control {
            tokio::select! {
                result = socket.recv(&mut bytes) => result,
                _ = control.read_u8() => return,
            }
        } else {
            socket.recv(&mut bytes).await
        };
        let Ok(size) = received else {
            break;
        };
        let mut payload = &bytes[..size];
        if control.is_some() {
            let Some(rest) = payload.strip_prefix(&[0, 0, 0]) else {
                continue;
            };
            payload = rest;
            if read_socks_target(&mut payload).await.is_err() {
                continue;
            }
        }
        meter.add(payload.len(), false);
        if replies
            .send(Packet {
                target: target.clone(),
                data: payload.to_vec(),
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn receive_stream(
    mut reader: impl AsyncRead + Unpin,
    header: bool,
    xudp: bool,
    target: Target,
    meter: Meter,
    replies: mpsc::Sender<Packet>,
) {
    if header && read_response(&mut reader).await.is_err() {
        return;
    }
    let mut default = Some(target.clone());
    while let Ok(Some(packet)) = read_packet(&mut reader, xudp, &mut default).await {
        meter.add(packet.data.len(), false);
        if replies
            .send(Packet {
                target: target.clone(),
                data: packet.data,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn read_packet(
    reader: &mut (impl AsyncRead + Unpin),
    xudp: bool,
    default: &mut Option<Target>,
) -> Result<Option<Packet>> {
    loop {
        let Some(length) = read_length(reader).await? else {
            return Ok(None);
        };
        if !xudp {
            let data = read_data(reader, length).await?;
            return Ok(Some(Packet {
                target: default.clone().context("missing UDP destination")?,
                data,
            }));
        }
        ensure!((4..=512).contains(&length), "invalid XUDP metadata length");
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        let mut meta = bytes.as_slice();
        ensure!(
            meta.read_u16().await? == 0,
            "only XUDP session ID 0 is supported"
        );
        let status = meta.read_u8().await?;
        let options = meta.read_u8().await?;
        ensure!(options <= 3, "invalid XUDP options");
        let target = match status {
            1 => {
                ensure!(default.is_none(), "duplicate XUDP start");
                ensure!(meta.read_u8().await? == 2, "XUDP accepts UDP only");
                let address = read_target(&mut meta).await?;
                ensure!(matches!(meta.len(), 0 | 8), "invalid XUDP start metadata");
                *default = Some(address.clone());
                Some(address)
            }
            2 => {
                ensure!(default.is_some(), "XUDP data before start");
                if meta.is_empty() {
                    default.clone()
                } else {
                    ensure!(meta.read_u8().await? == 2, "invalid XUDP network");
                    let address = read_target(&mut meta).await?;
                    ensure!(meta.is_empty(), "unexpected XUDP metadata");
                    Some(address)
                }
            }
            3 | 4 => None,
            _ => bail!("invalid XUDP frame status"),
        };
        let data = if options & 1 != 0 {
            let length = usize::from(reader.read_u16().await?);
            Some(read_data(reader, length).await?)
        } else {
            None
        };
        if status == 3 || options & 2 != 0 {
            return Ok(None);
        }
        if let (Some(target), Some(data)) = (target, data) {
            return Ok(Some(Packet { target, data }));
        }
    }
}

async fn read_length(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<usize>> {
    let high = match reader.read_u8().await {
        Ok(byte) => byte,
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(Some(
        u16::from_be_bytes([high, reader.read_u8().await?]).into(),
    ))
}

async fn read_data(reader: &mut (impl AsyncRead + Unpin), length: usize) -> Result<Vec<u8>> {
    ensure!(length <= MAX_DATAGRAM, "oversized UDP packet");
    let mut data = vec![0; length];
    reader.read_exact(&mut data).await?;
    Ok(data)
}
