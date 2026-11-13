mod api;
mod backend;
mod config;
mod dns;
mod egress;
mod geodata;
mod go_router;
mod grpc;
mod mux;
mod proxy_protocol;
mod routing;
mod shadowsocks;
mod sniff;
mod splice;
mod state;
mod tls_stream;
mod udp;
mod vless;
mod webhook;
mod ws;
mod xhttp;

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use backend::{Backend, Flow, Tunnel};
use config::{Inbound, RealityTarget, Transport, VerifyServerName};
use rustls::server::RealityClientHelloProbe;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use state::{Meter, Metered, Traffic};
use subtle::ConstantTimeEq;
use tls_stream::{SpliceReader, TlsStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;
use uuid::Uuid;
use vless::{VISION_FLOW, read_target, vision_first};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INBOUND_CONNECTIONS: usize = 32_768;
const LISTEN_BACKLOG: i32 = 65_535;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let first = args.next().context("supply a config file")?;
    if first == "version" || first == "--version" {
        println!("NightVPN Rust Core {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let path = if first == "-config" {
        args.next().context("missing config path")?
    } else {
        first
    };
    match (args.next().as_deref(), args.next().as_deref(), args.next()) {
        (None, None, None) | (Some("-format"), Some("json"), None) => {}
        _ => bail!("unsupported CLI arguments"),
    }
    let mut config = config::load(&path).await?;
    config.state.stats.start_clock();
    let mut services = JoinSet::new();
    for inbound in config.inbounds {
        let listener = bind(&inbound)?;
        let backend = config.backend.clone();
        let stats = config.state.stats.clone();
        services.spawn(serve(listener, Arc::new(inbound), backend, stats));
    }
    for inbound in config.shadowsocks {
        inbound.start(&mut services, config.backend.clone(), config.state.stats.clone())?;
    }
    if let Some(name) = config.api_socket {
        services.spawn(api::serve(name, config.state, config.backend.clone()));
    }
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let monitor = async {
        match config.companion.as_mut() {
            Some(child) => child.wait().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = terminate.recv() => {},
        _ = interrupt.recv() => {},
        result = monitor => bail!("routing companion exited ({})", result?),
        result = services.join_next() => {
            result.context("no services running")???;
            bail!("service unexpectedly exited");
        }
    }
    if let Some(mut child) = config.companion.take() {
        child.kill().await?;
    }
    Ok(())
}

fn bind(inbound: &Inbound) -> Result<TcpListener> {
    use std::os::fd::AsRawFd;
    let mut address = inbound.address;
    if address.is_ipv4() && address.ip().is_unspecified() {
        address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, address.port()));
    }
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() && address.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    if inbound.socket_options.tcp_fast_open {
        let queue: libc::c_int = 256;
        // The value is a valid pointer for the duration of this setsockopt call.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                (&queue as *const libc::c_int).cast(),
                std::mem::size_of_val(&queue) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    Ok(TcpListener::from_std(socket.into())?)
}

async fn serve(
    listener: TcpListener,
    inbound: Arc<Inbound>,
    backend: Arc<Backend>,
    traffic: Arc<Traffic>,
) -> Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
    println!("VLESS listener ready on {}", listener.local_addr()?);
    loop {
        let (socket, peer) = accept_tcp(&listener).await?;
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let inbound = inbound.clone();
        let backend = backend.clone();
        let traffic = traffic.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(error) =
                session(socket, canonical_address(peer), &inbound, &backend, traffic).await
            {
                eprintln!("Session rejected or closed: {error:#}");
            }
        });
    }
}

async fn accept_tcp(listener: &TcpListener) -> std::io::Result<(TcpStream, SocketAddr)> {
    loop {
        match listener.accept().await {
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
                ) =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionAborted => {}
            result => return result,
        }
    }
}

fn canonical_address(address: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(ipv6) = address {
        if let Some(ipv4) = ipv6.ip().to_ipv4_mapped() {
            return (ipv4, address.port()).into();
        }
    }
    address
}

async fn session(
    mut socket: TcpStream,
    peer: SocketAddr,
    inbound: &Arc<Inbound>,
    backend: &Arc<Backend>,
    traffic: Arc<Traffic>,
) -> Result<()> {
    socket.set_nodelay(inbound.socket_options.tcp_no_delay)?;
    let idle = inbound.socket_options.tcp_keep_alive_idle;
    let interval = inbound.socket_options.tcp_keep_alive_interval;
    if idle != 0 || interval != 0 {
        let delay = if idle == 0 { interval } else { idle };
        let mut keepalive = TcpKeepalive::new().with_time(Duration::from_secs(delay));
        if interval != 0 {
            keepalive = keepalive.with_interval(Duration::from_secs(interval));
        }
        SockRef::from(&socket).set_tcp_keepalive(&keepalive)?;
    }
    let local_listener = canonical_address(socket.local_addr()?);
    let (peer, listener) = if inbound.socket_options.accept_proxy_protocol {
        let trusted = &inbound.socket_options.trusted_proxy_protocol_sources;
        ensure!(
            (inbound.address.ip().is_loopback() && peer.ip().is_loopback())
                || trusted.iter().any(|network| network.contains(&peer.ip())),
            "PROXY protocol sender is not trusted"
        );
        let (source, destination) = timeout(
            CONNECT_TIMEOUT,
            proxy_protocol::addresses(&mut socket, peer, local_listener),
        )
        .await??;
        (canonical_address(source), canonical_address(destination))
    } else {
        (peer, local_listener)
    };
    match &inbound.transport {
        Transport::Reality {
            tls,
            verifier,
            fallback,
            xhttp,
            grpc,
        } => {
            let mut preface = Vec::new();
            if let Some(destination) = fallback {
                let is_reality = timeout(
                    CONNECT_TIMEOUT,
                    client_hello(&mut socket, &mut preface, verifier),
                )
                .await??;
                if !is_reality {
                    let mut site = timeout(CONNECT_TIMEOUT, connect_reality_target(destination, local_listener)).await??;
                    timeout(CONNECT_TIMEOUT, site.write_all(&preface)).await??;
                    if splice::enabled() {
                        splice::copy_tcp(&mut socket, &mut site).await?;
                    } else {
                        tokio::io::copy_bidirectional(&mut socket, &mut site).await?;
                    }
                    return Ok(());
                }
            }
            let stream = timeout(
                CONNECT_TIMEOUT,
                TlsStream::accept(socket, tls.clone(), preface),
            )
            .await??;
            if let Some(settings) = xhttp {
                return xhttp::serve(stream, settings, |stream| {
                    let (inbound, backend, traffic) = (inbound.clone(), backend.clone(), traffic.clone());
                    async move { vless_session(stream, peer, listener, &inbound, &backend, traffic, None).await }
                })
                .await;
            }
            if let Some(settings) = grpc {
                return grpc::serve(stream, settings, false, |stream, _| {
                    let (inbound, backend, traffic) = (inbound.clone(), backend.clone(), traffic.clone());
                    async move { vless_session(stream, peer, listener, &inbound, &backend, traffic, None).await }
                }).await;
            }
            let direct = stream.direct_read_control();
            vless_session(
                stream,
                peer,
                listener,
                inbound,
                backend,
                traffic,
                Some(direct),
            )
            .await
        }
        Transport::Grpc(settings) => grpc::serve(socket, settings, peer.ip().is_loopback(), |stream, forwarded| {
            let (inbound, backend, traffic) = (inbound.clone(), backend.clone(), traffic.clone());
            let peer = forwarded.map_or(peer, |ip| SocketAddr::new(ip, 0));
            async move { vless_session(stream, peer, listener, &inbound, &backend, traffic, None).await }
        }).await,
        Transport::WebSocket(settings) => {
            let (stream, forwarded_ip) = timeout(
                CONNECT_TIMEOUT,
                ws::accept(socket, settings, &inbound.socket_options.trusted_x_forwarded_for),
            )
            .await??;
            let peer = forwarded_ip.map_or(peer, |ip| SocketAddr::new(ip, 0));
            vless_session(
                stream,
                canonical_address(peer),
                canonical_address(listener),
                inbound,
                backend,
                traffic,
                None,
            )
            .await
        }
        Transport::Tls(tls) => {
            let stream = timeout(
                CONNECT_TIMEOUT,
                TlsStream::accept(socket, tls.clone(), Vec::new()),
            )
            .await??;
            let direct = stream.direct_read_control();
            vless_session(stream, peer, listener, inbound, backend, traffic, Some(direct)).await
        }
    }
}

async fn connect_reality_target(target: &RealityTarget, listener: SocketAddr) -> Result<TcpStream> {
    match target {
        RealityTarget::Address(address) => Ok(TcpStream::connect(address).await?),
        RealityTarget::Domain(target) => {
            let mut addresses = target.addresses().await?;
            addresses.retain(|address| canonical_address(*address) != listener);
            ensure!(!addresses.is_empty(), "REALITY fallback has no usable address");
            Ok(TcpStream::connect(addresses.as_slice()).await?)
        }
    }
}

async fn vless_session(
    mut stream: impl Tunnel,
    peer: SocketAddr,
    listener: SocketAddr,
    inbound: &Arc<Inbound>,
    backend: &Arc<Backend>,
    traffic: Arc<Traffic>,
    direct: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let (id, vision, command) = timeout(CONNECT_TIMEOUT, request_header(&mut stream)).await??;
    let user = inbound
        .users
        .read()
        .unwrap()
        .get(&id)
        .cloned()
        .context("invalid VLESS UUID")?;
    if !matches!(inbound.transport, Transport::Reality { fallback: None, .. }) {
        ensure!(
            (!vision || user.vision) && (command != 1 || user.vision == vision),
            "VLESS client flow mismatch"
        );
    }
    ensure!(
        !vision || direct.is_some(),
        "Vision requires a TLS or REALITY TCP inbound"
    );
    ensure!(!vision || command != 2, "Vision UDP requires XUDP");
    let target = match command {
        1 | 2 => Some(timeout(CONNECT_TIMEOUT, read_target(&mut stream)).await??),
        3 => None,
        _ => bail!("unsupported VLESS command"),
    };
    let flow = Flow {
        inbound: &inbound.tag,
        email: &user.email,
        id,
        peer,
        listener,
    };
    let proxy = async {
        if command == 1 {
            let target = target.context("missing TCP target")?;
            let raw_reader =
                if vision && splice::enabled() && matches!(backend.as_ref(), Backend::Native(_)) {
                    (&mut stream as &mut dyn std::any::Any)
                        .downcast_mut::<TlsStream>()
                        .and_then(TlsStream::prepare_splice)
                } else {
                    None
                };
            if matches!(backend.as_ref(), Backend::Native(_)) && inbound.sniffing.enabled {
                reply(&mut stream).await?;
                return relay_sniffed_tcp(
                    stream,
                    backend,
                    &target,
                    &inbound.sniffing,
                    flow,
                    traffic,
                    direct.filter(|_| vision),
                    raw_reader,
                )
                .await;
            }
            let mut origin = open_metered_tcp(
                backend,
                &target,
                &inbound.sniffing,
                flow,
                traffic,
                &sniff::Detected::default(),
            )
            .await?;
            reply(&mut stream).await?;
            if vision {
                relay_vision_tcp(stream, &mut origin, id, direct.as_deref(), raw_reader).await
            } else {
                tokio::io::copy_bidirectional(&mut stream, &mut origin).await?;
                Ok(())
            }
        } else if command == 2 {
            reply(&mut stream).await?;
            let ctx = udp::ContextInfo {
                backend,
                traffic,
                flow,
                sniffing: &inbound.sniffing,
            };
            let (read, write) = tokio::io::split(stream);
            udp::relay(read, write, target, ctx, None).await
        } else {
            reply(&mut stream).await?;
            let context = mux::Context {
                inbound: inbound.clone(),
                backend: backend.clone(),
                traffic,
                user: user.clone(),
                id,
                peer,
                listener,
            };
            let (mut read, write) = tokio::io::split(stream);
            if vision {
                let (mut unpacked, mut input) = tokio::io::duplex(128 * 1024);
                tokio::select! {
                    result = strip_vision(&mut read, &mut unpacked, id, None) => result,
                    result = mux::relay(&mut input, write, context, Some(id)) => result,
                }
            } else {
                mux::relay(read, write, context, None).await
            }
        }
    };
    tokio::select! {
        result = proxy => result,
        _ = user.revoked() => Ok(()),
    }
}

async fn open_metered_tcp(
    backend: &Backend,
    target: &routing::Target,
    sniffing: &sniff::Sniffing,
    flow: Flow<'_>,
    traffic: Arc<Traffic>,
    detected: &sniff::Detected,
) -> Result<Metered<Box<dyn Tunnel>>> {
    let (origin, tag) = backend.open_tcp(flow, target, sniffing, detected).await?;
    Ok(Metered(
        origin,
        Meter::new(
            traffic,
            flow.inbound,
            tag.as_deref(),
            flow.email,
            flow.peer.ip(),
        ),
    ))
}

async fn open_sniffed_tcp(
    read: &mut (impl AsyncRead + Unpin),
    backend: &Backend,
    target: &routing::Target,
    sniffing: &sniff::Sniffing,
    flow: Flow<'_>,
    traffic: Arc<Traffic>,
) -> Result<Metered<Box<dyn Tunnel>>> {
    let (prefix, protocol) = sniffing.tcp(read).await?;
    let mut origin = open_metered_tcp(backend, target, sniffing, flow, traffic, &protocol).await?;
    origin.write_all(&prefix).await?;
    Ok(origin)
}

async fn client_hello(
    socket: &mut TcpStream,
    bytes: &mut Vec<u8>,
    verifier: &VerifyServerName,
) -> Result<bool> {
    while bytes.len() < 128 * 1024 {
        let mut header = [0; 5];
        socket.read_exact(&mut header).await?;
        ensure!(
            header[0] == 22 && header[1] == 3,
            "expected a TLS handshake"
        );
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        ensure!((1..=18_432).contains(&length), "invalid TLS record length");
        bytes.extend_from_slice(&header);
        let start = bytes.len();
        bytes.resize(start + length, 0);
        socket.read_exact(&mut bytes[start..]).await?;
        if let Some(probe) = RealityClientHelloProbe::from_tls_records(bytes)? {
            return verifier.accepts(&probe);
        }
    }
    bail!("TLS ClientHello too large");
}

async fn request_header(reader: &mut (impl AsyncRead + Unpin)) -> Result<(Uuid, bool, u8)> {
    ensure!(reader.read_u8().await? == 0, "unsupported VLESS version");
    let mut id = [0; 16];
    reader.read_exact(&mut id).await?;
    let mut addons = vec![0; usize::from(reader.read_u8().await?)];
    reader.read_exact(&mut addons).await?;
    ensure!(
        addons.is_empty() || addons == VISION_FLOW,
        "unsupported VLESS add-ons"
    );
    Ok((
        Uuid::from_bytes(id),
        !addons.is_empty(),
        reader.read_u8().await?,
    ))
}

async fn reply(writer: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
    writer.write_all(&[0, 0]).await?;
    writer.flush().await?;
    Ok(())
}

async fn strip_vision(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    user: Uuid,
    direct: Option<&AtomicBool>,
) -> Result<()> {
    read_vision_prefix(reader, writer, user, direct).await?;
    tokio::io::copy(reader, writer).await?;
    writer.shutdown().await?;
    Ok(())
}

async fn read_vision_prefix(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    user: Uuid,
    direct: Option<&AtomicBool>,
) -> Result<bool> {
    let mut prefix = [0; 16];
    reader.read_exact(&mut prefix).await?;
    ensure!(
        bool::from(prefix.ct_eq(user.as_bytes())),
        "invalid Vision prefix"
    );
    loop {
        let command = reader.read_u8().await?;
        let content = u64::from(reader.read_u16().await?);
        let padding = u64::from(reader.read_u16().await?);
        ensure!(command <= 2, "invalid Vision command");
        ensure!(
            tokio::io::copy(&mut (&mut *reader).take(content), writer).await? == content,
            "incomplete Vision payload"
        );
        ensure!(
            tokio::io::copy(&mut (&mut *reader).take(padding), &mut tokio::io::sink()).await?
                == padding,
            "incomplete Vision padding"
        );
        if command == 2 {
            direct
                .context("direct Vision is only supported for TCP")?
                .store(true, Ordering::Relaxed);
            println!("Vision uplink switched to direct");
        }
        if command != 0 {
            return Ok(command == 2);
        }
    }
}

fn splice_target(origin: &Metered<Box<dyn Tunnel>>) -> Option<(TcpStream, Meter)> {
    let socket = (&*origin.0 as &dyn std::any::Any).downcast_ref::<TcpStream>()?;
    Some((splice::clone_socket(socket).ok()?, origin.1.clone()))
}

async fn relay_raw_uplink(
    mut read: TcpStream,
    write: &mut (impl AsyncWrite + Unpin),
    target: Option<(TcpStream, Meter)>,
) -> Result<()> {
    if let Some((socket, meter)) = target {
        match splice::copy(&read, &socket, |size| meter.add(size, true)).await? {
            splice::Transfer::Complete => return Ok(()),
            splice::Transfer::Buffered(tail) => write.write_all(&tail).await?,
        }
    }
    tokio::io::copy(&mut read, write).await?;
    Ok(())
}

async fn relay_vision_tcp(
    stream: impl Tunnel,
    origin: &mut Metered<Box<dyn Tunnel>>,
    id: Uuid,
    direct: Option<&AtomicBool>,
    raw_reader: Option<SpliceReader>,
) -> Result<()> {
    let raw_target = raw_reader.as_ref().and_then(|_| splice_target(origin));
    let (mut read, mut write) = tokio::io::split(stream);
    let (mut source, mut destination) = tokio::io::split(origin);
    let uplink = async {
        let raw = read_vision_prefix(&mut read, &mut destination, id, direct).await?;
        if let Some(socket) = raw_reader
            .filter(|_| raw)
            .and_then(SpliceReader::into_socket)
        {
            relay_raw_uplink(socket, &mut destination, raw_target).await?;
        } else {
            tokio::io::copy(&mut read, &mut destination).await?;
        }
        destination.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let downlink = async {
        let mut first = [0; 4096];
        let length = source.read(&mut first).await?;
        if length != 0 {
            vision_first(&mut write, id, &first[..length]).await?;
            tokio::io::copy(&mut source, &mut write).await?;
        }
        write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

async fn relay_sniffed_tcp(
    stream: impl Tunnel,
    backend: &Backend,
    target: &routing::Target,
    sniffing: &sniff::Sniffing,
    flow: Flow<'_>,
    traffic: Arc<Traffic>,
    direct: Option<Arc<AtomicBool>>,
    raw_reader: Option<SpliceReader>,
) -> Result<()> {
    let (mut read, mut write) = tokio::io::split(stream);
    async fn relay(
        read: &mut (impl AsyncRead + Unpin),
        write: &mut (impl AsyncWrite + Unpin),
        backend: &Backend,
        target: &routing::Target,
        sniffing: &sniff::Sniffing,
        flow: Flow<'_>,
        traffic: Arc<Traffic>,
        vision: bool,
        raw_input: Option<oneshot::Receiver<TcpStream>>,
    ) -> Result<()> {
        let origin = open_sniffed_tcp(read, backend, target, sniffing, flow, traffic).await?;
        let raw_target = raw_input.as_ref().and_then(|_| splice_target(&origin));
        let (mut source, mut destination) = tokio::io::split(origin);
        let up = async {
            tokio::io::copy(read, &mut destination).await?;
            if let Some(raw_input) = raw_input {
                if let Ok(socket) = raw_input.await {
                    relay_raw_uplink(socket, &mut destination, raw_target).await?;
                }
            }
            destination.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        let down = async {
            if vision {
                let mut first = [0; 4096];
                let size = source.read(&mut first).await?;
                if size != 0 {
                    vision_first(write, flow.id, &first[..size]).await?;
                }
            }
            tokio::io::copy(&mut source, write).await?;
            write.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(up, down)?;
        Ok(())
    }
    if let Some(direct) = direct {
        let (mut decoded, mut writer) = tokio::io::duplex(8192);
        let (handoff, raw_input) = raw_reader.as_ref().map(|_| oneshot::channel()).unzip();
        let decode = async move {
            let raw = read_vision_prefix(&mut read, &mut writer, flow.id, Some(&direct)).await?;
            let raw_socket = raw_reader
                .filter(|_| raw)
                .and_then(SpliceReader::into_socket);
            if let (Some(handoff), Some(socket)) = (handoff, raw_socket) {
                // The consumer drains the decoded prefix before reading the socket.
                let _ = handoff.send(socket);
            } else {
                tokio::io::copy(&mut read, &mut writer).await?;
            }
            writer.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(
            decode,
            relay(
                &mut decoded,
                &mut write,
                backend,
                target,
                sniffing,
                flow,
                traffic,
                true,
                raw_input,
            ),
        )?;
        Ok(())
    } else {
        relay(
            &mut read, &mut write, backend, target, sniffing, flow, traffic, false, None,
        )
        .await
    }
}
