use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use uuid::Uuid;

use crate::egress::{Egress, VlessStream};
use crate::go_router::GoRouter;
use crate::routing::{Router, Target};
use crate::sniff::{Detected, Sniffing};
use crate::vless::vision_first;

pub trait Tunnel: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any> Tunnel for T {}

pub enum Backend {
    Native(Router),
    Go(GoRouter),
}

#[derive(Clone, Copy)]
pub struct Flow<'a> {
    pub inbound: &'a str,
    pub email: &'a str,
    pub id: Uuid,
    pub peer: SocketAddr,
    pub listener: SocketAddr,
}

impl Backend {
    pub async fn open_tcp(
        &self,
        flow: Flow<'_>,
        target: &Target,
        sniffing: &Sniffing,
        detected: &Detected,
    ) -> Result<(Box<dyn Tunnel>, Option<String>)> {
        const CONNECT: Duration = Duration::from_secs(5);
        timeout(CONNECT, async {
            match self {
                Self::Native(router) => {
                    let route = router
                        .route(target, "tcp", flow, sniffing, detected)
                        .await?;
                    let stream: Box<dyn Tunnel> = match route.egress {
                        Egress::Direct(direct) => Box::new(direct.connect(&route.addresses).await?),
                        Egress::Http(proxy) => Box::new(proxy.connect(&route.target).await?),
                        Egress::Socks(proxy) => {
                            Box::new(proxy.socks_request(1, &route.target).await?.0)
                        }
                        Egress::Vless(proxy) => match proxy.open(router, &route.target, 1).await? {
                            VlessStream::Plain(stream) => Box::new(RelayTcp::new(stream)),
                            VlessStream::Tls(stream) if proxy.vision => {
                                Box::new(vision_cascade(stream, proxy.id))
                            }
                            VlessStream::Tls(stream) => Box::new(RelayTcp::new(stream)),
                        },
                        Egress::Block => unreachable!("blocked routes are rejected by Router"),
                    };
                    Ok((stream, Some(route.tag)))
                }
                Self::Go(router) => {
                    let stream = router
                        .open(flow.inbound, flow.id, flow.peer, flow.listener, target, 1)
                        .await?;
                    // Xray sends its response after it receives origin data. Expose the
                    // writer immediately and strip the header in the independent reader.
                    Ok((Box::new(RelayTcp::new(stream)) as Box<dyn Tunnel>, None))
                }
            }
        })
        .await?
    }

    pub fn go(&self) -> Option<&GoRouter> {
        match self {
            Self::Go(router) => Some(router),
            Self::Native(_) => None,
        }
    }
}

pub fn vision_cascade(
    stream: crate::tls_stream::TlsStream<rustls::ClientSide>,
    id: Uuid,
) -> tokio::io::DuplexStream {
    let (client, bridge) = tokio::io::duplex(8192);
    tokio::spawn(async move {
        let direct = stream.direct_read_control();
        let (mut remote_read, mut remote_write) = tokio::io::split(stream);
        let (mut from_client, mut to_client) = tokio::io::split(bridge);
        let uplink = async {
            let mut first = [0; 4096];
            let size = match timeout(Duration::from_millis(100), from_client.read(&mut first)).await
            {
                Ok(size) => size?,
                Err(_) => 0,
            };
            vision_first(&mut remote_write, id, &first[..size]).await?;
            tokio::io::copy(&mut from_client, &mut remote_write).await?;
            remote_write.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        let downlink = async {
            crate::go_router::read_response(&mut remote_read).await?;
            crate::strip_vision(&mut remote_read, &mut to_client, id, Some(&direct)).await
        };
        let _ = tokio::try_join!(uplink, downlink);
    });
    client
}

struct RelayTcp<S> {
    stream: S,
    header: [u8; 2],
    offset: usize,
}

impl<S> RelayTcp<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            header: [0; 2],
            offset: 0,
        }
    }
}

use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::ReadBuf;

impl<S: AsyncRead + Unpin> AsyncRead for RelayTcp<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let relay = &mut *self;
        while relay.offset < relay.header.len() {
            let mut header = ReadBuf::new(&mut relay.header[relay.offset..]);
            ready!(Pin::new(&mut relay.stream).poll_read(cx, &mut header))?;
            if header.filled().is_empty() {
                return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
            }
            relay.offset += header.filled().len();
            if relay.offset == 2 && relay.header != [0, 0] {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid routing companion response",
                )));
            }
        }
        Pin::new(&mut relay.stream).poll_read(cx, dst)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RelayTcp<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
