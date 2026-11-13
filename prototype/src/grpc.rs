use std::{
    future::{Future, poll_fn},
    io,
    net::IpAddr,
    time::Duration,
};

use anyhow::{Result, ensure};
use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use http::{HeaderMap, Method, Request, Response};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

const CHUNK: usize = 16 * 1024;
const MAX_MESSAGE: usize = 1024 * 1024;
const IDLE: Duration = Duration::from_secs(120);
static STREAM_SLOTS: Semaphore = Semaphore::const_new(1024);

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    service_name: String,
    #[serde(default, rename = "multiMode")]
    _multi_mode: bool,
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.service_name.is_empty()
                && self.service_name.len() <= 128
                && self
                    .service_name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
            "unsupported gRPC serviceName"
        );
        Ok(())
    }
}

#[derive(Message)]
struct Hunk {
    #[prost(bytes = "bytes", tag = "1")]
    data: Bytes,
}

#[derive(Message)]
struct MultiHunk {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    data: Vec<Bytes>,
}

pub async fn serve<S, F, R>(
    stream: S,
    settings: &Settings,
    trusted_proxy: bool,
    handle: F,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    F: Fn(DuplexStream, Option<IpAddr>) -> R,
    R: Future<Output = Result<()>> + Send + 'static,
{
    let mut connection = timeout(
        crate::CONNECT_TIMEOUT,
        h2::server::Builder::new()
            .max_concurrent_streams(64)
            .max_header_list_size(16 * 1024)
            .handshake(stream),
    )
    .await??;
    let mut tunnels = JoinSet::new();
    let single = format!("/{}/Tun", settings.service_name);
    let multi = format!("/{}/TunMulti", settings.service_name);
    loop {
        let request = if tunnels.is_empty() {
            match timeout(IDLE, connection.accept()).await {
                Ok(request) => request,
                Err(_) => return Ok(()),
            }
        } else {
            tokio::select! {
                request = connection.accept() => request,
                _ = tunnels.join_next() => continue,
            }
        };
        let Some(request) = request else {
            return Ok(());
        };
        let (request, mut response): (Request<RecvStream>, _) = request?;
        let valid_type = request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value == "application/grpc" || value.starts_with("application/grpc+")
            });
        if request.method() != Method::POST || !valid_type {
            let _ = response.send_response(Response::builder().status(415).body(())?, true);
            continue;
        }
        let path = request.uri().path();
        let is_multi = path == multi;
        if path != single && !is_multi {
            let _ = response.send_response(
                Response::builder()
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "12")
                    .body(())?,
                true,
            );
            continue;
        }
        let Ok(slot) = STREAM_SLOTS.try_acquire() else {
            let _ = response.send_response(
                Response::builder()
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "8")
                    .body(())?,
                true,
            );
            continue;
        };
        let Ok(send) = response.send_response(
            Response::builder()
                .header("content-type", "application/grpc")
                .body(())?,
            false,
        ) else {
            continue;
        };
        let forwarded = if trusted_proxy {
            request
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse().ok())
        } else {
            None
        };
        let (local, remote) = tokio::io::duplex(CHUNK * 2);
        let run = handle(local, forwarded);
        tunnels.spawn(async move {
            let _slot = slot;
            let _ = tokio::join!(run, relay(request.into_body(), send, remote, is_multi));
        });
    }
}

async fn relay(
    mut recv: RecvStream,
    mut send: SendStream<Bytes>,
    stream: DuplexStream,
    multi: bool,
) -> Result<()> {
    let (mut input, mut output) = tokio::io::split(stream);
    let mut pending = Bytes::new();
    let receive = async {
        loop {
            let mut header = [0; 5];
            if !read_exact(&mut recv, &mut pending, &mut header).await? {
                break;
            }
            ensure!(header[0] == 0, "compressed gRPC frame");
            let size = u32::from_be_bytes(header[1..].try_into()?) as usize;
            ensure!(size <= MAX_MESSAGE, "oversized gRPC frame");
            let mut body = vec![0; size];
            ensure!(
                read_exact(&mut recv, &mut pending, &mut body).await?,
                "truncated gRPC body"
            );
            let body = Bytes::from(body);
            if multi {
                for bytes in MultiHunk::decode(body)?.data {
                    output.write_all(&bytes).await?;
                }
            } else {
                output.write_all(&Hunk::decode(body)?.data).await?;
            }
        }
        output.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let result = {
        let transmit = async {
            let mut data = vec![0; CHUNK];
            loop {
                let n = input.read(&mut data).await?;
                if n == 0 {
                    return Ok::<(), anyhow::Error>(());
                }
                let bytes = Bytes::copy_from_slice(&data[..n]);
                let hunk = Hunk { data: bytes };
                // A single repeated bytes field is wire-identical to a normal Hunk.
                let mut frame = BytesMut::with_capacity(5 + hunk.encoded_len());
                frame.extend_from_slice(&[0]);
                frame.extend_from_slice(&(hunk.encoded_len() as u32).to_be_bytes());
                hunk.encode(&mut frame)?;
                send_frame(&mut send, frame.freeze()).await?;
            }
        };
        tokio::pin!(transmit);
        tokio::select! {
            result = &mut transmit => result,
            result = receive => match result {
                Ok(()) => transmit.await,
                Err(error) => Err(error),
            },
        }
    };
    let mut trailers = HeaderMap::new();
    trailers.insert(
        "grpc-status",
        if result.is_ok() { "0" } else { "13" }.parse()?,
    );
    let _ = send.send_trailers(trailers);
    result
}

async fn read_exact(recv: &mut RecvStream, pending: &mut Bytes, target: &mut [u8]) -> Result<bool> {
    let mut offset = 0;
    while offset < target.len() {
        if pending.is_empty() {
            let Some(data) = recv.data().await else {
                if offset == 0 {
                    return Ok(false);
                }
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            };
            *pending = data?;
        }
        let n = (target.len() - offset).min(pending.len());
        target[offset..offset + n].copy_from_slice(&pending[..n]);
        offset += n;
        pending.advance(n);
        recv.flow_control().release_capacity(n)?;
    }
    Ok(true)
}

async fn send_frame(send: &mut SendStream<Bytes>, mut frame: Bytes) -> Result<()> {
    while !frame.is_empty() {
        send.reserve_capacity(frame.len());
        let n = if send.capacity() != 0 {
            send.capacity()
        } else {
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(n) => n?,
                None => return Err(io::Error::from(io::ErrorKind::BrokenPipe).into()),
            }
        };
        if n != 0 {
            send.send_data(frame.split_to(n.min(frame.len())), false)?;
        }
    }
    Ok(())
}
