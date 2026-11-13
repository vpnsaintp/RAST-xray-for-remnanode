use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use anyhow::{Result, ensure};
use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream, server::SendResponse};
use http::header::{CACHE_CONTROL, CONTENT_TYPE, REFERER};
use http::uri::Authority;
use http::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

const CHUNK: usize = 16 * 1024;
const IDLE: Duration = Duration::from_secs(120);
const PADDING_MIN: usize = 100;
const PADDING_MAX: usize = 1000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub path: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    no_sse_header: bool,
    #[serde(skip, default = "stream_slots")]
    slots: std::sync::Arc<Semaphore>,
}

fn stream_slots() -> std::sync::Arc<Semaphore> {
    std::sync::Arc::new(Semaphore::new(4096))
}

impl Settings {
    pub fn validate(&mut self) -> Result<()> {
        ensure!(
            matches!(self.mode.as_str(), "" | "auto" | "stream-one"),
            "XHTTP over REALITY supports stream-one mode"
        );
        let path = self.path.split('?').next().unwrap_or_default();
        ensure!(
            path.starts_with('/') && path.parse::<http::uri::PathAndQuery>().is_ok(),
            "invalid XHTTP path"
        );
        self.path = format!("{}/", path.trim_end_matches('/'));
        if !self.host.is_empty() {
            self.host = self.host.parse::<Authority>()?.host().to_owned();
        }
        Ok(())
    }

    fn status(&self, request: &Request<RecvStream>) -> StatusCode {
        if request.uri().path() != self.path
            || (!self.host.is_empty()
                && !request
                    .uri()
                    .host()
                    .is_some_and(|host| host.eq_ignore_ascii_case(&self.host)))
        {
            return StatusCode::NOT_FOUND;
        }
        if request.method() != Method::POST {
            return StatusCode::METHOD_NOT_ALLOWED;
        }
        let query = match request.headers().get(REFERER) {
            Some(referer) => referer.to_str().ok().and_then(|value| {
                value
                    .split_once('?')
                    .map(|(_, query)| query.split('#').next().unwrap_or_default())
            }),
            None => request.uri().query(),
        };
        let padding = query.and_then(|query| {
            query
                .split('&')
                .find_map(|part| part.strip_prefix("x_padding="))
        });
        if !padding.is_some_and(|value| (PADDING_MIN..=PADDING_MAX).contains(&value.len())) {
            return StatusCode::BAD_REQUEST;
        }
        StatusCode::OK
    }
}

pub async fn serve<S, F, R>(stream: S, settings: &Settings, handle: F) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(Stream) -> R,
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
        let Some(request) = request else { break };
        let (request, mut reply) = request?;
        let status = settings.status(&request);
        if status != StatusCode::OK {
            let _ = reply.send_response(Response::builder().status(status).body(())?, true);
            continue;
        }
        let Ok(slot) = settings.slots.clone().try_acquire_owned() else {
            let _ = reply.send_response(Response::builder().status(503).body(())?, true);
            continue;
        };
        let Ok(send) = start_response(&mut reply, settings) else {
            // A peer can cancel a single stream while the HTTP/2 connection stays open.
            continue;
        };
        let session = handle(Stream {
            recv: request.into_body(),
            send,
            pending: Bytes::new(),
            closed: false,
        });
        tunnels.spawn(async move {
            let _slot = slot;
            if let Err(error) = session.await {
                eprintln!("XHTTP session rejected or closed: {error:#}");
            }
        });
    }
    Ok(())
}

fn start_response(reply: &mut SendResponse<Bytes>, settings: &Settings) -> Result<SendStream<Bytes>> {
    let mut random = [0; 2];
    aws_lc_rs::rand::fill(&mut random).map_err(|_| anyhow::anyhow!("XHTTP padding RNG failed"))?;
    let count = PADDING_MIN + usize::from(u16::from_ne_bytes(random)) % (PADDING_MAX - PADDING_MIN + 1);
    let mut padding = http::HeaderValue::from_str(&"X".repeat(count))?;
    padding.set_sensitive(true);
    let mut response = Response::builder()
        .header(CACHE_CONTROL, "no-store")
        .header("x-accel-buffering", "no")
        .header("x-padding", padding);
    if !settings.no_sse_header {
        response = response.header(CONTENT_TYPE, "text/event-stream");
    }
    Ok(reply.send_response(response.body(())?, false)?)
}

pub struct Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    pending: Bytes,
    closed: bool,
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.pending.is_empty() {
            let Some(data) = ready!(self.recv.poll_data(cx)) else {
                return Poll::Ready(Ok(()));
            };
            self.pending = data.map_err(io::Error::other)?;
        }
        let length = self.pending.len().min(buffer.remaining());
        buffer.put_slice(&self.pending[..length]);
        self.pending.advance(length);
        self.recv
            .flow_control()
            .release_capacity(length)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let requested = buffer.len().min(CHUNK);
        self.send.reserve_capacity(requested);
        while self.send.capacity() == 0 {
            match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let length = self.send.capacity().min(requested);
        self.send
            .send_data(Bytes::copy_from_slice(&buffer[..length]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The HTTP/2 connection drives queued frames independently of this stream.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.finish();
        Poll::Ready(Ok(()))
    }
}

impl Stream {
    fn finish(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.send.send_data(Bytes::new(), true);
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.finish();
    }
}
