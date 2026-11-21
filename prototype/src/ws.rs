use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{Sink, Stream};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Error, Message, http};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config};

#[derive(Deserialize)]
#[serde(try_from = "RawSettings")]
pub struct Settings {
    pub path: String,
    pub host: String,
    pub accept_proxy_protocol: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSettings {
    #[serde(default = "default_path")]
    path: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    accept_proxy_protocol: bool,
    // Xray accepts this on an inbound, but heartbeat is emitted by the WS
    // client. Server-side parsing must not reject otherwise valid profiles.
    #[serde(default)]
    heartbeat_period: u32,
}

impl TryFrom<RawSettings> for Settings {
    type Error = String;

    fn try_from(raw: RawSettings) -> std::result::Result<Self, Self::Error> {
        let mut host = raw.host;
        for (name, value) in raw.headers {
            if !name.eq_ignore_ascii_case("host") {
                return Err(format!("unsupported WebSocket request header: {name}"));
            }
            if !host.is_empty() && !host.eq_ignore_ascii_case(&value) {
                return Err("conflicting WebSocket host settings".into());
            }
            host = value;
        }
        let _ = raw.heartbeat_period;
        Ok(Self {
            path: raw.path,
            host,
            accept_proxy_protocol: raw.accept_proxy_protocol,
        })
    }
}
fn default_path() -> String {
    "/".into()
}

pub struct Ws<S = TcpStream> {
    stream: WebSocketStream<S>,
    pending: Bytes,
    eof: bool,
    closing: bool,
}

pub async fn accept<S>(
    socket: S,
    settings: &Settings,
    trusted_forwarding_headers: &[String],
) -> Result<(Ws<S>, Option<IpAddr>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending = Bytes::new();
    let mut forwarded_ip = None;
    let path = settings.path.split('?').next().unwrap_or("/");
    let config = WebSocketConfig::default()
        .read_buffer_size(8 * 1024)
        .write_buffer_size(0)
        .max_write_buffer_size(64 * 1024)
        .max_message_size(Some(2 * 1024 * 1024))
        .max_frame_size(Some(2 * 1024 * 1024));
    let stream = accept_hdr_async_with_config(
        socket,
        |request: &Request, mut response: Response| {
            let host_matches = settings.host.is_empty()
                || request
                    .headers()
                    .get(http::header::HOST)
                    .is_some_and(|header| {
                        header
                            .to_str()
                            .ok()
                            .and_then(|host| host.parse::<http::uri::Authority>().ok())
                            .is_some_and(|host| host.host().eq_ignore_ascii_case(&settings.host))
                    });
            if request.uri().path() != path || !host_matches {
                return Err(http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(None)
                    .expect("fixed HTTP response"));
            }
            forwarded_ip = forwarded_client_ip(request.headers(), trusted_forwarding_headers);
            if let Some(protocol) = request.headers().get(http::header::SEC_WEBSOCKET_PROTOCOL) {
                if let Ok(text) = protocol.to_str() {
                    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(
                        text.replace('+', "-")
                            .replace('/', "_")
                            .trim_end_matches('='),
                    ) {
                        if !bytes.is_empty() {
                            pending = bytes.into();
                            response
                                .headers_mut()
                                .insert(http::header::SEC_WEBSOCKET_PROTOCOL, protocol.clone());
                        }
                    }
                }
            }
            Ok(response)
        },
        Some(config),
    )
    .await?;
    Ok((
        Ws {
            stream,
            pending,
            eof: false,
            closing: false,
        },
        forwarded_ip,
    ))
}

fn forwarded_client_ip(headers: &http::HeaderMap, trusted: &[String]) -> Option<IpAddr> {
    let forwarded = headers.get("x-forwarded-for")?.to_str().ok()?;
    if !trusted
        .iter()
        .any(|name| headers.contains_key(name.as_str()))
    {
        return None;
    }
    forwarded.split(',').next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_ip_requires_a_configured_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "2001:db8::3, 192.0.2.1".parse().unwrap());
        assert_eq!(forwarded_client_ip(&headers, &[]), None);
        assert_eq!(forwarded_client_ip(&headers, &["X-Proxy".into()]), None);
        assert_eq!(
            forwarded_client_ip(&headers, &["X-Forwarded-For".into()]),
            Some("2001:db8::3".parse().unwrap())
        );
    }

    #[test]
    fn xray_headers_host_sets_ws_host() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "path": "/test",
            "headers": {"Host": "example.test"},
            "heartbeatPeriod": 30
        }))
        .unwrap();
        assert_eq!(settings.host, "example.test");
        assert_eq!(settings.path, "/test");
    }

    #[test]
    fn conflicting_ws_hosts_are_rejected() {
        let parsed = serde_json::from_value::<Settings>(serde_json::json!({
            "host": "one.test",
            "headers": {"Host": "two.test"}
        }));
        assert!(parsed.is_err());
    }

    #[test]
    fn unsupported_ws_header_is_rejected() {
        let parsed = serde_json::from_value::<Settings>(serde_json::json!({
            "headers": {"X-Custom": "value"}
        }));
        assert!(parsed.is_err());
    }
}
fn io_error(error: Error) -> io::Error {
    match error {
        Error::Io(error) => error,
        error => io::Error::other(error),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Ws<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.eof || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.closing {
            ready!(Pin::new(&mut self.stream).poll_flush(cx)).map_err(io_error)?;
            self.eof = true;
            return Poll::Ready(Ok(()));
        }
        while self.pending.is_empty() {
            match ready!(Pin::new(&mut self.stream).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => self.pending = bytes,
                Some(Ok(Message::Close(_))) => {
                    self.closing = true;
                    ready!(Pin::new(&mut self.stream).poll_flush(cx)).map_err(io_error)?;
                    self.eof = true;
                    break;
                }
                None => {
                    self.eof = true;
                    break;
                }
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected a binary VLESS frame",
                    )));
                }
                Some(Err(error)) => return Poll::Ready(Err(io_error(error))),
                Some(Ok(_)) => {}
            }
        }
        let size = self.pending.len().min(buffer.remaining());
        buffer.put_slice(&self.pending.split_to(size));
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Ws<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let stream = Pin::new(&mut self.stream);
        ready!(stream.poll_ready(cx)).map_err(io_error)?;
        let size = bytes.len().min(16 * 1024);
        Pin::new(&mut self.stream)
            .start_send(Message::binary(bytes[..size].to_vec()))
            .map_err(io_error)?;
        Poll::Ready(Ok(size))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx).map_err(io_error)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closing && self.eof {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_close(cx).map_err(io_error)
    }
}
