//! Bounded PROXY protocol v1 prelude for an explicitly trusted HAProxy.
//!
//! The header is authoritative only when it arrives on the explicitly
//! configured HAProxy peer. No direct TLS is accepted in that mode.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use tokio::{io::AsyncReadExt, net::TcpStream, time::timeout};

const MAX_LINE: usize = 107;
const HEADER_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) async fn read_v1(
    stream: &mut TcpStream,
    physical_peer: SocketAddr,
    trusted_proxy_ip: Option<Ipv4Addr>,
) -> io::Result<SocketAddr> {
    let trusted = match trusted_proxy_ip {
        Some(ip) => physical_peer.ip() == IpAddr::V4(ip),
        None => physical_peer.ip().is_loopback(),
    };
    if !trusted {
        return Err(invalid());
    }
    timeout(HEADER_TIMEOUT, read_line(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "PROXY v1 header timeout"))?
}

async fn read_line(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut line = [0_u8; MAX_LINE];
    stream.read_exact(&mut line[..6]).await?;
    if &line[..6] != b"PROXY " {
        return Err(invalid());
    }
    let mut len = 6;
    loop {
        if len >= MAX_LINE {
            return Err(invalid());
        }
        stream.read_exact(&mut line[len..len + 1]).await?;
        len += 1;
        if line[len - 1] == b'\n' {
            if len < 2 || line[len - 2] != b'\r' {
                return Err(invalid());
            }
            break;
        }
        if line[len - 1] == b'\r' {
            // A carriage return may occur only immediately before newline.
            if len >= MAX_LINE {
                return Err(invalid());
            }
            stream.read_exact(&mut line[len..len + 1]).await?;
            len += 1;
            if line[len - 1] != b'\n' {
                return Err(invalid());
            }
            break;
        }
    }
    let text = std::str::from_utf8(&line[..len - 2]).map_err(|_| invalid())?;
    let fields = text.split(' ').collect::<Vec<_>>();
    if fields.len() != 6 || fields[0] != "PROXY" {
        return Err(invalid());
    }
    let source = fields[2].parse::<IpAddr>().map_err(|_| invalid())?;
    let destination = fields[3].parse::<IpAddr>().map_err(|_| invalid())?;
    match (fields[1], source, destination) {
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_)) => {}
        _ => return Err(invalid()),
    }
    let source_port = fields[4].parse::<u16>().map_err(|_| invalid())?;
    let destination_port = fields[5].parse::<u16>().map_err(|_| invalid())?;
    if source.is_unspecified()
        || destination.is_unspecified()
        || source_port == 0
        || destination_port == 0
    {
        return Err(invalid());
    }
    Ok(SocketAddr::new(source, source_port))
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v1 header")
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::read_v1;

    async fn exchange(input: &[u8]) -> io::Result<(SocketAddr, Vec<u8>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let bytes = input.to_vec();
        let sender = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let (mut inbound, peer) = listener.accept().await?;
        let result = read_v1(&mut inbound, peer, None).await;
        let mut remainder = Vec::new();
        if result.is_ok() {
            inbound.read_to_end(&mut remainder).await?;
        }
        sender.await.unwrap();
        result.map(|source| (source, remainder))
    }

    #[tokio::test]
    async fn accepts_valid_tcp4_and_preserves_first_tls_byte() {
        let (source, rest) =
            exchange(b"PROXY TCP4 198.51.100.7 127.0.0.1 43210 443\r\n\x16\x03\x01")
                .await
                .unwrap();
        assert_eq!(source.to_string(), "198.51.100.7:43210");
        assert_eq!(rest, b"\x16\x03\x01");
    }

    #[tokio::test]
    async fn rejects_direct_tls_and_unknown_or_malformed_headers() {
        for value in [
            b"\x16\x03\x01\x00\x00\x00".as_slice(),
            b"PROXY UNKNOWN\r\n",
            b"PROXY TCP4 198.51.100.7 ::1 1234 443\r\n",
            b"PROXY TCP4 198.51.100.7 127.0.0.1 0 443\r\n",
            b"PROXY TCP4 198.51.100.7 127.0.0.1 1234 443\n",
        ] {
            assert!(exchange(value).await.is_err());
        }
    }

    #[tokio::test]
    async fn rejects_non_loopback_transport_even_with_valid_header() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let _sender = TcpStream::connect(address).await.unwrap();
        let (mut inbound, _) = listener.accept().await.unwrap();
        let false_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 1234);
        assert!(read_v1(&mut inbound, false_peer, None).await.is_err());
    }

    #[tokio::test]
    async fn remote_header_requires_exact_trusted_transport_peer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let header = b"PROXY TCP4 198.51.100.7 198.51.100.83 43210 443\r\n";
        let sender = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(header).await.unwrap();
        });
        let (mut inbound, _) = listener.accept().await.unwrap();
        let bridge = Ipv4Addr::new(198, 51, 100, 241);
        let peer = SocketAddr::new(IpAddr::V4(bridge), 54321);
        assert_eq!(
            read_v1(&mut inbound, peer, Some(bridge))
                .await
                .unwrap()
                .to_string(),
            "198.51.100.7:43210"
        );
        sender.await.unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let _sender = TcpStream::connect(address).await.unwrap();
        let (mut inbound, _) = listener.accept().await.unwrap();
        let impostor = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 242)), 54321);
        assert!(read_v1(&mut inbound, impostor, Some(bridge)).await.is_err());
    }
}
