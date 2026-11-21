use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt};

type Endpoints = (SocketAddr, SocketAddr);

pub fn encode(version: u8, source: SocketAddr, destination: SocketAddr) -> Result<Vec<u8>> {
    ensure!(version == 1 || version == 2, "unsupported PROXY protocol version");
    let bytes = match (version, source, destination) {
        (1, SocketAddr::V4(src), SocketAddr::V4(dst)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            src.ip(), dst.ip(), src.port(), dst.port()
        ).into_bytes(),
        (1, SocketAddr::V6(src), SocketAddr::V6(dst)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            src.ip(), dst.ip(), src.port(), dst.port()
        ).into_bytes(),
        (1, _, _) => b"PROXY UNKNOWN\r\n".to_vec(),
        (2, src, dst) => {
            let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            match (src, dst) {
                (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                    header.extend_from_slice(&[0x21, 0x11, 0, 12]);
                    header.extend_from_slice(&src.ip().octets());
                    header.extend_from_slice(&dst.ip().octets());
                    header.extend_from_slice(&src.port().to_be_bytes());
                    header.extend_from_slice(&dst.port().to_be_bytes());
                }
                (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                    header.extend_from_slice(&[0x21, 0x21, 0, 36]);
                    header.extend_from_slice(&src.ip().octets());
                    header.extend_from_slice(&dst.ip().octets());
                    header.extend_from_slice(&src.port().to_be_bytes());
                    header.extend_from_slice(&dst.port().to_be_bytes());
                }
                _ => header.extend_from_slice(&[0x20, 0, 0, 0]),
            }
            header
        }
        _ => unreachable!(),
    };
    Ok(bytes)
}

#[cfg(test)]
mod encode_tests {
    use super::encode;

    #[test]
    fn proxy_v1_ipv4() {
        let header = encode(1, "192.0.2.1:1234".parse().unwrap(), "198.51.100.2:443".parse().unwrap()).unwrap();
        assert_eq!(header, b"PROXY TCP4 192.0.2.1 198.51.100.2 1234 443\r\n");
    }

    #[test]
    fn proxy_v2_ipv4() {
        let header = encode(2, "192.0.2.1:1234".parse().unwrap(), "198.51.100.2:443".parse().unwrap()).unwrap();
        assert_eq!(&header[..16], b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c");
        assert_eq!(&header[16..], &[192, 0, 2, 1, 198, 51, 100, 2, 4, 210, 1, 187]);
    }
}

pub async fn addresses(
    stream: &mut (impl AsyncRead + Unpin),
    peer: SocketAddr,
    listener: SocketAddr,
) -> Result<Endpoints> {
    let endpoints = (peer, listener);
    match stream.read_u8().await? {
        b'P' => read_v1(stream, endpoints).await,
        b'\r' => read_v2(stream, endpoints).await,
        _ => bail!("missing PROXY protocol header"),
    }
}

async fn read_v1(stream: &mut (impl AsyncRead + Unpin), endpoints: Endpoints) -> Result<Endpoints> {
    // Read exactly through CRLF so TLS can continue directly on the socket.
    let mut line = [0; 107];
    line[0] = b'P';
    for end in 1..line.len() {
        line[end] = stream.read_u8().await?;
        if line[end] == b'\n' {
            ensure!(line[end - 1] == b'\r', "invalid PROXY v1 line ending");
            return parse_v1(std::str::from_utf8(&line[..end - 1])?, endpoints);
        }
    }
    bail!("PROXY v1 header exceeds 107 bytes");
}

fn parse_v1(line: &str, endpoints: Endpoints) -> Result<Endpoints> {
    let fields: Vec<_> = line.split(' ').collect();
    match fields.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(endpoints),
        [
            "PROXY",
            "TCP4",
            source,
            destination,
            source_port,
            destination_port,
        ] => Ok((
            (source.parse::<Ipv4Addr>()?, source_port.parse::<u16>()?).into(),
            (
                destination.parse::<Ipv4Addr>()?,
                destination_port.parse::<u16>()?,
            )
                .into(),
        )),
        [
            "PROXY",
            "TCP6",
            source,
            destination,
            source_port,
            destination_port,
        ] => Ok((
            (source.parse::<Ipv6Addr>()?, source_port.parse::<u16>()?).into(),
            (
                destination.parse::<Ipv6Addr>()?,
                destination_port.parse::<u16>()?,
            )
                .into(),
        )),
        _ => bail!("invalid PROXY v1 header"),
    }
}

async fn read_v2(stream: &mut (impl AsyncRead + Unpin), endpoints: Endpoints) -> Result<Endpoints> {
    const SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
    let mut header = [0; 16];
    header[0] = b'\r';
    stream.read_exact(&mut header[1..]).await?;
    ensure!(
        &header[..12] == SIGNATURE && header[12] >> 4 == 2,
        "invalid PROXY v2 header"
    );
    let length = usize::from(port(&header[14..]));
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    match (header[12] & 0x0f, header[13]) {
        (0, _) | (1, 0) => Ok(endpoints),
        (1, 0x11) if length >= 12 => Ok((
            (
                Ipv4Addr::from(<[u8; 4]>::try_from(&payload[..4])?),
                port(&payload[8..]),
            )
                .into(),
            (
                Ipv4Addr::from(<[u8; 4]>::try_from(&payload[4..8])?),
                port(&payload[10..]),
            )
                .into(),
        )),
        (1, 0x21) if length >= 36 => Ok((
            (
                Ipv6Addr::from(<[u8; 16]>::try_from(&payload[..16])?),
                port(&payload[32..]),
            )
                .into(),
            (
                Ipv6Addr::from(<[u8; 16]>::try_from(&payload[16..32])?),
                port(&payload[34..]),
            )
                .into(),
        )),
        _ => bail!("unsupported PROXY v2 command or address family"),
    }
}

fn port(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}
