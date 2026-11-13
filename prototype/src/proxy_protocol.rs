use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt};

type Endpoints = (SocketAddr, SocketAddr);

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
        ["PROXY", "TCP4", source, destination, source_port, destination_port] => Ok((
            (source.parse::<Ipv4Addr>()?, source_port.parse::<u16>()?).into(),
            (
                destination.parse::<Ipv4Addr>()?,
                destination_port.parse::<u16>()?,
            )
                .into(),
        )),
        ["PROXY", "TCP6", source, destination, source_port, destination_port] => Ok((
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
