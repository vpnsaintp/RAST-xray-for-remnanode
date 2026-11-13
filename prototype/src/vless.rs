use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::routing::{Host, Target, validate_domain};

pub const VISION_FLOW: &[u8] = b"\x0a\x10xtls-rprx-vision";

pub async fn read_target(reader: &mut (impl AsyncRead + Unpin)) -> Result<Target> {
    let port = reader.read_u16().await?;
    ensure!(port != 0, "invalid VLESS port");
    let host = match reader.read_u8().await? {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            Host::Ip(Ipv4Addr::from(bytes).into())
        }
        2 => {
            let length = reader.read_u8().await?;
            let mut name = vec![0; length.into()];
            reader.read_exact(&mut name).await?;
            let name = validate_domain(std::str::from_utf8(&name)?)?;
            Host::Name(name.to_ascii_lowercase())
        }
        3 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            Host::Ip(Ipv6Addr::from(bytes).into())
        }
        _ => bail!("invalid VLESS address type"),
    };
    Ok(Target { host, port })
}

pub fn put_target(bytes: &mut Vec<u8>, target: &Target) {
    use std::net::IpAddr;
    bytes.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Name(name) => {
            bytes.extend_from_slice(&[2, name.len() as u8]);
            bytes.extend_from_slice(name.as_bytes());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            bytes.push(3);
            bytes.extend_from_slice(&ip.octets());
        }
    }
}

pub async fn vision_first(
    writer: &mut (impl AsyncWrite + Unpin),
    user: uuid::Uuid,
    bytes: &[u8],
) -> Result<()> {
    let length = u16::try_from(bytes.len())?;
    let mut frame = Vec::with_capacity(21 + bytes.len());
    frame.extend_from_slice(user.as_bytes());
    frame.push(1);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(bytes);
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}
