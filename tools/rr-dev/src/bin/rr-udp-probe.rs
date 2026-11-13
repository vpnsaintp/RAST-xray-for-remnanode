//! SOCKS5 UDP ASSOCIATE probe used only inside an owned QEMU guest.
//!
//! Prints exactly one stdout line: `probe=PASS` or `probe=FAIL reason=<token>`.
//! `--hold-ms` keeps the SOCKS control connection open after a successful
//! associate so the controller can observe the landward TCP carrier.

use std::{
    env,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    process::ExitCode,
    thread,
    time::Duration,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            println!("probe=FAIL reason={reason}");
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
    }
}

struct Args {
    socks: Option<String>,
    dest: Option<String>,
    raw_dest: Option<String>,
    payload: String,
    timeout: Duration,
    hold: Duration,
}

fn run() -> Result<(), String> {
    let args = parse(env::args().skip(1))?;
    let payload = args.payload.as_bytes();
    if let Some(raw) = &args.raw_dest {
        raw_exchange(raw, payload, args.timeout)?;
        println!("probe=PASS");
        let _ = std::io::stdout().flush();
        return Ok(());
    }
    let socks = args.socks.as_deref().ok_or("missing --socks")?;
    let dest = args.dest.as_deref().ok_or("missing --dest")?;
    socks_exchange(socks, dest, payload, args.timeout, args.hold)
}

fn parse(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut socks = None;
    let mut dest = None;
    let mut raw_dest = None;
    let mut payload = "rr-guest-udp-proof".to_owned();
    let mut timeout_ms = 5_000_u64;
    let mut hold_ms = 0_u64;
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socks" => socks = Some(args.next().ok_or("missing --socks value")?),
            "--dest" => dest = Some(args.next().ok_or("missing --dest value")?),
            "--raw-dest" => raw_dest = Some(args.next().ok_or("missing --raw-dest value")?),
            "--payload" => payload = args.next().ok_or("missing --payload value")?,
            "--timeout-ms" => {
                timeout_ms = args
                    .next()
                    .ok_or("missing --timeout-ms value")?
                    .parse()
                    .map_err(|_| "invalid --timeout-ms")?;
            }
            "--hold-ms" => {
                hold_ms = args
                    .next()
                    .ok_or("missing --hold-ms value")?
                    .parse()
                    .map_err(|_| "invalid --hold-ms")?;
            }
            other => return Err(format!("unknown-arg-{other}")),
        }
    }
    if raw_dest.is_some() == (socks.is_some() || dest.is_some()) {
        return Err("choose-socks-or-raw".to_owned());
    }
    if socks.is_some() != dest.is_some() && raw_dest.is_none() {
        return Err("socks-requires-dest".to_owned());
    }
    Ok(Args {
        socks,
        dest,
        raw_dest,
        payload,
        timeout: Duration::from_millis(timeout_ms),
        hold: Duration::from_millis(hold_ms),
    })
}

fn raw_exchange(dest: &str, payload: &[u8], timeout: Duration) -> Result<(), String> {
    let dest: SocketAddr = dest.parse().map_err(|_| "bad-raw-dest")?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| "raw-bind")?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|_| "raw-timeout-set")?;
    socket.send_to(payload, dest).map_err(|_| "raw-send")?;
    let mut buf = [0_u8; 2048];
    let (len, _) = socket.recv_from(&mut buf).map_err(|_| "timeout")?;
    if &buf[..len] != payload {
        return Err("payload-mismatch".to_owned());
    }
    Ok(())
}

fn socks_exchange(
    socks: &str,
    dest: &str,
    payload: &[u8],
    timeout: Duration,
    hold: Duration,
) -> Result<(), String> {
    let dest: SocketAddr = dest.parse().map_err(|_| "bad-dest")?;
    let SocketAddr::V4(dest) = dest else {
        return Err("dest-not-ipv4".to_owned());
    };
    let mut tcp = TcpStream::connect(socks).map_err(|_| "socks-connect")?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|_| "socks-timeout-set")?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|_| "socks-timeout-set")?;
    tcp.write_all(&[0x05, 0x01, 0x00])
        .map_err(|_| "socks-greeting-write")?;
    let mut greeting = [0_u8; 2];
    tcp.read_exact(&mut greeting)
        .map_err(|_| "socks-greeting")?;
    if greeting != [0x05, 0x00] {
        return Err("socks-auth".to_owned());
    }
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|_| "socks-associate-write")?;
    let mut header = [0_u8; 4];
    tcp.read_exact(&mut header).map_err(|_| "socks-associate")?;
    if header[1] != 0x00 {
        return Err(format!("socks-rep-{}", header[1]));
    }
    let (bind_ip, bind_port) = match header[3] {
        0x01 => {
            let mut addr = [0_u8; 4];
            let mut port = [0_u8; 2];
            tcp.read_exact(&mut addr).map_err(|_| "socks-bind-addr")?;
            tcp.read_exact(&mut port).map_err(|_| "socks-bind-port")?;
            (std::net::Ipv4Addr::from(addr), u16::from_be_bytes(port))
        }
        other => return Err(format!("socks-atyp-{other}")),
    };
    let udp_dest = if bind_ip.is_unspecified() {
        let peer = tcp.peer_addr().map_err(|_| "socks-peer")?;
        SocketAddr::new(peer.ip(), bind_port)
    } else {
        SocketAddr::from((bind_ip, bind_port))
    };
    let udp = UdpSocket::bind("0.0.0.0:0").map_err(|_| "udp-bind")?;
    udp.set_read_timeout(Some(timeout))
        .map_err(|_| "udp-timeout-set")?;
    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0, 0, 0, 1]);
    packet.extend_from_slice(&dest.ip().octets());
    packet.extend_from_slice(&dest.port().to_be_bytes());
    packet.extend_from_slice(payload);
    udp.send_to(&packet, udp_dest).map_err(|_| "udp-send")?;
    let mut buf = [0_u8; 2048];
    let (len, _) = udp.recv_from(&mut buf).map_err(|_| "timeout")?;
    let body = strip_udp_reply(&buf[..len])?;
    if body != payload {
        return Err("payload-mismatch".to_owned());
    }
    println!("probe=PASS");
    let _ = std::io::stdout().flush();
    if !hold.is_zero() {
        thread::sleep(hold);
    }
    drop(tcp);
    Ok(())
}

fn strip_udp_reply(packet: &[u8]) -> Result<&[u8], String> {
    if packet.len() < 4 || packet[2] != 0 {
        return Err("udp-header".to_owned());
    }
    match packet[3] {
        1 if packet.len() >= 10 => Ok(&packet[10..]),
        4 if packet.len() >= 22 => Ok(&packet[22..]),
        _ => Err("udp-atyp".to_owned()),
    }
}
