//! Mandatory rust↔rust UDP/443 + genuine HTTP/3 over XUDP (AGENTS.md §6 / ADR 0059).
//!
//! Topology for the HTTP/3 case:
//!   Quinn+h3 client → SOCKS5 UDP ASSOCIATE → rust-reality Client
//!     → REALITY+Vision+XUDP → rust-reality Server → Direct **or NXR LANDING** UDP/443
//!     → independent Quinn+h3 origin.
//!
//! NXR cases (ADR 0060 / #314 PR3) place LANDING on `127.0.0.2` so origin peers
//! prove the Internet-facing UDP sender is LANDING, not LINE.
//!
//! Exact-head Native grants CAP_NET_BIND_SERVICE, sets `RR_REQUIRE_UDP443=1`,
//! and runs these `#[ignore]` tests with `--ignored --exact`. Binding
//! `127.0.0.1:443` is required — an unprivileged skip is a FAIL, never a pass.
//!
//! Not native QUIC on the REALITY LINE: XUDP still carries UDP datagrams.
//! Test-only Quinn/h3 deps; never linked into the production binary.

use std::{
    fs,
    io::{self, ErrorKind, IoSliceMut, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket as StdUdpSocket},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use futures::future;
use http::{Request, Response, StatusCode};
use quinn::{
    AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, ServerConfig, UdpPoller,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    udp::{RecvMeta, Transmit},
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket};

const MARKER: &[u8] = b"rr-udp443-xudp-echo-ok";
const H3_BODY: &[u8] = b"rust-reality-genuine-h3-udp443-ok";
const DEST_443: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn bind_udp443() -> StdUdpSocket {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match StdUdpSocket::bind(DEST_443) {
            Ok(sock) => return sock,
            Err(err) if err.kind() == ErrorKind::AddrInUse && Instant::now() < deadline => {
                eprintln!("UDP/443 still in use ({err}); retrying");
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => panic!(
                "cannot bind 127.0.0.1:443 ({err}); Exact-head Native must grant \
                 CAP_NET_BIND_SERVICE (RR_REQUIRE_UDP443=1). Unprivileged skip is FAIL, not PASS"
            ),
        }
    }
}

fn bind_tcp443() -> TcpListener {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match TcpListener::bind(DEST_443) {
            Ok(sock) => return sock,
            Err(err) if err.kind() == ErrorKind::AddrInUse && Instant::now() < deadline => {
                eprintln!("TCP/443 still in use ({err}); retrying");
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => panic!("TCP watchdog bind 127.0.0.1:443: {err}"),
        }
    }
}

struct TcpWatchdog {
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl TcpWatchdog {
    fn spawn() -> Self {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let hits_bg = hits.clone();
        let stop_bg = stop.clone();
        let tcp_watch = bind_tcp443();
        tcp_watch.set_nonblocking(true).ok();
        let join = thread::spawn(move || {
            while !stop_bg.load(Ordering::SeqCst) {
                if tcp_watch.accept().is_ok() {
                    hits_bg.fetch_add(1, Ordering::SeqCst);
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        Self {
            hits,
            stop,
            join: Some(join),
        }
    }
}

impl Drop for TcpWatchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn require_udp443_capability() {
    // Always fail closed when this binary is the mandatory gate: missing bind
    // privilege must never register as a green skip.
    let _probe = bind_udp443();
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

fn wait_tcp(port: u16, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("port {port} not ready within {budget:?}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rust-reality"))
}

fn generate(subcommand: &str) -> String {
    let output = Command::new(bin())
        .args(["generate", subcommand])
        .output()
        .expect("generate");
    assert!(
        output.status.success(),
        "generate {subcommand} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .next()
        .expect("one line")
        .trim()
        .to_owned()
}

fn generate_x25519() -> (String, String) {
    let output = Command::new(bin())
        .args(["generate", "x25519"])
        .output()
        .expect("generate x25519");
    assert!(output.status.success(), "x25519 generate failed");
    let text = String::from_utf8(output.stdout).expect("utf8");
    let mut private = None;
    let mut public = None;
    for line in text.lines() {
        if let Some(v) = line.split_once(':').map(|(_, v)| v.trim()) {
            if line.starts_with("private key") {
                private = Some(v.to_owned());
            } else if line.starts_with("public key") {
                public = Some(v.to_owned());
            }
        }
    }
    (
        private.expect("private key line"),
        public.expect("public key line"),
    )
}

fn write(path: &Path, body: &str) {
    fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn spawn_logged(name: &str, mut command: Command, log: &Path) -> KillOnDrop {
    let file = fs::File::create(log).expect("log file");
    command.stdout(Stdio::from(file.try_clone().expect("clone")));
    command.stderr(Stdio::from(file));
    KillOnDrop(
        command
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}")),
    )
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

fn start_openssl_cover(root: &Path) -> (u16, KillOnDrop) {
    let openssl = which("openssl").expect("openssl required for cover");
    let cover_port = free_port();
    let key = root.join("cover.key");
    let crt = root.join("cover.crt");
    assert!(
        Command::new(&openssl)
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&crt)
            .status()
            .expect("openssl req")
            .success(),
        "openssl req failed"
    );
    let cover = spawn_logged(
        "openssl-cover",
        {
            let mut c = Command::new(&openssl);
            c.args([
                "s_server",
                "-tls1_3",
                "-quiet",
                "-accept",
                &cover_port.to_string(),
                "-cert",
            ])
            .arg(&crt)
            .arg("-key")
            .arg(&key)
            .stdin(Stdio::null());
            c
        },
        &root.join("cover.log"),
    );
    wait_tcp(cover_port, Duration::from_secs(30));
    (cover_port, cover)
}

fn start_rr_stack(root: &Path, allow_udp_443: bool) -> (u16, KillOnDrop, KillOnDrop, KillOnDrop) {
    let (cover_port, cover) = start_openssl_cover(root);
    let (private_key, public_key) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let entry_port = free_port();
    let socks_port = free_port();
    let allow_line = if allow_udp_443 {
        r#", "allowUdp443": true"#
    } else {
        ""
    };

    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{private_key}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "udp443-gate"
  }}],
  "routing": {{ "default": "direct" }}
}}
"#
        ),
    );
    write(
        &root.join("client.json"),
        &format!(
            r#"{{
  "role": "client",
  "listeners": [{{ "port": {socks_port}, "ipv4": "127.0.0.1" }}],
  "lines": [{{
    "address": "127.0.0.1",
    "port": {entry_port},
    "id": "{user_id}",
    "publicKey": "{public_key}",
    "shortId": "{short_id}",
    "serverName": "localhost"{allow_line}
  }}]
}}
"#
        ),
    );

    let entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_tcp(entry_port, Duration::from_secs(20));
    let client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("client.json"));
            c
        },
        &root.join("client.log"),
    );
    wait_tcp(socks_port, Duration::from_secs(20));
    (socks_port, cover, entry, client)
}

/// LINE on 127.0.0.1 + NXR LANDING on 127.0.0.2 (UDP source proof).
fn start_rr_nxr_stack(
    root: &Path,
    allow_udp_443: bool,
) -> (u16, KillOnDrop, KillOnDrop, KillOnDrop, KillOnDrop) {
    let (cover_port, cover) = start_openssl_cover(root);
    let (private_key, public_key) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let psk = generate("psk");
    let entry_port = free_port();
    let landing_port = free_port();
    let socks_port = free_port();
    let allow_line = if allow_udp_443 {
        r#", "allowUdp443": true"#
    } else {
        ""
    };
    write(
        &root.join("landing.json"),
        &format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "127.0.0.2" }}],
  "landing": {{ "protocol": "nxr", "psk": "{psk}" }}
}}
"#
        ),
    );
    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{private_key}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "udp443-nxr"
  }}],
  "outbounds": {{
    "landing-1": {{
      "type": "nxr",
      "address": "127.0.0.2",
      "port": {landing_port},
      "psk": "{psk}",
      "warmTcp": false
    }}
  }},
  "routing": {{ "default": "landing-1" }}
}}
"#
        ),
    );
    write(
        &root.join("client.json"),
        &format!(
            r#"{{
  "role": "client",
  "listeners": [{{ "port": {socks_port}, "ipv4": "127.0.0.1" }}],
  "lines": [{{
    "address": "127.0.0.1",
    "port": {entry_port},
    "id": "{user_id}",
    "publicKey": "{public_key}",
    "shortId": "{short_id}",
    "serverName": "localhost"{allow_line}
  }}]
}}
"#
        ),
    );
    let landing = spawn_logged(
        "landing",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("landing.json"));
            c
        },
        &root.join("landing.log"),
    );
    wait_tcp_addr("127.0.0.2", landing_port, Duration::from_secs(20));
    let entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_tcp(entry_port, Duration::from_secs(20));
    let client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("client.json"));
            c
        },
        &root.join("client.log"),
    );
    wait_tcp(socks_port, Duration::from_secs(20));
    (socks_port, cover, landing, entry, client)
}

/// LINE on 127.0.0.1 + Handoff LANDING on 127.0.0.2 (UDP source proof).
fn start_rr_handoff_stack(
    root: &Path,
    allow_udp_443: bool,
) -> (u16, KillOnDrop, KillOnDrop, KillOnDrop, KillOnDrop) {
    let (cover_port, cover) = start_openssl_cover(root);
    let (reality_private, reality_public) = generate_x25519();
    let (landing_private, landing_public) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let psk = generate("psk");
    let entry_port = free_port();
    let landing_port = free_port();
    let socks_port = free_port();
    let allow_line = if allow_udp_443 {
        r#", "allowUdp443": true"#
    } else {
        ""
    };
    write(
        &root.join("landing.json"),
        &format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "127.0.0.2" }}],
  "landing": {{
    "protocol": "handoff",
    "psk": "{psk}",
    "privateKey": "{landing_private}"
  }}
}}
"#
        ),
    );
    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{reality_private}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "udp443-handoff"
  }}],
  "outbounds": {{
    "landing-1": {{
      "type": "handoff",
      "address": "127.0.0.2",
      "port": {landing_port},
      "psk": "{psk}",
      "landingPublicKey": "{landing_public}",
      "warmTcp": false
    }}
  }},
  "routing": {{ "default": "landing-1" }}
}}
"#
        ),
    );
    write(
        &root.join("client.json"),
        &format!(
            r#"{{
  "role": "client",
  "listeners": [{{ "port": {socks_port}, "ipv4": "127.0.0.1" }}],
  "lines": [{{
    "address": "127.0.0.1",
    "port": {entry_port},
    "id": "{user_id}",
    "publicKey": "{reality_public}",
    "shortId": "{short_id}",
    "serverName": "localhost"{allow_line}
  }}]
}}
"#
        ),
    );
    let landing = spawn_logged(
        "landing",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("landing.json"));
            c
        },
        &root.join("landing.log"),
    );
    wait_tcp_addr("127.0.0.2", landing_port, Duration::from_secs(20));
    let entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_tcp(entry_port, Duration::from_secs(20));
    let client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("client.json"));
            c
        },
        &root.join("client.log"),
    );
    wait_tcp(socks_port, Duration::from_secs(20));
    (socks_port, cover, landing, entry, client)
}

fn wait_tcp_addr(ip: &str, port: u16, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        if TcpStream::connect((ip, port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{ip}:{port} not ready within {budget:?}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn socks5_udp_round_trip(
    socks_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut control =
        TcpStream::connect(("127.0.0.1", socks_port)).map_err(|e| format!("socks connect: {e}"))?;
    control.set_read_timeout(Some(Duration::from_secs(10))).ok();
    control
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();
    control
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("method: {e}"))?;
    let mut method = [0_u8; 2];
    control
        .read_exact(&mut method)
        .map_err(|e| format!("method reply: {e}"))?;
    if method != [0x05, 0x00] {
        return Err(format!("unexpected method reply {method:?}"));
    }
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| format!("associate: {e}"))?;
    let mut reply = [0_u8; 10];
    control
        .read_exact(&mut reply)
        .map_err(|e| format!("associate reply: {e}"))?;
    if reply[0] != 0x05 || reply[1] != 0x00 || reply[3] != 0x01 {
        return Err(format!("associate failed: {reply:?}"));
    }
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let udp = StdUdpSocket::bind("127.0.0.1:0").map_err(|e| format!("udp bind: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("udp timeout: {e}"))?;
    let mut datagram = vec![0, 0, 0, 1, 127, 0, 0, 1];
    datagram.extend_from_slice(&dest_port.to_be_bytes());
    datagram.extend_from_slice(payload);
    udp.send_to(&datagram, relay)
        .map_err(|e| format!("udp send: {e}"))?;
    let mut buf = [0_u8; 65535];
    let (n, _) = udp
        .recv_from(&mut buf)
        .map_err(|e| format!("udp recv: {e}"))?;
    if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 1 {
        return Err(format!(
            "bad socks udp reply header: {:?}",
            &buf[..n.min(16)]
        ));
    }
    drop(control);
    Ok(buf[10..n].to_vec())
}

/// Positive UDP/443 echo through XUDP with allowUdp443 (no TCP CONNECT).
#[test]
#[ignore = "requires CAP_NET_BIND_SERVICE for 127.0.0.1:443; Exact-head Native runs with --ignored"]
fn udp443_echo_via_xudp_with_allow_udp443() {
    require_udp443_capability();
    let root = std::env::temp_dir().join(format!("rr-udp443-echo-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    let echo = bind_udp443();
    assert_eq!(echo.local_addr().unwrap().port(), 443);
    echo.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let echo_c = echo.try_clone().unwrap();
    let echo_thread = thread::spawn(move || {
        let mut buf = [0_u8; 65535];
        for _ in 0..16 {
            match echo_c.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let _ = echo_c.send_to(&buf[..n], from);
                }
                Err(_) => break,
            }
        }
    });

    // TCP watchdog: any TCP accept on :443 means an illicit TCP fallback path.
    let watchdog = TcpWatchdog::spawn();

    let (socks_port, _cover, _entry, _client) = start_rr_stack(&root, true);
    let body = socks5_udp_round_trip(socks_port, 443, MARKER).unwrap_or_else(|e| {
        panic!(
            "UDP/443 XUDP echo failed (no TCP fallback expected): {e}\nentry:\n{}\nclient:\n{}",
            fs::read_to_string(root.join("entry.log")).unwrap_or_default(),
            fs::read_to_string(root.join("client.log")).unwrap_or_default()
        );
    });
    assert_eq!(body, MARKER);
    let _ = echo_thread.join();
    assert_eq!(
        watchdog.hits.load(Ordering::SeqCst),
        0,
        "TCP accept on :443 — illicit TCP fallback"
    );
    eprintln!("udp443_echo_via_xudp PASS (SOCKS5 UDP ASSOCIATE only)");
}

/// Negative: without allowUdp443, UDP/443 must fail closed before destination delivery.
#[test]
#[ignore = "paired with mandatory UDP/443 positive gate; Exact-head Native runs with --ignored"]
fn udp443_rejected_without_allow_udp443_before_destination() {
    // Does not require binding :443 — policy rejects on the client. Still
    // marked ignore so default nextest is not the mandatory receipt; Native
    // runs it explicitly alongside the positive case.
    let root = std::env::temp_dir().join(format!("rr-udp443-deny-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());
    let (socks_port, _cover, _entry, _client) = start_rr_stack(&root, false);
    let err = socks5_udp_round_trip(socks_port, 443, b"deny-probe")
        .expect_err("UDP/443 without allowUdp443 must fail");
    assert!(
        err.contains("udp recv") || err.contains("associate") || err.contains("udp send"),
        "unexpected error shape: {err}"
    );
    eprintln!("udp443_rejected_without_allow_udp443 PASS ({err})");
}

// --- SOCKS5-proxied AsyncUdpSocket for Quinn ---------------------------------

struct Socks5UdpSocket {
    udp: UdpSocket,
    relay: SocketAddr,
    target: SocketAddr,
    _control: TokioTcpStream,
}

#[derive(Debug)]
struct Socks5Poller {
    sock: Arc<Socks5UdpSocket>,
}

impl UdpPoller for Socks5Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sock.udp.poll_send_ready(cx)
    }
}

impl std::fmt::Debug for Socks5UdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5UdpSocket")
            .field("relay", &self.relay)
            .field("target", &self.target)
            .finish()
    }
}

impl AsyncUdpSocket for Socks5UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Socks5Poller { sock: self })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "SOCKS5 UDP socket expected {} got {}",
                    self.target, transmit.destination
                ),
            ));
        }
        let mut buf = Vec::with_capacity(10 + transmit.contents.len());
        buf.extend_from_slice(&[0, 0, 0, 1, 127, 0, 0, 1]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(transmit.contents);
        match self.udp.try_send_to(&buf, self.relay) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => Err(e),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut scratch = vec![0u8; bufs[0].len().saturating_add(32).max(2048)];
        loop {
            let mut read_buf = tokio::io::ReadBuf::new(&mut scratch);
            match self.udp.poll_recv_from(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(src)) => {
                    if src != self.relay {
                        continue;
                    }
                    let n = read_buf.filled().len();
                    if n < 10 || scratch[0] != 0 || scratch[1] != 0 || scratch[2] != 0 {
                        continue;
                    }
                    let payload = &scratch[10..n];
                    if payload.len() > bufs[0].len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "recv buffer too small for SOCKS5 UDP payload",
                        )));
                    }
                    bufs[0][..payload.len()].copy_from_slice(payload);
                    meta[0] = RecvMeta {
                        addr: self.target,
                        len: payload.len(),
                        stride: payload.len(),
                        ecn: None,
                        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    };
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

async fn socks5_udp_associate(socks_port: u16) -> (TokioTcpStream, SocketAddr) {
    let mut control = TokioTcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("socks connect");
    control
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("method");
    let mut method = [0u8; 2];
    tokio::io::AsyncReadExt::read_exact(&mut control, &mut method)
        .await
        .expect("method reply");
    assert_eq!(method, [0x05, 0x00]);
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate");
    let mut reply = [0u8; 10];
    tokio::io::AsyncReadExt::read_exact(&mut control, &mut reply)
        .await
        .expect("associate reply");
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);
    assert_eq!(reply[3], 0x01);
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    (control, relay)
}

fn make_h3_certs() -> (
    CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
    rustls::RootCertStore,
) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
    let cert = CertificateDer::from(certified.cert);
    let key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("add root");
    (cert, key, roots)
}

/// Genuine HTTP/3 (ALPN h3) through SOCKS5 UDP ASSOCIATE → XUDP → UDP/443 origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CAP_NET_BIND_SERVICE + Quinn/h3; Exact-head Native runs with --ignored"]
async fn genuine_http3_over_xudp_udp443_no_tcp_fallback() {
    require_udp443_capability();
    let root = std::env::temp_dir().join(format!("rr-h3-udp443-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    // Bring up rust-reality first (blocking openssl); keep it off the hot path
    // of the Quinn accept loop by using a dedicated thread pool (multi_thread).
    let (socks_port, _cover, _entry, _client) = tokio::task::spawn_blocking({
        let root = root.clone();
        move || start_rr_stack(&root, true)
    })
    .await
    .expect("stack join");

    let watchdog = TcpWatchdog::spawn();

    let (cert, key, roots) = make_h3_certs();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .expect("server cert");
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    transport.initial_mtu(1200);
    server_config.transport = Arc::new(transport);

    let server_sock = bind_udp443();
    assert_eq!(server_sock.local_addr().unwrap().port(), 443);
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_sock,
        quinn::default_runtime().expect("tokio runtime"),
    )
    .expect("server endpoint");

    let server_task = tokio::spawn(async move {
        let incoming = server
            .accept()
            .await
            .expect("accept")
            .await
            .expect("handshake");
        let origin_alpn = incoming
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hs| hs.protocol)
            .unwrap_or_default();
        eprintln!("h3-origin negotiated ALPN={origin_alpn:?}");
        assert_eq!(origin_alpn.as_slice(), b"h3", "origin ALPN must be h3");
        let mut h3 = h3::server::builder()
            .build(h3_quinn::Connection::new(incoming))
            .await
            .expect("h3 server");
        let mut handled = 0usize;
        while let Ok(Some(resolver)) = h3.accept().await {
            let (req, mut stream) = resolver.resolve_request().await.expect("resolve");
            assert_eq!(req.uri().path(), "/rr-h3-probe");
            let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
            stream.send_response(response).await.expect("resp");
            stream
                .send_data(Bytes::from_static(H3_BODY))
                .await
                .expect("body");
            stream.finish().await.expect("finish");
            handled += 1;
            eprintln!("h3-origin handled request #{handled}");
        }
        eprintln!("h3-origin accept loop ended after {handled} requests");
        handled
    });

    let (control, relay) = socks5_udp_associate(socks_port).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    let socks = Arc::new(Socks5UdpSocket {
        udp,
        relay,
        target: DEST_443,
        _control: control,
    });

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    client_crypto.enable_early_data = true;

    let mut client_endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socks,
        quinn::default_runtime().expect("tokio runtime"),
    )
    .expect("client endpoint");
    let mut client_transport = quinn::TransportConfig::default();
    client_transport.initial_mtu(1200);
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(Arc::new(client_transport));
    client_endpoint.set_default_client_config(client_config);

    let conn = client_endpoint
        .connect(DEST_443, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake via XUDP");
    let client_alpn = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .unwrap_or_default();
    assert_eq!(client_alpn.as_slice(), b"h3", "client ALPN must be h3");
    eprintln!(
        "h3-client negotiated ALPN=h3; remote={:?}",
        conn.remote_address()
    );

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .expect("h3 client");

    let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };

    let request = async move {
        for i in 0..3usize {
            if i == 2 {
                eprintln!("h3-client idle sleep before request 2");
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
            eprintln!("h3-client starting request {i}");
            let req = Request::builder()
                .uri("https://localhost/rr-h3-probe")
                .body(())
                .unwrap();
            let mut stream = send_request.send_request(req).await.expect("send_request");
            stream.finish().await.expect("req finish");
            let response = stream.recv_response().await.expect("recv_response");
            assert_eq!(response.status(), StatusCode::OK, "request {i}");
            let mut body = Vec::new();
            while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
                body.extend_from_slice(chunk.chunk());
            }
            assert_eq!(body, H3_BODY, "request {i} body");
            eprintln!("h3-client finished request {i}");
        }
        Ok::<_, ()>(())
    };

    let (req_res, drive_res) = tokio::join!(request, drive);
    req_res.expect("H3 requests");
    // `poll_close` resolves to ConnectionError (including graceful H3_NO_ERROR).
    eprintln!("h3 drive finished: {drive_res:?}");

    let handled = server_task.await.expect("server task");
    assert!(
        handled >= 3,
        "origin handled {handled} H3 requests (want >= 3)"
    );
    assert_eq!(
        watchdog.hits.load(Ordering::SeqCst),
        0,
        "TCP accept on :443 during H3 — illicit TCP fallback"
    );
    eprintln!(
        "genuine_http3_over_xudp_udp443 PASS (ALPN h3, {handled} origin requests, idle survived, no TCP fallback)"
    );
    client_endpoint.close(0u32.into(), b"done");
}

/// Genuine HTTP/3 through NXR LANDING UDP/443 (ADR 0060 / #314 PR3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CAP_NET_BIND_SERVICE + Quinn/h3; Exact-head Native runs with --ignored"]
async fn genuine_http3_over_nxr_xudp_udp443_no_tcp_fallback() {
    require_udp443_capability();
    let root = std::env::temp_dir().join(format!("rr-h3-nxr-udp443-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    let (socks_port, _cover, _landing, _entry, _client) = tokio::task::spawn_blocking({
        let root = root.clone();
        move || start_rr_nxr_stack(&root, true)
    })
    .await
    .expect("nxr stack join");

    let watchdog = TcpWatchdog::spawn();

    let origin_peers = Arc::new(std::sync::Mutex::new(Vec::<SocketAddr>::new()));
    let (cert, key, roots) = make_h3_certs();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .expect("server cert");
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    transport.initial_mtu(1200);
    server_config.transport = Arc::new(transport);

    let server_sock = bind_udp443();
    assert_eq!(server_sock.local_addr().unwrap().port(), 443);
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_sock,
        quinn::default_runtime().expect("tokio runtime"),
    )
    .expect("server endpoint");

    let peers_bg = origin_peers.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server
            .accept()
            .await
            .expect("accept")
            .await
            .expect("handshake");
        peers_bg.lock().unwrap().push(incoming.remote_address());
        let origin_alpn = incoming
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hs| hs.protocol)
            .unwrap_or_default();
        assert_eq!(origin_alpn.as_slice(), b"h3", "origin ALPN must be h3");
        let mut h3 = h3::server::builder()
            .build(h3_quinn::Connection::new(incoming))
            .await
            .expect("h3 server");
        let mut handled = 0usize;
        while let Ok(Some(resolver)) = h3.accept().await {
            let (req, mut stream) = resolver.resolve_request().await.expect("resolve");
            assert_eq!(req.uri().path(), "/rr-h3-probe");
            let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
            stream.send_response(response).await.expect("resp");
            stream
                .send_data(Bytes::from_static(H3_BODY))
                .await
                .expect("body");
            stream.finish().await.expect("finish");
            handled += 1;
        }
        handled
    });

    let (control, relay) = socks5_udp_associate(socks_port).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    let socks = Arc::new(Socks5UdpSocket {
        udp,
        relay,
        target: DEST_443,
        _control: control,
    });

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    client_crypto.enable_early_data = true;

    let mut client_endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socks,
        quinn::default_runtime().expect("tokio runtime"),
    )
    .expect("client endpoint");
    let mut client_transport = quinn::TransportConfig::default();
    client_transport.initial_mtu(1200);
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(Arc::new(client_transport));
    client_endpoint.set_default_client_config(client_config);

    let conn = client_endpoint
        .connect(DEST_443, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake via NXR XUDP");
    assert_eq!(
        conn.handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.protocol)
            .unwrap_or_default()
            .as_slice(),
        b"h3"
    );

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .expect("h3 client");
    let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
    let request = async move {
        for i in 0..3usize {
            if i == 2 {
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
            let req = Request::builder()
                .uri("https://localhost/rr-h3-probe")
                .body(())
                .unwrap();
            let mut stream = send_request.send_request(req).await.expect("send_request");
            stream.finish().await.expect("req finish");
            let response = stream.recv_response().await.expect("recv_response");
            assert_eq!(response.status(), StatusCode::OK, "request {i}");
            let mut body = Vec::new();
            while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
                body.extend_from_slice(chunk.chunk());
            }
            assert_eq!(body, H3_BODY, "request {i} body");
        }
        Ok::<_, ()>(())
    };
    let (req_res, _drive_res) = tokio::join!(request, drive);
    req_res.expect("H3 requests");
    let handled = server_task.await.expect("server task");
    assert!(handled >= 3, "origin handled {handled}");
    assert_eq!(
        watchdog.hits.load(Ordering::SeqCst),
        0,
        "TCP fallback on :443"
    );
    let peers = origin_peers.lock().unwrap().clone();
    assert!(
        peers
            .iter()
            .any(|p| p.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        "H3 origin must see LANDING 127.0.0.2 as UDP peer, got {peers:?}"
    );
    eprintln!(
        "genuine_http3_over_nxr_xudp_udp443 PASS (ALPN h3, {handled} requests, peers={peers:?}, no TCP fallback)"
    );
    client_endpoint.close(0u32.into(), b"done");
}

/// Stock Xray Client → LINE → NXR LANDING → genuine HTTP/3 UDP/443.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires XRAY_BIN + CAP_NET_BIND_SERVICE; Exact-head Native runs with --ignored"]
async fn stock_xray_client_nxr_genuine_http3_udp443() {
    require_udp443_capability();
    let xray = std::env::var_os("XRAY_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("XRAY_BIN unset; Exact-head Native must export pinned stock Xray")
        });
    assert!(xray.is_file(), "XRAY_BIN missing");

    let root = std::env::temp_dir().join(format!("rr-h3-xray-nxr-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    let (cover_port, _cover) = start_openssl_cover(&root);
    let (private_key, public_key) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let psk = generate("psk");
    let entry_port = free_port();
    let landing_port = free_port();
    let socks_port = free_port();

    write(
        &root.join("landing.json"),
        &format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "127.0.0.2" }}],
  "landing": {{ "protocol": "nxr", "psk": "{psk}" }}
}}
"#
        ),
    );
    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{private_key}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "xray-nxr-h3"
  }}],
  "outbounds": {{
    "landing-1": {{
      "type": "nxr",
      "address": "127.0.0.2",
      "port": {landing_port},
      "psk": "{psk}",
      "warmTcp": false
    }}
  }},
  "routing": {{ "default": "landing-1" }}
}}
"#
        ),
    );
    write(
        &root.join("xray-client.json"),
        &format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{ "auth": "noauth", "udp": true }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{
      "vnext": [{{
        "address": "127.0.0.1",
        "port": {entry_port},
        "users": [{{
          "id": "{user_id}",
          "encryption": "none",
          "flow": "xtls-rprx-vision-udp443"
        }}]
      }}]
    }},
    "streamSettings": {{
      "network": "tcp",
      "security": "reality",
      "realitySettings": {{
        "fingerprint": "chrome",
        "serverName": "localhost",
        "publicKey": "{public_key}",
        "shortId": "{short_id}",
        "spiderX": "/"
      }}
    }}
  }}]
}}
"#
        ),
    );

    let _landing = spawn_logged(
        "landing",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("landing.json"));
            c
        },
        &root.join("landing.log"),
    );
    wait_tcp_addr("127.0.0.2", landing_port, Duration::from_secs(20));
    let _entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_tcp(entry_port, Duration::from_secs(20));
    let _xray = spawn_logged(
        "xray-client",
        {
            let mut c = Command::new(&xray);
            c.args(["run", "-c"]).arg(root.join("xray-client.json"));
            c
        },
        &root.join("xray-client.log"),
    );
    wait_tcp(socks_port, Duration::from_secs(20));

    let watchdog = TcpWatchdog::spawn();

    let origin_peers = Arc::new(std::sync::Mutex::new(Vec::<SocketAddr>::new()));
    let (cert, key, roots) = make_h3_certs();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .expect("server cert");
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    transport.initial_mtu(1200);
    server_config.transport = Arc::new(transport);
    let server_sock = bind_udp443();
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_sock,
        quinn::default_runtime().expect("runtime"),
    )
    .expect("endpoint");
    let peers_bg = origin_peers.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("accept").await.expect("hs");
        peers_bg.lock().unwrap().push(incoming.remote_address());
        assert_eq!(
            incoming
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.protocol)
                .unwrap_or_default()
                .as_slice(),
            b"h3"
        );
        let mut h3 = h3::server::builder()
            .build(h3_quinn::Connection::new(incoming))
            .await
            .expect("h3");
        let mut handled = 0usize;
        while let Ok(Some(resolver)) = h3.accept().await {
            let (req, mut stream) = resolver.resolve_request().await.expect("resolve");
            assert_eq!(req.uri().path(), "/rr-h3-probe");
            stream
                .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
                .await
                .unwrap();
            stream.send_data(Bytes::from_static(H3_BODY)).await.unwrap();
            stream.finish().await.unwrap();
            handled += 1;
        }
        handled
    });

    let (control, relay) = socks5_udp_associate(socks_port).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socks = Arc::new(Socks5UdpSocket {
        udp,
        relay,
        target: DEST_443,
        _control: control,
    });
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut client_endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socks,
        quinn::default_runtime().unwrap(),
    )
    .unwrap();
    let mut client_transport = quinn::TransportConfig::default();
    client_transport.initial_mtu(1200);
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(Arc::new(client_transport));
    client_endpoint.set_default_client_config(client_config);
    let conn = client_endpoint
        .connect(DEST_443, "localhost")
        .unwrap()
        .await
        .expect("QUIC via stock Xray → NXR");
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
    let request = async move {
        for i in 0..2usize {
            let req = Request::builder()
                .uri("https://localhost/rr-h3-probe")
                .body(())
                .unwrap();
            let mut stream = send_request.send_request(req).await.unwrap();
            stream.finish().await.unwrap();
            assert_eq!(
                stream.recv_response().await.unwrap().status(),
                StatusCode::OK
            );
            let mut body = Vec::new();
            while let Some(chunk) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(chunk.chunk());
            }
            assert_eq!(body, H3_BODY, "req {i}");
        }
        Ok::<_, ()>(())
    };
    let (req_res, _) = tokio::join!(request, drive);
    req_res.unwrap();
    let handled = server_task.await.unwrap();
    assert!(handled >= 2);
    assert_eq!(watchdog.hits.load(Ordering::SeqCst), 0);
    let peers = origin_peers.lock().unwrap().clone();
    assert!(
        peers
            .iter()
            .any(|p| p.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        "stock Xray NXR H3 origin peers must include LANDING 127.0.0.2, got {peers:?}"
    );
    eprintln!("stock_xray_client_nxr_genuine_http3_udp443 PASS peers={peers:?}");
    client_endpoint.close(0u32.into(), b"done");
}

/// Genuine HTTP/3 through Handoff LANDING UDP/443 (ADR 0060 / #314 PR6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CAP_NET_BIND_SERVICE + Quinn/h3; Exact-head Native runs with --ignored"]
async fn genuine_http3_over_handoff_xudp_udp443_no_tcp_fallback() {
    require_udp443_capability();
    let root = std::env::temp_dir().join(format!("rr-h3-handoff-udp443-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    let (socks_port, _cover, _landing, _entry, _client) = tokio::task::spawn_blocking({
        let root = root.clone();
        move || start_rr_handoff_stack(&root, true)
    })
    .await
    .expect("handoff stack join");

    let watchdog = TcpWatchdog::spawn();

    let origin_peers = Arc::new(std::sync::Mutex::new(Vec::<SocketAddr>::new()));
    let (cert, key, roots) = make_h3_certs();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .expect("server cert");
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    transport.initial_mtu(1200);
    server_config.transport = Arc::new(transport);

    let server_sock = bind_udp443();
    assert_eq!(server_sock.local_addr().unwrap().port(), 443);
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_sock,
        quinn::default_runtime().expect("tokio runtime"),
    )
    .expect("server endpoint");

    let peers_bg = origin_peers.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server
            .accept()
            .await
            .expect("accept")
            .await
            .expect("handshake");
        peers_bg.lock().unwrap().push(incoming.remote_address());
        let origin_alpn = incoming
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hs| hs.protocol)
            .unwrap_or_default();
        assert_eq!(origin_alpn.as_slice(), b"h3", "origin ALPN must be h3");
        let mut h3 = h3::server::builder()
            .build(h3_quinn::Connection::new(incoming))
            .await
            .expect("h3 server");
        let mut handled = 0usize;
        while let Ok(Some(resolver)) = h3.accept().await {
            let (req, mut stream) = resolver.resolve_request().await.expect("resolve");
            assert_eq!(req.uri().path(), "/rr-h3-probe");
            let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
            stream.send_response(response).await.expect("resp");
            stream
                .send_data(Bytes::from_static(H3_BODY))
                .await
                .expect("body");
            stream.finish().await.expect("finish");
            handled += 1;
        }
        handled
    });

    let (control, relay) = socks5_udp_associate(socks_port).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    let socks = Arc::new(Socks5UdpSocket {
        udp,
        relay,
        target: DEST_443,
        _control: control,
    });

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    client_crypto.enable_early_data = true;

    let mut client_endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socks,
        quinn::default_runtime().expect("tokio runtime"),
    )
    .expect("client endpoint");
    let mut client_transport = quinn::TransportConfig::default();
    client_transport.initial_mtu(1200);
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(Arc::new(client_transport));
    client_endpoint.set_default_client_config(client_config);

    let conn = client_endpoint
        .connect(DEST_443, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake via Handoff XUDP");
    assert_eq!(
        conn.handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.protocol)
            .unwrap_or_default()
            .as_slice(),
        b"h3"
    );

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .expect("h3 client");
    let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
    let request = async move {
        for i in 0..3usize {
            if i == 2 {
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
            let req = Request::builder()
                .uri("https://localhost/rr-h3-probe")
                .body(())
                .unwrap();
            let mut stream = send_request.send_request(req).await.expect("send_request");
            stream.finish().await.expect("req finish");
            let response = stream.recv_response().await.expect("recv_response");
            assert_eq!(response.status(), StatusCode::OK, "request {i}");
            let mut body = Vec::new();
            while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
                body.extend_from_slice(chunk.chunk());
            }
            assert_eq!(body, H3_BODY, "request {i} body");
        }
        Ok::<_, ()>(())
    };
    let (req_res, _drive_res) = tokio::join!(request, drive);
    req_res.expect("H3 requests");
    let handled = server_task.await.expect("server task");
    assert!(handled >= 3, "origin handled {handled}");
    assert_eq!(
        watchdog.hits.load(Ordering::SeqCst),
        0,
        "TCP fallback on :443"
    );
    let peers = origin_peers.lock().unwrap().clone();
    assert!(
        peers
            .iter()
            .any(|p| p.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        "H3 origin must see LANDING 127.0.0.2 as UDP peer, got {peers:?}"
    );
    eprintln!(
        "genuine_http3_over_handoff_xudp_udp443 PASS (ALPN h3, {handled} requests, peers={peers:?}, no TCP fallback)"
    );
    client_endpoint.close(0u32.into(), b"done");
}

/// Stock Xray Client → LINE → Handoff LANDING → genuine HTTP/3 UDP/443.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires XRAY_BIN + CAP_NET_BIND_SERVICE; Exact-head Native runs with --ignored"]
async fn stock_xray_client_handoff_genuine_http3_udp443() {
    require_udp443_capability();
    let xray = std::env::var_os("XRAY_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("XRAY_BIN unset; Exact-head Native must export pinned stock Xray")
        });
    assert!(xray.is_file(), "XRAY_BIN missing");

    let root = std::env::temp_dir().join(format!("rr-h3-xray-handoff-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    let (cover_port, _cover) = start_openssl_cover(&root);
    let (reality_private, reality_public) = generate_x25519();
    let (landing_private, landing_public) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let psk = generate("psk");
    let entry_port = free_port();
    let landing_port = free_port();
    let socks_port = free_port();

    write(
        &root.join("landing.json"),
        &format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "127.0.0.2" }}],
  "landing": {{
    "protocol": "handoff",
    "psk": "{psk}",
    "privateKey": "{landing_private}"
  }}
}}
"#
        ),
    );
    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{reality_private}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "xray-handoff-h3"
  }}],
  "outbounds": {{
    "landing-1": {{
      "type": "handoff",
      "address": "127.0.0.2",
      "port": {landing_port},
      "psk": "{psk}",
      "landingPublicKey": "{landing_public}",
      "warmTcp": false
    }}
  }},
  "routing": {{ "default": "landing-1" }}
}}
"#
        ),
    );
    write(
        &root.join("xray-client.json"),
        &format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{ "auth": "noauth", "udp": true }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{
      "vnext": [{{
        "address": "127.0.0.1",
        "port": {entry_port},
        "users": [{{
          "id": "{user_id}",
          "encryption": "none",
          "flow": "xtls-rprx-vision-udp443"
        }}]
      }}]
    }},
    "streamSettings": {{
      "network": "tcp",
      "security": "reality",
      "realitySettings": {{
        "fingerprint": "chrome",
        "serverName": "localhost",
        "publicKey": "{reality_public}",
        "shortId": "{short_id}",
        "spiderX": "/"
      }}
    }}
  }}]
}}
"#
        ),
    );

    let _landing = spawn_logged(
        "landing",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("landing.json"));
            c
        },
        &root.join("landing.log"),
    );
    wait_tcp_addr("127.0.0.2", landing_port, Duration::from_secs(20));
    let _entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_tcp(entry_port, Duration::from_secs(20));
    let _xray = spawn_logged(
        "xray-client",
        {
            let mut c = Command::new(&xray);
            c.args(["run", "-c"]).arg(root.join("xray-client.json"));
            c
        },
        &root.join("xray-client.log"),
    );
    wait_tcp(socks_port, Duration::from_secs(20));

    let watchdog = TcpWatchdog::spawn();

    let origin_peers = Arc::new(std::sync::Mutex::new(Vec::<SocketAddr>::new()));
    let (cert, key, roots) = make_h3_certs();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .expect("server cert");
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    transport.initial_mtu(1200);
    server_config.transport = Arc::new(transport);

    let server_sock = bind_udp443();
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_sock,
        quinn::default_runtime().expect("tokio runtime"),
    )
    .expect("server endpoint");

    let peers_bg = origin_peers.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server
            .accept()
            .await
            .expect("accept")
            .await
            .expect("handshake");
        peers_bg.lock().unwrap().push(incoming.remote_address());
        let mut h3 = h3::server::builder()
            .build(h3_quinn::Connection::new(incoming))
            .await
            .expect("h3 server");
        let mut handled = 0usize;
        while let Ok(Some(resolver)) = h3.accept().await {
            let (_req, mut stream) = resolver.resolve_request().await.expect("resolve");
            let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
            stream.send_response(response).await.expect("resp");
            stream
                .send_data(Bytes::from_static(H3_BODY))
                .await
                .expect("body");
            stream.finish().await.expect("finish");
            handled += 1;
        }
        handled
    });

    let (control, relay) = socks5_udp_associate(socks_port).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    let socks = Arc::new(Socks5UdpSocket {
        udp,
        relay,
        target: DEST_443,
        _control: control,
    });

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    client_crypto.enable_early_data = true;

    let mut client_endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socks,
        quinn::default_runtime().expect("tokio runtime"),
    )
    .expect("client endpoint");
    let mut client_transport = quinn::TransportConfig::default();
    client_transport.initial_mtu(1200);
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(Arc::new(client_transport));
    client_endpoint.set_default_client_config(client_config);

    let conn = client_endpoint
        .connect(DEST_443, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake via stock Xray → Handoff");
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .expect("h3 client");
    let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
    let request = async move {
        let req = Request::builder()
            .uri("https://localhost/rr-h3-probe")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.expect("send_request");
        stream.finish().await.expect("req finish");
        let response = stream.recv_response().await.expect("recv_response");
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
            body.extend_from_slice(chunk.chunk());
        }
        assert_eq!(body, H3_BODY);
        Ok::<_, ()>(())
    };
    let (req_res, _drive_res) = tokio::join!(request, drive);
    req_res.expect("H3 request");
    let handled = server_task.await.expect("server task");
    assert!(handled >= 1, "origin handled {handled}");
    assert_eq!(
        watchdog.hits.load(Ordering::SeqCst),
        0,
        "TCP fallback on :443"
    );
    let peers = origin_peers.lock().unwrap().clone();
    assert!(
        peers
            .iter()
            .any(|p| p.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        "H3 origin must see LANDING 127.0.0.2, got {peers:?}"
    );
    eprintln!("stock_xray_client_handoff_genuine_http3_udp443 PASS peers={peers:?}");
    client_endpoint.close(0u32.into(), b"done");
}
