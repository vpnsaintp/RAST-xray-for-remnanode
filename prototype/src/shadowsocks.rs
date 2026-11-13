use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use aws_lc_rs::{aead, digest, hkdf, rand};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant, timeout};
use uuid::Uuid;

use crate::backend::{Backend, Flow};
use crate::egress::{put_socks_target, read_socks_target};
use crate::sniff::{Detected, Sniffing};
use crate::state::{Traffic, User};
use crate::udp::{self, ContextInfo, Packet};
use crate::{CONNECT_TIMEOUT, MAX_INBOUND_CONNECTIONS, accept_tcp, canonical_address};

const SALT_SIZE: usize = 32;
const TAG_SIZE: usize = 16;
const MAX_CHUNK: usize = 0x3fff;
const MAX_DATAGRAM: usize = 65_507;
const UDP_IDLE: Duration = Duration::from_secs(120);
const MAX_UDP_SESSIONS: usize = 4096;
const MAX_SALTS: usize = 262_144;
const AUTH_WORK_PER_TICK: usize = 4_096;
const AUTH_TICK: Duration = Duration::from_millis(20);
pub const ACCOUNT_TYPE: &str = "xray.proxy.shadowsocks.Account";
const METHOD: &str = "chacha20-ietf-poly1305";

type Salt = [u8; SALT_SIZE];

pub struct Inbound {
    pub tag: String,
    pub address: SocketAddr,
    pub users: Arc<Users>,
    sniffing: Sniffing,
    tcp: bool,
    udp: bool,
    salts: Arc<Mutex<Salts>>,
    auth_budget: Mutex<AuthBudget>,
}

pub type Users = RwLock<HashMap<Uuid, Client>>;

#[derive(Clone)]
pub struct Client {
    id: Uuid,
    pub user: User,
    password: Arc<str>,
    master: [u8; 32],
    salt_scope: [u8; 16],
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Account {
    #[prost(string, tag = "1")]
    pub password: String,
    #[prost(enumeration = "Cipher", tag = "2")]
    pub cipher_type: i32,
    #[prost(bool, tag = "3")]
    pub iv_check: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum Cipher {
    Chacha20Poly1305 = 7,
}

impl Client {
    fn new(id: Uuid, email: String, password: String) -> Result<Self> {
        ensure!(!password.is_empty(), "empty Shadowsocks password");
        let first = md5::compute(password.as_bytes());
        let mut second = md5::Context::new();
        second.consume(first.0);
        second.consume(password.as_bytes());
        let mut master = [0; 32];
        master[..16].copy_from_slice(&first.0);
        master[16..].copy_from_slice(&second.finalize().0);
        let hash = digest::digest(&digest::SHA256, &master);
        Ok(Self {
            id,
            user: User::new(email, "")?,
            password: password.into(),
            master,
            salt_scope: hash.as_ref()[..16].try_into()?,
        })
    }

    pub fn from_account(email: String, account: Account) -> Result<Self> {
        // Remnanode's batch API uses 0 to request the inbound cipher.
        ensure!(
            account.cipher_type == 0 || account.cipher_type == Cipher::Chacha20Poly1305 as i32,
            "unsupported Shadowsocks cipher"
        );
        let hash = digest::digest(&digest::SHA256, email.as_bytes());
        let id = Uuid::from_bytes(hash.as_ref()[..16].try_into()?);
        Self::new(id, email, account.password)
    }

    pub fn account(&self) -> Account {
        Account {
            password: self.password.to_string(),
            cipher_type: Cipher::Chacha20Poly1305 as i32,
            iv_check: true,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn same_key(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.master.ct_eq(&other.master).into()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    protocol: String,
    tag: String,
    port: u16,
    listen: Option<IpAddr>,
    settings: Settings,
    sniffing: Option<Sniffing>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    network: String,
    clients: Vec<ProfileClient>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileClient {
    id: Option<String>,
    method: String,
    password: String,
    email: String,
    #[serde(default)]
    level: u32,
    #[serde(default, rename = "ivCheck")]
    _iv_check: bool,
}

impl Inbound {
    pub fn parse(value: serde_json::Value) -> Result<Self> {
        let profile: Profile =
            serde_json::from_value(value).context("unsupported Shadowsocks inbound")?;
        ensure!(
            profile.protocol == "shadowsocks" && profile.port != 0,
            "invalid Shadowsocks inbound"
        );
        let networks: HashSet<_> = profile.settings.network.split(',').map(str::trim).collect();
        ensure!(
            !networks.is_empty() && networks.iter().all(|value| matches!(*value, "tcp" | "udp")),
            "unsupported Shadowsocks network"
        );
        let mut users = HashMap::<Uuid, Client>::new();
        for config in profile.settings.clients {
            ensure!(
                config.level == 0 && config.method == METHOD,
                "unsupported Shadowsocks client settings"
            );
            let mut client = Client::from_account(
                config.email,
                Account {
                    password: config.password,
                    cipher_type: Cipher::Chacha20Poly1305 as i32,
                    iv_check: true,
                },
            )?;
            if let Some(id) = config.id {
                client.id = Uuid::parse_str(&id).context("invalid Shadowsocks user ID")?;
            }
            ensure!(
                !users
                    .values()
                    .any(|old| old.user.email == client.user.email || old.same_key(&client)),
                "duplicate Shadowsocks credentials"
            );
            ensure!(
                users.insert(client.id(), client).is_none(),
                "duplicate Shadowsocks user ID"
            );
        }
        Ok(Self {
            tag: profile.tag,
            address: SocketAddr::new(
                profile.listen.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                profile.port,
            ),
            users: Arc::new(RwLock::new(users)),
            sniffing: profile.sniffing.unwrap_or_default(),
            tcp: networks.contains("tcp"),
            udp: networks.contains("udp"),
            salts: Arc::new(Mutex::new(Salts::default())),
            auth_budget: Mutex::new(AuthBudget {
                updated: Instant::now(),
                remaining: AUTH_WORK_PER_TICK,
            }),
        })
    }

    pub fn start(
        self,
        services: &mut tokio::task::JoinSet<Result<()>>,
        backend: Arc<Backend>,
        traffic: Arc<Traffic>,
    ) -> Result<()> {
        let bind = |kind, protocol| -> Result<socket2::Socket> {
            let address = match self.address {
                SocketAddr::V4(ip) if ip.ip().is_unspecified() => {
                    (std::net::Ipv6Addr::UNSPECIFIED, ip.port()).into()
                }
                address => address,
            };
            let socket =
                socket2::Socket::new(socket2::Domain::for_address(address), kind, Some(protocol))?;
            if address.ip().is_unspecified() {
                socket.set_only_v6(false)?;
            }
            socket.set_nonblocking(true)?;
            if kind == socket2::Type::STREAM {
                socket.set_reuse_address(true)?;
            }
            socket.bind(&address.into())?;
            Ok(socket)
        };
        let tcp = if self.tcp {
            let socket = bind(socket2::Type::STREAM, socket2::Protocol::TCP)?;
            socket.listen(crate::LISTEN_BACKLOG)?;
            Some(TcpListener::from_std(socket.into())?)
        } else {
            None
        };
        let udp = if self.udp {
            Some(UdpSocket::from_std(
                bind(socket2::Type::DGRAM, socket2::Protocol::UDP)?.into(),
            )?)
        } else {
            None
        };
        let inbound = Arc::new(self);
        if let Some(listener) = tcp {
            services.spawn(serve_tcp(
                listener,
                inbound.clone(),
                backend.clone(),
                traffic.clone(),
            ));
        }
        if let Some(listener) = udp {
            services.spawn(serve_udp(Arc::new(listener), inbound, backend, traffic));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Salts {
    seen: HashSet<([u8; 16], Salt)>,
    expiry: VecDeque<(Instant, ([u8; 16], Salt))>,
}

impl Salts {
    fn accept(&mut self, key_scope: [u8; 16], salt: Salt) -> Result<()> {
        let now = Instant::now();
        while self
            .expiry
            .front()
            .is_some_and(|(expires, _)| *expires <= now)
        {
            if let Some((_, entry)) = self.expiry.pop_front() {
                self.seen.remove(&entry);
            }
        }
        ensure!(self.seen.len() < MAX_SALTS, "Shadowsocks replay cache full");
        let entry = (key_scope, salt);
        ensure!(self.seen.insert(entry), "duplicate Shadowsocks salt");
        self.expiry.push_back((now + UDP_IDLE, entry));
        Ok(())
    }
}

struct KeyLength;
impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

fn session_key(client: &Client, salt: &Salt) -> aead::LessSafeKey {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt).extract(&client.master);
    let mut key = [0; 32];
    prk.expand(&[b"ss-subkey"], KeyLength)
        .expect("valid Shadowsocks HKDF length")
        .fill(&mut key)
        .expect("fixed key length");
    aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).expect("fixed ChaCha20 key length"),
    )
}

struct AuthBudget {
    updated: Instant,
    remaining: usize,
}

impl AuthBudget {
    fn take(&mut self, work: usize) -> bool {
        if self.updated.elapsed() >= AUTH_TICK {
            self.updated = Instant::now();
            self.remaining = AUTH_WORK_PER_TICK;
        }
        let Some(remaining) = self.remaining.checked_sub(work) else {
            return false;
        };
        self.remaining = remaining;
        true
    }
}

fn authenticate(
    inbound: &Inbound,
    salt: Salt,
    ciphertext: &[u8],
) -> Result<(Client, aead::LessSafeKey, Vec<u8>)> {
    let users = inbound.users.read().unwrap();
    // Budget failed authentication too. Each candidate key processes the packet.
    let work = (1 + ciphertext.len() / 1024)
        .saturating_mul(users.len())
        .min(AUTH_WORK_PER_TICK);
    ensure!(
        inbound.auth_budget.lock().unwrap().take(work),
        "Shadowsocks authentication rate limit reached"
    );
    let mut plaintext = ciphertext.to_vec();
    for client in users.values() {
        let key = session_key(client, &salt);
        plaintext.copy_from_slice(ciphertext);
        if let Ok(opened) = key.open_in_place(nonce(0), aead::Aad::empty(), &mut plaintext) {
            let size = opened.len();
            plaintext.truncate(size);
            inbound
                .salts
                .lock()
                .unwrap()
                .accept(client.salt_scope, salt)?;
            return Ok((client.clone(), key, plaintext));
        }
    }
    anyhow::bail!("Shadowsocks authentication failed");
}

fn nonce(sequence: u64) -> aead::Nonce {
    let mut value = [0; aead::NONCE_LEN];
    value[..8].copy_from_slice(&sequence.to_le_bytes());
    aead::Nonce::assume_unique_for_key(value)
}

fn open(key: &aead::LessSafeKey, sequence: u64, data: &mut [u8]) -> Result<usize> {
    key.open_in_place(nonce(sequence), aead::Aad::empty(), data)
        .map(|body| body.len())
        .map_err(|_| anyhow::anyhow!("invalid Shadowsocks AEAD data"))
}

fn seal(key: &aead::LessSafeKey, sequence: u64, data: &mut Vec<u8>) -> Result<()> {
    key.seal_in_place_append_tag(nonce(sequence), aead::Aad::empty(), data)
        .map_err(|_| anyhow::anyhow!("Shadowsocks AEAD encryption failed"))
}

fn response_salt(client: &Client, salts: &Mutex<Salts>) -> Result<Salt> {
    let mut salt = [0; SALT_SIZE];
    rand::fill(&mut salt).map_err(|_| anyhow::anyhow!("Shadowsocks random salt failed"))?;
    salts.lock().unwrap().accept(client.salt_scope, salt)?;
    Ok(salt)
}

async fn serve_tcp(
    listener: TcpListener,
    inbound: Arc<Inbound>,
    backend: Arc<Backend>,
    traffic: Arc<Traffic>,
) -> Result<()> {
    println!(
        "Shadowsocks TCP listener ready on {}",
        listener.local_addr()?
    );
    let slots = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
    loop {
        let (socket, peer) = accept_tcp(&listener).await?;
        if let Ok(permit) = slots.clone().try_acquire_owned() {
            let (inbound, backend, traffic) = (inbound.clone(), backend.clone(), traffic.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let _ =
                    tcp_session(socket, canonical_address(peer), &inbound, &backend, traffic).await;
            });
        }
    }
}

async fn tcp_session(
    mut socket: TcpStream,
    peer: SocketAddr,
    inbound: &Inbound,
    backend: &Backend,
    traffic: Arc<Traffic>,
) -> Result<()> {
    let listener = canonical_address(socket.local_addr()?);
    let (client, key, length) = timeout(CONNECT_TIMEOUT, async {
        let mut header = [0; SALT_SIZE + 2 + TAG_SIZE];
        socket.read_exact(&mut header).await?;
        authenticate(
            inbound,
            header[..SALT_SIZE].try_into()?,
            &header[SALT_SIZE..],
        )
    })
    .await??;
    let (mut recv, mut send) = socket.split();
    let (mut proxy, clear) = tokio::io::duplex(64 * 1024);
    let (clear_recv, clear_send) = tokio::io::split(clear);
    let forward = async {
        let target = timeout(CONNECT_TIMEOUT, read_socks_target(&mut proxy)).await??;
        let flow = Flow {
            inbound: &inbound.tag,
            email: &client.user.email,
            id: client.id,
            peer,
            listener,
        };
        let mut origin = if inbound.sniffing.enabled {
            crate::open_sniffed_tcp(
                &mut proxy,
                backend,
                &target,
                &inbound.sniffing,
                flow,
                traffic,
            )
            .await?
        } else {
            crate::open_metered_tcp(
                backend,
                &target,
                &inbound.sniffing,
                flow,
                traffic,
                &Detected::default(),
            )
            .await?
        };
        tokio::io::copy_bidirectional(&mut proxy, &mut origin).await?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = async { tokio::try_join!(
            decrypt_tcp(&mut recv, clear_send, key, length),
            encrypt_tcp(clear_recv, &mut send, &client, &inbound.salts),
            forward,
        ).map(|_| ()) } => result,
        _ = client.user.revoked() => Ok(()),
    }
}

async fn decrypt_tcp(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    key: aead::LessSafeKey,
    first_length: Vec<u8>,
) -> Result<()> {
    let mut length = first_length.as_slice().try_into().map(u16::from_be_bytes)?;
    let mut sequence = 1;
    let mut data = Vec::with_capacity(MAX_CHUNK + TAG_SIZE);
    loop {
        ensure!(
            usize::from(length) <= MAX_CHUNK,
            "oversize Shadowsocks TCP chunk"
        );
        data.resize(usize::from(length) + TAG_SIZE, 0);
        reader.read_exact(&mut data).await?;
        let size = open(&key, sequence, &mut data)?;
        writer.write_all(&data[..size]).await?;
        let mut next = [0; 2 + TAG_SIZE];
        if reader.read(&mut next[..1]).await? == 0 {
            break;
        }
        reader.read_exact(&mut next[1..]).await?;
        open(&key, sequence + 1, &mut next)?;
        length = u16::from_be_bytes([next[0], next[1]]);
        sequence += 2;
    }
    writer.shutdown().await?;
    Ok(())
}

async fn encrypt_tcp(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    client: &Client,
    salts: &Mutex<Salts>,
) -> Result<()> {
    let mut payload = [0; MAX_CHUNK];
    let mut size = reader.read(&mut payload).await?;
    if size != 0 {
        let salt = response_salt(client, salts)?;
        writer.write_all(&salt).await?;
        let key = session_key(client, &salt);
        let mut sequence = 0;
        let mut length = Vec::with_capacity(2 + TAG_SIZE);
        let mut data = Vec::with_capacity(MAX_CHUNK + TAG_SIZE);
        while size != 0 {
            length.clear();
            length.extend_from_slice(&(size as u16).to_be_bytes());
            seal(&key, sequence, &mut length)?;
            data.clear();
            data.extend_from_slice(&payload[..size]);
            seal(&key, sequence + 1, &mut data)?;
            writer.write_all(&length).await?;
            writer.write_all(&data).await?;
            sequence += 2;
            size = reader.read(&mut payload).await?;
        }
    }
    writer.shutdown().await?;
    Ok(())
}

async fn serve_udp(
    socket: Arc<UdpSocket>,
    inbound: Arc<Inbound>,
    backend: Arc<Backend>,
    traffic: Arc<Traffic>,
) -> Result<()> {
    let listener = canonical_address(socket.local_addr()?);
    println!("Shadowsocks UDP listener ready on {listener}");
    let mut data = vec![0; MAX_DATAGRAM];
    let mut sessions = HashMap::<(SocketAddr, Uuid), mpsc::Sender<Packet>>::new();
    let mut cleanup = Instant::now();
    loop {
        let (size, peer) = socket.recv_from(&mut data).await?;
        if size < SALT_SIZE + TAG_SIZE + 1 {
            continue;
        }
        let salt = data[..SALT_SIZE].try_into()?;
        let Ok((client, _, mut plaintext)) = authenticate(&inbound, salt, &data[SALT_SIZE..size])
        else {
            continue;
        };
        plaintext[0] &= 0x0f;
        let mut body = plaintext.as_slice();
        let Ok(target) = read_socks_target(&mut body).await else {
            continue;
        };
        if cleanup.elapsed() >= Duration::from_secs(1) {
            sessions.retain(|_, sender| !sender.is_closed());
            cleanup = Instant::now();
        }
        let key = (peer, client.id);
        if sessions.get(&key).is_some_and(mpsc::Sender::is_closed) {
            sessions.remove(&key);
        }
        if sessions.len() >= MAX_UDP_SESSIONS && !sessions.contains_key(&key) {
            continue;
        }
        let sender = sessions.entry(key).or_insert_with(|| {
            let (sender, input) = mpsc::channel(32);
            let (socket, inbound, backend, traffic) = (
                socket.clone(),
                inbound.clone(),
                backend.clone(),
                traffic.clone(),
            );
            tokio::spawn(async move {
                let _ = udp_session(
                    socket, peer, listener, &inbound, &backend, traffic, client, input,
                )
                .await;
            });
            sender
        });
        let _ = sender.try_send(Packet {
            target,
            data: body.to_vec(),
        });
    }
}

async fn udp_session(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    listener: SocketAddr,
    inbound: &Inbound,
    backend: &Backend,
    traffic: Arc<Traffic>,
    client: Client,
    mut input: mpsc::Receiver<Packet>,
) -> Result<()> {
    let (packets, packet_rx) = mpsc::channel(32);
    let (reply_tx, mut replies) = mpsc::channel::<Packet>(32);
    let ctx = ContextInfo {
        backend,
        traffic,
        sniffing: &inbound.sniffing,
        flow: Flow {
            inbound: &inbound.tag,
            email: &client.user.email,
            id: client.id,
            peer: canonical_address(peer),
            listener,
        },
    };
    let send = async {
        while let Ok(Some(packet)) = timeout(UDP_IDLE, input.recv()).await {
            if packets.send(packet).await.is_err() {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    let recv = async {
        while let Some(reply) = replies.recv().await {
            let mut packet = Vec::new();
            put_socks_target(&mut packet, &reply.target)?;
            if SALT_SIZE + packet.len() + reply.data.len() + TAG_SIZE > MAX_DATAGRAM {
                continue;
            }
            packet.extend_from_slice(&reply.data);
            let salt = response_salt(&client, &inbound.salts)?;
            seal(&session_key(&client, &salt), 0, &mut packet)?;
            let mut wire = salt.to_vec();
            wire.extend_from_slice(&packet);
            socket.send_to(&wire, peer).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = send => result,
        result = recv => result,
        result = udp::relay_packets(packet_rx, reply_tx, &ctx) => result,
        _ = client.user.revoked() => Ok(()),
    }
}
