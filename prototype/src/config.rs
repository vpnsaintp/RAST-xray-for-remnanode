use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::backend::Backend;
use crate::go_router::{GoRouter, connect_abstract};
use anyhow::{Context, Result, bail, ensure};
use rustls::ServerConfig;
use rustls::crypto::{Identity, SelectedCredential};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::{
    ClientHello, ClientHelloVerifier, NoServerSessionStorage, RealityClientHello,
    RealityClientHelloProbe, ServerCredentialResolver, Tls13Tickets,
};
use rustls_aws_lc_rs::reality::{
    RealityServerVerifierConfig, default_x25519_tls13_reality_provider,
};
use rustls_aws_lc_rs::{DEFAULT_PROVIDER, DEFAULT_TLS12_PROVIDER, DEFAULT_TLS13_PROVIDER};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use uuid::Uuid;

use crate::routing::{Host, Outbound, Router, RoutingConfig, Target};
use crate::sniff::Sniffing;
use crate::state::{State, Traffic, User, Users, VISION};

pub struct Inbound {
    pub tag: String,
    pub address: SocketAddr,
    pub transport: Transport,
    pub users: Arc<Users>,
    pub socket_options: SocketOptions,
    pub sniffing: Sniffing,
}

pub enum Transport {
    Reality {
        tls: Arc<ServerConfig>,
        verifier: Arc<VerifyServerName>,
        fallback: Option<RealityTarget>,
        xhttp: Option<Arc<crate::xhttp::Settings>>,
        grpc: Option<Arc<crate::grpc::Settings>>,
    },
    Grpc(crate::grpc::Settings),
    Tls(Arc<ServerConfig>),
    WebSocket(crate::ws::Settings),
}

pub struct Config {
    pub inbounds: Vec<Inbound>,
    pub shadowsocks: Vec<crate::shadowsocks::Inbound>,
    pub api_socket: Option<String>,
    pub backend: Arc<Backend>,
    pub companion: Option<Child>,
    pub state: Arc<State>,
}

#[derive(Deserialize)]
struct LegacyConfig {
    listen: SocketAddr,
    targets: Vec<SocketAddr>,
    uuid: String,
    server_name: String,
    client_version: [u8; 3],
    short_id: String,
    private_key: String,
}

#[derive(Deserialize)]
struct Profile {
    inbounds: Vec<serde_json::Value>,
    outbounds: serde_json::Value,
    #[serde(default)]
    routing: serde_json::Value,
    #[serde(default)]
    dns: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VlessInbound {
    tag: String,
    port: u16,
    #[serde(default)]
    listen: Option<IpAddr>,
    settings: VlessSettings,
    stream_settings: StreamSettings,
    #[serde(default)]
    sniffing: Option<Sniffing>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessSettings {
    decryption: String,
    #[serde(default)]
    flow: String,
    clients: Vec<VlessClient>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessClient {
    id: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    level: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StreamSettings {
    network: String,
    #[serde(default)]
    security: String,
    reality_settings: Option<RealitySettings>,
    tls_settings: Option<InboundTlsSettings>,
    ws_settings: Option<crate::ws::Settings>,
    #[serde(alias = "splithttpSettings")]
    xhttp_settings: Option<crate::xhttp::Settings>,
    grpc_settings: Option<crate::grpc::Settings>,
    #[serde(default)]
    sockopt: SocketOptions,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InboundTlsSettings {
    certificates: Vec<InboundTlsCertificate>,
    #[serde(default)]
    min_version: String,
    #[serde(default)]
    max_version: String,
    #[serde(default)]
    alpn: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InboundTlsCertificate {
    certificate: Option<Vec<String>>,
    certificate_file: Option<PathBuf>,
    key: Option<Vec<String>>,
    key_file: Option<PathBuf>,
}

impl InboundTlsSettings {
    fn compile(mut self) -> Result<Arc<ServerConfig>> {
        let provider = match (self.min_version.as_str(), self.max_version.as_str()) {
            ("" | "1.2", "" | "1.3") => DEFAULT_PROVIDER,
            ("" | "1.2", "1.2") => DEFAULT_TLS12_PROVIDER,
            ("1.3", "" | "1.3") => DEFAULT_TLS13_PROVIDER,
            _ => bail!("unsupported inbound TLS version range"),
        };
        ensure!(
            self.certificates.len() == 1,
            "expected one inbound TLS certificate"
        );
        let certificate = self.certificates.pop().unwrap();
        let certificate_pem = tls_pem(certificate.certificate, certificate.certificate_file)?;
        let key_pem = tls_pem(certificate.key, certificate.key_file)?;
        let chain = CertificateDer::pem_slice_iter(&certificate_pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("invalid inbound TLS certificate PEM")?;
        let identity =
            Identity::from_cert_chain(chain).context("missing inbound TLS certificate")?;
        let key = PrivateKeyDer::from_pem_slice(&key_pem).context("invalid inbound TLS key PEM")?;
        let mut tls = ServerConfig::builder(Arc::new(provider))
            .with_no_client_auth()
            .with_single_cert(Arc::new(identity), key)
            .context("invalid inbound TLS credentials")?;
        tls.alpn_protocols = if self.alpn.is_empty() {
            vec![b"h2".as_slice().into(), b"http/1.1".as_slice().into()]
        } else {
            self.alpn
                .into_iter()
                .map(|protocol| protocol.into_bytes().into())
                .collect()
        };
        tls.send_tls13_tickets = Tls13Tickets { default: 0, max: 0 };
        tls.session_storage = Arc::new(NoServerSessionStorage {});
        Ok(Arc::new(tls))
    }
}

fn tls_pem(inline: Option<Vec<String>>, path: Option<PathBuf>) -> Result<Vec<u8>> {
    match (inline, path) {
        (Some(lines), None) => Ok(lines.join("\n").into_bytes()),
        (None, Some(path)) => std::fs::read(path).context("read inbound TLS PEM file"),
        _ => bail!("expected exactly one source for inbound TLS PEM"),
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SocketOptions {
    #[serde(default)]
    pub tcp_no_delay: bool,
    #[serde(default)]
    pub tcp_keep_alive_idle: u64,
    #[serde(default)]
    pub tcp_keep_alive_interval: u64,
    #[serde(default)]
    pub tcp_fast_open: bool,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    #[serde(default)]
    pub trusted_proxy_protocol_sources: Vec<ipnet::IpNet>,
    #[serde(default)]
    pub trusted_x_forwarded_for: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RealitySettings {
    #[serde(default)]
    show: bool,
    #[serde(default)]
    xver: u8,
    #[serde(alias = "dest", deserialize_with = "reality_target")]
    target: RealityTarget,
    private_key: String,
    server_names: Vec<String>,
    short_ids: Vec<String>,
    #[serde(default)]
    min_client_ver: String,
    #[serde(default)]
    max_client_ver: String,
    #[serde(default)]
    max_time_diff: u64,
}

pub enum RealityTarget {
    Address(SocketAddr),
    Domain(Target),
}

impl RealityTarget {
    fn points_to(&self, listener: SocketAddr) -> bool {
        match self {
            Self::Address(address) => {
                *address == listener
                    || (listener.ip().is_unspecified() && address.port() == listener.port())
            }
            Self::Domain(target) => {
                listener.ip().is_unspecified() && target.port == listener.port()
            }
        }
    }
}

fn reality_target<'de, D: serde::Deserializer<'de>>(input: D) -> Result<RealityTarget, D::Error> {
    let value = String::deserialize(input)?;
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() != 0 {
            return Ok(RealityTarget::Address(address));
        }
    } else if let Some((name, port)) = value.rsplit_once(':') {
        if let (Ok(name), Ok(port)) = (rustls::pki_types::DnsName::try_from(name), port.parse()) {
            if port != 0 {
                return Ok(RealityTarget::Domain(Target {
                    host: Host::Name(name.as_ref().to_owned()),
                    port,
                }));
            }
        }
    }
    Err(serde::de::Error::custom("invalid REALITY target address"))
}

#[derive(Debug)]
struct NoFallbackCredential;

impl ServerCredentialResolver for NoFallbackCredential {
    fn resolve(&self, _: &ClientHello<'_>) -> Result<SelectedCredential, rustls::Error> {
        Err(rustls::Error::NoSuitableCertificate)
    }
}

#[derive(Debug)]
pub struct VerifyServerName {
    names: Vec<String>,
    reality: Arc<dyn ClientHelloVerifier>,
}

impl VerifyServerName {
    fn matches(&self, name: Option<&str>) -> bool {
        name.is_some_and(|name| {
            self.names
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name))
        })
    }

    pub fn accepts(&self, probe: &RealityClientHelloProbe) -> Result<bool> {
        Ok(self.matches(probe.server_name()) && self.reality.verify_client_hello_probe(probe)?)
    }
}

impl ClientHelloVerifier for VerifyServerName {
    fn verify_client_hello(&self, hello: &RealityClientHello<'_>) -> Result<(), rustls::Error> {
        if !self.matches(hello.server_name().map(|name| name.as_ref())) {
            return Err(rustls::Error::General("unexpected REALITY SNI".into()));
        }
        self.reality.verify_client_hello(hello)
    }

    fn reality_auth_key(
        &self,
        hello: &RealityClientHello<'_>,
    ) -> Result<Option<[u8; 32]>, rustls::Error> {
        self.reality.reality_auth_key(hello)
    }

    fn hash_config(&self, hash: &mut dyn std::hash::Hasher) {
        for name in &self.names {
            hash.write(name.as_bytes());
            hash.write_u8(0);
        }
        self.reality.hash_config(hash);
    }
}

pub async fn load(argument: &str) -> Result<Config> {
    let bytes = if argument.starts_with('@') {
        tokio::time::timeout(Duration::from_secs(10), fetch(argument)).await??
    } else {
        std::fs::read(PathBuf::from(argument)).context("read config file")?
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).context("decode config JSON")?;
    if value.get("inbounds").is_some() {
        from_profile(value).await
    } else {
        from_legacy(serde_json::from_value(value).context("decode test config")?)
    }
}

async fn fetch(reference: &str) -> Result<Vec<u8>> {
    let (name, path) = reference[1..]
        .split_once(':')
        .context("invalid config socket reference")?;
    ensure!(
        !name.is_empty()
            && path.starts_with("/internal/get-config?")
            && !path.contains(['\r', '\n', ' ']),
        "invalid internal config path"
    );
    let mut stream = connect_abstract(name).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    const MAX_CONFIG: u64 = 64 * 1024 * 1024;
    let mut response = Vec::new();
    stream
        .take(MAX_CONFIG + 1)
        .read_to_end(&mut response)
        .await?;
    ensure!(
        response.len() as u64 <= MAX_CONFIG,
        "config response too large"
    );
    let head = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .context("invalid config HTTP response")?;
    let headers = std::str::from_utf8(&response[..head])?;
    ensure!(
        headers
            .lines()
            .next()
            .is_some_and(|line| line.split_ascii_whitespace().nth(1) == Some("200")),
        "Remnanode rejected config request"
    );
    ensure!(
        !headers.to_ascii_lowercase().contains("transfer-encoding:"),
        "unsupported config HTTP transfer encoding"
    );

    if let Some(length) = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
    {
        ensure!(
            response.len() - head - 4 == length.parse::<usize>()?,
            "incomplete config response"
        );
    }
    Ok(response.split_off(head + 4))
}

fn from_legacy(config: LegacyConfig) -> Result<Config> {
    ensure!(
        config.listen.ip().is_loopback()
            && !config.targets.is_empty()
            && config
                .targets
                .iter()
                .all(|target| target.ip().is_loopback()),
        "test addresses must be loopback"
    );
    let router = Router::new(
        RoutingConfig::default(),
        vec![Outbound {
            tag: "DIRECT".into(),
            protocol: "freedom".into(),
            settings: serde_json::Value::Null,
            stream: serde_json::Value::Null,
        }],
        Some(config.targets),
        None,
    )?;
    // The original isolated test fixture runs both flows with the same UUID.
    let id = Uuid::parse_str(&config.uuid)?;
    let users = Arc::new(RwLock::new(HashMap::from([(
        id,
        User::new("".into(), "")?,
    )])));
    let (tls, verifier) = reality_tls(
        &config.private_key,
        &[config.short_id],
        vec![config.server_name],
        config.client_version,
        [255; 3],
        Duration::from_secs(30),
    )?;
    Ok(assemble(
        vec![Inbound {
            tag: "test".into(),
            address: config.listen,
            transport: Transport::Reality {
                tls,
                verifier,
                fallback: None,
                xhttp: None,
                grpc: None,
            },
            users,
            socket_options: SocketOptions::default(),
            sniffing: Sniffing::default(),
        }],
        Vec::new(),
        None,
        Backend::Native(router),
        None,
    ))
}

async fn from_profile(value: serde_json::Value) -> Result<Config> {
    let companion_path = std::env::var_os("NIGHTVPN_ROUTE_CORE").map(PathBuf::from);
    let profile: Profile = serde_json::from_value(value.clone()).context("decode Xray profile")?;
    let mut inbounds = Vec::new();
    let mut shadowsocks = Vec::new();
    let mut api = None;
    for value in profile.inbounds {
        match value["protocol"].as_str() {
            Some("tunnel") if value["tag"] == "REMNAWAVE_API_INBOUND" => {
                ensure!(api.is_none(), "duplicate Remnanode API inbound");
                api = Some(
                    value["listen"]
                        .as_str()
                        .context("API socket missing")?
                        .to_owned(),
                );
            }
            Some("vless") => {
                let config: VlessInbound =
                    serde_json::from_value(value).context("unsupported VLESS inbound")?;
                ensure!(
                    config.settings.decryption == "none",
                    "unsupported VLESS decryption"
                );
                let default_flow = config.settings.flow;
                ensure!(
                    matches!(default_flow.as_str(), "" | VISION),
                    "unsupported inbound flow"
                );
                let address = SocketAddr::new(
                    config
                        .listen
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    config.port,
                );
                let mut stream = config.stream_settings;
                let transport = stream.transport(address)?;
                let mut users = HashMap::new();
                for client in config.settings.clients {
                    ensure!(client.level == 0, "unsupported client level");
                    let id = Uuid::parse_str(&client.id).context("invalid client UUID")?;
                    let flow = if client.flow.is_empty() {
                        &default_flow
                    } else {
                        &client.flow
                    };
                    ensure!(
                        !matches!(
                            transport,
                            Transport::WebSocket(_)
                                | Transport::Grpc(_)
                                | Transport::Reality { xhttp: Some(_), .. }
                                | Transport::Reality { grpc: Some(_), .. }
                        ) || flow.is_empty(),
                        "Vision requires a TLS or REALITY TCP inbound"
                    );
                    ensure!(
                        users.insert(id, User::new(client.email, flow)?).is_none(),
                        "duplicate client UUID"
                    );
                }
                ensure!(
                    config.port != 0
                        && !inbounds
                            .iter()
                            .any(|old: &Inbound| old.tag == config.tag || old.address == address),
                    "duplicate or invalid inbound"
                );
                inbounds.push(Inbound {
                    tag: config.tag,
                    address,
                    transport,
                    users: Arc::new(RwLock::new(users)),
                    socket_options: stream.sockopt,
                    sniffing: config.sniffing.unwrap_or_default(),
                });
            }
            Some("shadowsocks") => shadowsocks.push(crate::shadowsocks::Inbound::parse(value)?),
            _ => bail!("unsupported inbound protocol"),
        }
    }
    ensure!(
        !inbounds.is_empty() || !shadowsocks.is_empty(),
        "no proxy inbounds"
    );
    let mut tags = std::collections::HashSet::new();
    for tag in inbounds
        .iter()
        .map(|inbound| &inbound.tag)
        .chain(shadowsocks.iter().map(|inbound| &inbound.tag))
    {
        ensure!(tags.insert(tag), "duplicate inbound tag");
    }
    if let Some(path) = companion_path {
        ensure!(
            shadowsocks.is_empty(),
            "Shadowsocks requires native routing"
        );
        let (backend, child) = GoRouter::start(&path, value).await?;
        Ok(assemble(
            inbounds,
            shadowsocks,
            api,
            Backend::Go(backend),
            Some(child),
        ))
    } else {
        let routing = if profile.routing.is_null() {
            RoutingConfig::default()
        } else {
            serde_json::from_value(profile.routing).context("unsupported native routing rule")?
        };
        let outbounds = serde_json::from_value(profile.outbounds)?;
        let dns = profile
            .dns
            .map(serde_json::from_value)
            .transpose()
            .context("unsupported native DNS settings")?;
        let router = Router::new(routing, outbounds, None, dns)?;
        Ok(assemble(
            inbounds,
            shadowsocks,
            api,
            Backend::Native(router),
            None,
        ))
    }
}

impl StreamSettings {
    fn transport(&mut self, address: SocketAddr) -> Result<Transport> {
        match (self.network.as_str(), self.security.as_str()) {
            ("ws", "" | "none") => {
                ensure!(
                    self.reality_settings.is_none()
                        && self.tls_settings.is_none()
                        && self.grpc_settings.is_none()
                        && self.xhttp_settings.is_none(),
                    "unexpected security settings on a WebSocket inbound"
                );
                let settings = self.ws_settings.take().context("missing wsSettings")?;
                ensure!(
                    settings.path.starts_with('/'),
                    "WebSocket path must start with '/'"
                );
                self.sockopt.accept_proxy_protocol |= settings.accept_proxy_protocol;
                ensure!(
                    !self.sockopt.accept_proxy_protocol || address.ip().is_loopback(),
                    "PROXY protocol requires a loopback WebSocket listener"
                );
                Ok(Transport::WebSocket(settings))
            }
            ("grpc", "" | "none") => {
                ensure!(
                    address.ip().is_loopback()
                        && self.reality_settings.is_none()
                        && self.tls_settings.is_none()
                        && self.ws_settings.is_none()
                        && self.xhttp_settings.is_none()
                        && !self.sockopt.accept_proxy_protocol,
                    "cleartext gRPC requires a loopback listener behind a TLS reverse proxy"
                );
                let settings = self.grpc_settings.take().context("missing grpcSettings")?;
                settings.validate()?;
                Ok(Transport::Grpc(settings))
            }
            (network @ ("raw" | "tcp" | "xhttp" | "splithttp" | "grpc"), "reality") => {
                ensure!(
                    self.ws_settings.is_none() && self.tls_settings.is_none(),
                    "unexpected transport settings on REALITY inbound"
                );
                ensure!(
                    !self.sockopt.accept_proxy_protocol
                        || address.ip().is_loopback()
                        || !self.sockopt.trusted_proxy_protocol_sources.is_empty(),
                    "public REALITY PROXY protocol requires trustedProxyProtocolSources"
                );
                let xhttp = if matches!(network, "xhttp" | "splithttp") {
                    let mut settings = self
                        .xhttp_settings
                        .take()
                        .context("missing xhttpSettings")?;
                    settings.validate()?;
                    Some(Arc::new(settings))
                } else {
                    ensure!(
                        self.xhttp_settings.is_none(),
                        "unexpected XHTTP settings on this inbound"
                    );
                    None
                };
                let grpc = if network == "grpc" {
                    let settings = self.grpc_settings.take().context("missing grpcSettings")?;
                    settings.validate()?;
                    Some(Arc::new(settings))
                } else {
                    ensure!(
                        self.grpc_settings.is_none(),
                        "unexpected gRPC settings on this inbound"
                    );
                    None
                };
                let reality = self
                    .reality_settings
                    .take()
                    .context("missing realitySettings")?;
                ensure!(
                    !reality.show && reality.xver == 0,
                    "unsupported REALITY show or proxy protocol"
                );
                ensure!(
                    !reality.target.points_to(address),
                    "REALITY fallback points to its own listener"
                );
                let (mut tls, verifier) = reality_tls(
                    &reality.private_key,
                    &reality.short_ids,
                    reality.server_names,
                    version(&reality.min_client_ver, [0; 3])?,
                    version(&reality.max_client_ver, [255; 3])?,
                    Duration::from_millis(reality.max_time_diff),
                )?;
                if xhttp.is_some() || grpc.is_some() {
                    Arc::make_mut(&mut tls).alpn_protocols = vec![b"h2".as_slice().into()];
                }
                Ok(Transport::Reality {
                    tls,
                    verifier,
                    fallback: Some(reality.target),
                    xhttp,
                    grpc,
                })
            }
            ("raw" | "tcp", "tls") => {
                ensure!(
                    self.reality_settings.is_none()
                        && self.ws_settings.is_none()
                        && self.xhttp_settings.is_none()
                        && self.grpc_settings.is_none()
                        && !self.sockopt.accept_proxy_protocol,
                    "unexpected transport settings or PROXY protocol on TLS inbound"
                );
                let tls = self.tls_settings.take().context("missing tlsSettings")?;
                Ok(Transport::Tls(tls.compile()?))
            }
            _ => bail!("unsupported VLESS inbound transport"),
        }
    }
}

fn version(value: &str, default: [u8; 3]) -> Result<[u8; 3]> {
    if value.is_empty() {
        return Ok(default);
    }
    if value == "0" {
        return Ok([0; 3]);
    }
    let bytes = value
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid REALITY client version"))
}

fn reality_tls(
    private_key: &str,
    short_ids: &[String],
    names: Vec<String>,
    minimum: [u8; 3],
    maximum: [u8; 3],
    skew: Duration,
) -> Result<(Arc<ServerConfig>, Arc<VerifyServerName>)> {
    ensure!(minimum <= maximum, "invalid REALITY version range");
    ensure!(
        !short_ids.is_empty() && !names.is_empty(),
        "REALITY short IDs and server names required"
    );
    let parse_id = |id: &str| -> Result<Vec<u8>> {
        ensure!(
            id.len() <= 16 && id.len() % 2 == 0 && id.is_ascii(),
            "invalid REALITY short ID"
        );
        (0..id.len())
            .step_by(2)
            .map(|index| Ok(u8::from_str_radix(&id[index..index + 2], 16)?))
            .collect()
    };
    let ids = short_ids
        .iter()
        .map(|id| parse_id(id))
        .collect::<Result<Vec<_>>>()?;
    let mut tls = ServerConfig::builder(Arc::new(default_x25519_tls13_reality_provider()))
        .with_no_client_auth()
        .with_server_credential_resolver(Arc::new(NoFallbackCredential))?;
    let reality =
        RealityServerVerifierConfig::from_xray_fields(minimum, &short_ids[0], private_key)?
            .with_short_ids(ids)
            .with_client_version_range(minimum, maximum)
            .with_max_time_skew(skew);
    reality.install_into(&mut tls)?;
    let verifier = Arc::new(VerifyServerName {
        names,
        reality: reality.build_verifier()?,
    });
    tls.dangerous()
        .set_reality_client_hello_verifier(Some(verifier.clone()));
    Ok((Arc::new(tls), verifier))
}

fn assemble(
    inbounds: Vec<Inbound>,
    shadowsocks: Vec<crate::shadowsocks::Inbound>,
    api_socket: Option<String>,
    backend: Backend,
    companion: Option<Child>,
) -> Config {
    let state = State {
        inbounds: inbounds
            .iter()
            .map(|inbound| (inbound.tag.clone(), inbound.users.clone()))
            .collect(),
        shadowsocks: shadowsocks
            .iter()
            .map(|inbound| (inbound.tag.clone(), inbound.users.clone()))
            .collect(),
        stats: Arc::new(Traffic::default()),
        started: Instant::now(),
    };
    Config {
        inbounds,
        shadowsocks,
        api_socket,
        backend: Arc::new(backend),
        companion,
        state: Arc::new(state),
    }
}
