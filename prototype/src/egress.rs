use std::hash::Hasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use aws_lc_rs::digest::{SHA256, digest};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::client::ClientHelloProfile;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerIdentity, ServerVerifier, SignatureVerificationInput,
    VerifiedIdentity,
};
use rustls::crypto::{
    Identity, SignatureScheme, WebPkiSupportedAlgorithms, verify_tls12_signature,
    verify_tls13_signature,
};
use rustls::error::CertificateError;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientSide};
use serde::Deserialize;
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use uuid::Uuid;

use crate::backend::Tunnel;
use crate::routing::{Host, Router, Target, validate_domain};
use crate::tls_stream::TlsStream;
use crate::vless::{VISION_FLOW, put_target};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outbound {
    pub tag: String,
    pub protocol: String,
    #[serde(default)]
    pub settings: serde_json::Value,
    #[serde(rename = "streamSettings", default)]
    pub stream: serde_json::Value,
    #[serde(rename = "sendThrough", default)]
    pub send_through: Option<IpAddr>,
}

#[derive(Clone)]
pub enum Egress {
    Direct(Direct),
    Block,
    Http(HttpProxy),
    Socks(Endpoint),
    Vless(VlessProxy),
}

impl Egress {
    pub fn compile(outbound: Outbound) -> Result<Self> {
        let settings = outbound.settings;
        let stream = outbound.stream;
        let empty = |value: &serde_json::Value| {
            value.is_null() || value.as_object().is_some_and(|v| v.is_empty())
        };
        ensure!(
            matches!(outbound.protocol.as_str(), "vless" | "freedom") || empty(&stream),
            "unsupported outbound stream settings"
        );
        ensure!(
            outbound.send_through.is_none() || outbound.protocol == "freedom",
            "sendThrough is supported only for freedom outbound"
        );
        Ok(match outbound.protocol.as_str() {
            "freedom" => Self::Direct(Direct::compile(settings, stream, outbound.send_through)?),
            "blackhole" if empty(&settings) => Self::Block,
            "http" => {
                let proxy: HttpSettings = serde_json::from_value(settings)?;
                Self::Http(only(proxy.servers, "HTTP server")?)
            }
            "socks" => Self::Socks(if settings.get("servers").is_some() {
                only(
                    serde_json::from_value::<SocksSettings>(settings)?.servers,
                    "SOCKS server",
                )?
            } else {
                serde_json::from_value(settings)?
            }),
            "vless" => Self::Vless(VlessProxy::compile(settings, stream)?),
            _ => bail!("unsupported native outbound {}", outbound.protocol),
        })
    }
}
fn only<T>(mut items: Vec<T>, description: &str) -> Result<T> {
    ensure!(items.len() == 1, "expected one {description}");
    Ok(items.pop().unwrap())
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Direct {
    #[serde(default, alias = "domainStrategy")]
    pub target_strategy: String,
    #[serde(default)]
    pub final_rules: Vec<FinalRule>,
    #[serde(skip)]
    sockopt: OutboundSockopt,
    #[serde(skip)]
    send_through: Option<IpAddr>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DirectStream {
    #[serde(default)]
    network: String,
    #[serde(default)]
    security: String,
    #[serde(default)]
    sockopt: OutboundSockopt,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalRule {
    pub action: String,
    pub ip: Vec<ipnet::IpNet>,
    pub port: String,
}

impl Direct {
    fn compile(
        settings: serde_json::Value,
        stream: serde_json::Value,
        send_through: Option<IpAddr>,
    ) -> Result<Self> {
        let mut direct: Self = if settings.is_null() {
            Self::default()
        } else {
            serde_json::from_value(settings)?
        };
        let stream: DirectStream = if stream.is_null() {
            DirectStream::default()
        } else {
            serde_json::from_value(stream)?
        };
        ensure!(
            matches!(stream.network.as_str(), "" | "raw" | "tcp")
                && matches!(stream.security.as_str(), "" | "none"),
            "unsupported freedom transport"
        );
        ensure!(
            matches!(
                direct.target_strategy.as_str(),
                "" | "AsIs" | "ForceIPv4" | "UseIPv4"
            ),
            "unsupported freedom strategy"
        );
        stream.sockopt.validate()?;
        direct.sockopt = stream.sockopt;
        ensure!(
            send_through.is_none_or(|ip| !ip.is_unspecified()),
            "sendThrough must name a specific source IP"
        );
        direct.send_through = send_through;
        Ok(direct)
    }

    pub async fn addresses(
        &self,
        router: &Router,
        target: &Target,
        legacy_fixture: bool,
    ) -> Result<Vec<SocketAddr>> {
        let force_v4 = matches!(self.target_strategy.as_str(), "ForceIPv4" | "UseIPv4")
            || self.sockopt.force_ipv4();
        let mut addresses = router.resolve(target, force_v4, force_v4).await?;
        addresses.retain(|address| {
            let matched = self.final_rules.iter().find(|rule| {
                rule.ip
                    .iter()
                    .any(|network| network.contains(&address.ip()))
                    && rule.port.split(',').any(|port| {
                        let (first, last) = port.split_once('-').unwrap_or((port, port));
                        first
                            .parse::<u16>()
                            .ok()
                            .zip(last.parse::<u16>().ok())
                            .is_some_and(|(first, last)| (first..=last).contains(&address.port()))
                    })
            });
            match matched {
                Some(rule) => rule.action == "allow",
                None => legacy_fixture || !private_address(address.ip()),
            }
        });
        ensure!(!addresses.is_empty(), "destination not permitted");
        Ok(addresses)
    }

    pub async fn connect(&self, addresses: &[SocketAddr]) -> Result<TcpStream> {
        let socket = if let Some(source) = self.send_through {
            let mut last_error = None;
            let mut connected = None;
            for address in addresses
                .iter()
                .copied()
                .filter(|addr| addr.is_ipv4() == source.is_ipv4())
            {
                let tcp = if source.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                tcp.bind(SocketAddr::new(source, 0))?;
                match tcp.connect(address).await {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            connected.ok_or_else(|| {
                last_error.map(anyhow::Error::from).unwrap_or_else(|| {
                    anyhow::anyhow!("no destination matching sendThrough address family")
                })
            })?
        } else {
            TcpStream::connect(addresses).await?
        };
        self.sockopt.apply_tcp(&socket)?;
        Ok(socket)
    }

    pub async fn udp_socket(&self, address: SocketAddr) -> Result<UdpSocket> {
        let source = match self.send_through {
            Some(source) if source.is_ipv4() != address.is_ipv4() => {
                bail!("UDP destination does not match sendThrough address family")
            }
            Some(source) => source,
            None if address.is_ipv4() => std::net::Ipv4Addr::UNSPECIFIED.into(),
            None => std::net::Ipv6Addr::UNSPECIFIED.into(),
        };
        let socket = UdpSocket::bind(SocketAddr::new(source, 0)).await?;
        socket.connect(address).await?;
        Ok(socket)
    }
}
fn private_address(address: IpAddr) -> bool {
    // Xray's default Freedom policy for VLESS inbounds.
    static PRIVATE: LazyLock<Vec<ipnet::IpNet>> = LazyLock::new(|| {
        [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/3",
            "::/127",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        ]
        .iter()
        .map(|value| value.parse().expect("fixed CIDR"))
        .collect()
    });
    let ip = match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    };
    PRIVATE.iter().any(|range| range.contains(&ip))
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    address: String,
    port: u16,
}

impl Endpoint {
    fn target(&self) -> Target {
        let host = self
            .address
            .parse()
            .map_or_else(|_| Host::Name(self.address.clone()), Host::Ip);
        Target {
            host,
            port: self.port,
        }
    }

    pub async fn socks_request(&self, command: u8, target: &Target) -> Result<(TcpStream, Target)> {
        let mut stream = TcpStream::connect((self.address.as_str(), self.port)).await?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut hello = [0; 2];
        stream.read_exact(&mut hello).await?;
        ensure!(hello == [5, 0], "SOCKS proxy rejected authentication");
        let mut request = vec![5, command, 0];
        put_socks_target(&mut request, target)?;
        stream.write_all(&request).await?;
        let mut reply = [0; 3];
        stream.read_exact(&mut reply).await?;
        ensure!(reply == [5, 0, 0], "SOCKS proxy rejected the request");
        let mut bound = read_socks_target(&mut stream).await?;
        if matches!(bound.host, Host::Ip(ip) if ip.is_unspecified()) {
            bound.host = Host::Ip(stream.peer_addr()?.ip());
        }
        Ok((stream, bound))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksSettings {
    servers: Vec<Endpoint>,
}

pub fn put_socks_target(buf: &mut Vec<u8>, target: &Target) -> Result<()> {
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            buf.push(1);
            buf.extend(ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            buf.push(4);
            buf.extend(ip.octets());
        }
        Host::Name(name) => {
            buf.extend([3, u8::try_from(name.len())?]);
            buf.extend(name.as_bytes());
        }
    }
    buf.extend(target.port.to_be_bytes());
    Ok(())
}

pub async fn read_socks_target(input: &mut (impl AsyncRead + Unpin)) -> Result<Target> {
    let host = match input.read_u8().await? {
        1 => Host::Ip(IpAddr::from(input.read_u32().await?.to_be_bytes())),
        4 => Host::Ip(IpAddr::from(input.read_u128().await?.to_be_bytes())),
        3 => {
            let mut bytes = vec![0; usize::from(input.read_u8().await?)];
            input.read_exact(&mut bytes).await?;
            let name = std::str::from_utf8(&bytes)?;
            validate_domain(name)?;
            Host::Name(name.to_owned())
        }
        _ => bail!("invalid SOCKS address"),
    };
    Ok(Target {
        host,
        port: input.read_u16().await?,
    })
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProxy {
    address: String,
    port: u16,
    #[serde(default)]
    users: Vec<HttpUser>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpUser {
    user: String,
    pass: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpSettings {
    servers: Vec<HttpProxy>,
}

impl HttpProxy {
    pub async fn connect(&self, target: &Target) -> Result<TcpStream> {
        if let Host::Name(name) = &target.host {
            validate_domain(name)?;
        }
        let authority = target.authority();
        let mut stream = TcpStream::connect((self.address.as_str(), self.port)).await?;
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(user) = self.users.first() {
            let credentials = STANDARD.encode(format!("{}:{}", user.user, user.pass));
            request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
        }
        stream.write_all((request + "\r\n").as_bytes()).await?;
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            ensure!(headers.len() < 16 * 1024, "oversized HTTP CONNECT response");
            headers.push(stream.read_u8().await?);
        }
        let status = std::str::from_utf8(&headers)?
            .lines()
            .next()
            .and_then(|line| line.split_ascii_whitespace().nth(1));
        ensure!(status == Some("200"), "HTTP proxy rejected CONNECT");
        Ok(stream)
    }
}

#[derive(Clone)]
pub struct VlessProxy {
    endpoint: Endpoint,
    pub id: Uuid,
    pub vision: bool,
    security: VlessSecurity,
    sockopt: OutboundSockopt,
}

#[derive(Clone)]
enum VlessSecurity {
    Plain,
    Tls {
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        reality: bool,
    },
}

pub enum VlessStream {
    Plain(TcpStream),
    Tls(TlsStream<ClientSide>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessSettings {
    vnext: Vec<VlessServer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessServer {
    address: String,
    port: u16,
    users: Vec<VlessUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessUser {
    id: UuidValue,
    encryption: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    level: u32,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct UuidValue(String);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CascadeStream {
    network: String,
    #[serde(default)]
    security: String,
    tls_settings: Option<CascadeTls>,
    reality_settings: Option<CascadeReality>,
    #[serde(default)]
    sockopt: OutboundSockopt,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CascadeTls {
    #[serde(default)]
    server_name: Option<String>,
    pinned_peer_cert_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CascadeReality {
    server_name: String,
    #[serde(alias = "password")]
    public_key: String,
    #[serde(default)]
    short_id: String,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    spider_x: String,
    #[serde(default)]
    show: bool,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OutboundSockopt {
    #[serde(default)]
    tcp_no_delay: bool,
    // Keep ordinary TCP connect and allow the field for Xray config compatibility.
    #[serde(default, rename = "tcpFastOpen")]
    _tcp_fast_open: bool,
    #[serde(default)]
    tcp_keep_alive_idle: u64,
    #[serde(default)]
    tcp_keep_alive_interval: u64,
    #[serde(default)]
    domain_strategy: String,
}

impl OutboundSockopt {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.domain_strategy.as_str(), "" | "AsIs" | "ForceIPv4"),
            "unsupported outbound socket address policy"
        );
        Ok(())
    }

    fn force_ipv4(&self) -> bool {
        self.domain_strategy == "ForceIPv4"
    }

    fn apply_tcp(&self, socket: &TcpStream) -> Result<()> {
        socket.set_nodelay(self.tcp_no_delay)?;
        if self.tcp_keep_alive_idle != 0 || self.tcp_keep_alive_interval != 0 {
            let mut settings = TcpKeepalive::new();
            if self.tcp_keep_alive_idle != 0 {
                settings = settings.with_time(Duration::from_secs(self.tcp_keep_alive_idle));
            }
            if self.tcp_keep_alive_interval != 0 {
                settings =
                    settings.with_interval(Duration::from_secs(self.tcp_keep_alive_interval));
            }
            SockRef::from(socket).set_tcp_keepalive(&settings)?;
        }
        Ok(())
    }
}

impl VlessProxy {
    fn compile(settings: serde_json::Value, stream: serde_json::Value) -> Result<Self> {
        let settings: VlessSettings = serde_json::from_value(settings)?;
        let stream: CascadeStream = serde_json::from_value(stream)?;
        ensure!(
            matches!(stream.network.as_str(), "raw" | "tcp"),
            "unsupported VLESS cascade transport"
        );
        stream.sockopt.validate()?;
        let server = only(settings.vnext, "VLESS server")?;
        let user = only(server.users, "VLESS account")?;
        ensure!(
            user.encryption == "none"
                && user.level == 0
                && matches!(user.flow.as_str(), "" | "xtls-rprx-vision"),
            "unsupported VLESS cascade account"
        );
        let vision = !user.flow.is_empty();
        let security = match stream.security.as_str() {
            "" | "none" => {
                ensure!(
                    stream.tls_settings.is_none() && stream.reality_settings.is_none(),
                    "security settings on a plain VLESS cascade"
                );
                ensure!(
                    !vision,
                    "Vision requires TLS or REALITY on the VLESS cascade"
                );
                VlessSecurity::Plain
            }
            "tls" => {
                ensure!(
                    stream.reality_settings.is_none(),
                    "REALITY settings on a TLS cascade"
                );
                stream
                    .tls_settings
                    .context("missing TLS settings for VLESS cascade")?
                    .compile(&server.address)?
            }
            "reality" => {
                ensure!(
                    stream.tls_settings.is_none(),
                    "TLS settings on a REALITY cascade"
                );
                stream
                    .reality_settings
                    .context("missing REALITY settings for VLESS cascade")?
                    .compile()?
            }
            _ => bail!("unsupported VLESS cascade security"),
        };
        Ok(Self {
            endpoint: Endpoint {
                address: server.address,
                port: server.port,
            },
            id: Uuid::parse_str(&user.id.0)?,
            vision,
            security,
            sockopt: stream.sockopt,
        })
    }

    pub async fn open(&self, router: &Router, target: &Target, command: u8) -> Result<VlessStream> {
        let force_v4 = self.sockopt.force_ipv4();
        let addresses = router
            .resolve(&self.endpoint.target(), force_v4, force_v4)
            .await?;
        let socket = TcpStream::connect(addresses.as_slice()).await?;
        self.sockopt.apply_tcp(&socket)?;
        let mut stream = match &self.security {
            VlessSecurity::Plain => VlessStream::Plain(socket),
            VlessSecurity::Tls { config, name, .. } => {
                VlessStream::Tls(TlsStream::connect(socket, config.clone(), name.clone()).await?)
            }
        };
        let mut request = vec![0];
        request.extend(self.id.as_bytes());
        if self.vision {
            request.push(VISION_FLOW.len() as u8);
            request.extend_from_slice(VISION_FLOW);
        } else {
            request.push(0);
        }
        request.push(command);
        if command != 3 {
            put_target(&mut request, target);
        }
        let writer: &mut dyn Tunnel = match &mut stream {
            VlessStream::Plain(socket) => socket,
            VlessStream::Tls(tls) => tls,
        };
        writer.write_all(&request).await?;
        writer.flush().await?;
        Ok(stream)
    }
}

impl CascadeTls {
    fn compile(self, address: &str) -> Result<VlessSecurity> {
        let name = ServerName::try_from(self.server_name.unwrap_or_else(|| address.to_owned()))?;
        let pins = self
            .pinned_peer_cert_sha256
            .split(',')
            .map(|text| {
                ensure!(
                    text.len() == 64 && text.is_ascii(),
                    "invalid pinned certificate digest"
                );
                let mut pin = [0; 32];
                for (index, byte) in pin.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
                }
                Ok(pin)
            })
            .collect::<Result<Vec<_>>>()?;
        let provider = rustls_aws_lc_rs::DEFAULT_PROVIDER;
        let algorithms = provider.signature_verification_algorithms;
        let mut tls = ClientConfig::builder(Arc::new(provider))
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pins { pins, algorithms }))
            .with_no_client_auth()?;
        tls.alpn_protocols = vec![b"h2".as_slice().into(), b"http/1.1".as_slice().into()];
        Ok(VlessSecurity::Tls {
            config: Arc::new(tls),
            name,
            reality: false,
        })
    }
}

impl CascadeReality {
    fn compile(self) -> Result<VlessSecurity> {
        ensure!(
            self.fingerprint == "firefox",
            "unsupported REALITY fingerprint: expected firefox"
        );
        ensure!(
            matches!(self.spider_x.as_str(), "" | "/") && !self.show,
            "unsupported REALITY debug or spider settings"
        );
        validate_domain(&self.server_name)?;
        let name = ServerName::try_from(self.server_name)?;
        let version = [
            env!("CARGO_PKG_VERSION_MAJOR").parse()?,
            env!("CARGO_PKG_VERSION_MINOR").parse()?,
            env!("CARGO_PKG_VERSION_PATCH").parse()?,
        ];
        let mut config = rustls_aws_lc_rs::reality::RealitySessionIdConfig::from_xray_fields(
            version,
            &self.short_id,
            &self.public_key,
        )?
        .build_browser_client_config(
            ClientHelloProfile::Firefox148,
            rustls::RootCertStore::empty(),
        )?;
        config.alpn_protocols = vec![b"h2".as_slice().into(), b"http/1.1".as_slice().into()];
        Ok(VlessSecurity::Tls {
            config: Arc::new(config),
            name,
            reality: true,
        })
    }
}

#[derive(Debug)]
struct Pins {
    pins: Vec<[u8; 32]>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerVerifier for Pins {
    fn verify_identity<'a>(
        &self,
        server: &ServerIdentity<'a, '_>,
    ) -> Result<VerifiedIdentity<'a>, rustls::Error> {
        if let Identity::X509(cert) = server.identity {
            let hash = digest(&SHA256, cert.end_entity.as_ref());
            if self.pins.iter().any(|pin| hash.as_ref() == pin) {
                return Ok(VerifiedIdentity::assertion(server.identity.clone()));
            }
        }
        Err(CertificateError::ApplicationVerificationFailure.into())
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(input, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(input, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
    fn request_ocsp_response(&self) -> bool {
        false
    }
    fn hash_config(&self, hasher: &mut dyn Hasher) {
        for pin in &self.pins {
            hasher.write(pin);
        }
    }
}

#[cfg(test)]
mod send_through_tests {
    use serde_json::json;

    use super::*;
    use tokio::net::{TcpListener, UdpSocket};

    fn direct(source: &str) -> Direct {
        Direct::compile(
            serde_json::Value::Null,
            serde_json::Value::Null,
            Some(source.parse().unwrap()),
        )
        .unwrap()
    }

    fn vless_reality(fingerprint: &str, key_field: &str) -> Result<VlessProxy> {
        let mut reality = json!({
            "serverName": "example.com",
            "shortId": "0102030405060708",
            "fingerprint": fingerprint,
            "spiderX": "/"
        });
        reality[key_field] = json!("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI");
        VlessProxy::compile(
            json!({"vnext": [{
                "address": "192.0.2.1",
                "port": 443,
                "users": [{
                    "id": "ff207bb7-09ae-41ee-9a93-1da42158174c",
                    "encryption": "none",
                    "flow": "xtls-rprx-vision"
                }]
            }]}),
            json!({
                "network": "tcp",
                "security": "reality",
                "realitySettings": reality
            }),
        )
    }

    #[test]
    fn accepts_remnawave_vless_reality_outbound_with_firefox() {
        for key_field in ["publicKey", "password"] {
            let outbound = vless_reality("firefox", key_field).unwrap();
            assert!(outbound.vision);
            let VlessSecurity::Tls {
                config, reality, ..
            } = outbound.security
            else {
                panic!("expected REALITY TLS security");
            };
            assert!(reality);
            assert_eq!(config.client_hello_profile, ClientHelloProfile::Firefox148);
        }
    }

    #[test]
    fn rejects_non_firefox_or_mismatched_reality_settings() {
        assert!(vless_reality("chrome", "publicKey").is_err());
        assert!(
            VlessProxy::compile(
                json!({"vnext": [{
                    "address": "192.0.2.1",
                    "port": 443,
                    "users": [{
                        "id": "ff207bb7-09ae-41ee-9a93-1da42158174c",
                        "encryption": "none"
                    }]
                }]}),
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "realitySettings": {
                        "serverName": "example.com",
                        "publicKey": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
                        "fingerprint": "firefox"
                    }
                })
            )
            .is_err()
        );
    }

    #[test]
    fn parses_remnawave_freedom_use_ipv4() {
        let outbound: Outbound = serde_json::from_str(
            r#"{"tag":"DIRECT","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}"#,
        )
        .unwrap();
        let Egress::Direct(direct) = Egress::compile(outbound).unwrap() else {
            panic!("expected freedom outbound");
        };
        assert_eq!(direct.target_strategy, "UseIPv4");
    }

    #[tokio::test]
    async fn tcp_uses_requested_source_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = direct("127.0.0.2").connect(&[address]).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(
            client.local_addr().unwrap().ip(),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(peer.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn tcp_never_falls_back_when_source_is_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        assert!(direct("192.0.2.254").connect(&[address]).await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn udp_uses_requested_source_address() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = direct("127.0.0.2")
            .udp_socket(listener.local_addr().unwrap())
            .await
            .unwrap();
        client.send(b"test").await.unwrap();
        let mut bytes = [0; 4];
        let (_, peer) = listener.recv_from(&mut bytes).await.unwrap();
        assert_eq!(peer.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(&bytes, b"test");
    }

    #[tokio::test]
    async fn udp_never_falls_back_when_source_is_unavailable() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            direct("192.0.2.254")
                .udp_socket(listener.local_addr().unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn tcp_never_falls_back_to_other_address_family() {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        assert!(
            direct("127.0.0.2")
                .connect(&[listener.local_addr().unwrap()])
                .await
                .is_err()
        );
    }

    #[test]
    fn parses_send_through_from_xray_outbound() {
        let outbound: Outbound = serde_json::from_str(
            r#"{"tag":"DIRECT","protocol":"freedom","sendThrough":"127.0.0.2"}"#,
        )
        .unwrap();
        assert!(matches!(
            Egress::compile(outbound).unwrap(),
            Egress::Direct(Direct {
                send_through: Some(IpAddr::V4(_)),
                ..
            })
        ));
    }

    #[test]
    fn rejects_send_through_on_unimplemented_outbound() {
        let outbound: Outbound = serde_json::from_str(
            r#"{"tag":"PROXY","protocol":"http","sendThrough":"127.0.0.2","settings":{"servers":[{"address":"127.0.0.1","port":8080}]}}"#,
        )
        .unwrap();
        assert!(Egress::compile(outbound).is_err());
    }

    #[test]
    fn rejects_unspecified_source_instead_of_falling_back() {
        assert!(
            Direct::compile(
                serde_json::Value::Null,
                serde_json::Value::Null,
                Some("0.0.0.0".parse().unwrap())
            )
            .is_err()
        );
    }
}
