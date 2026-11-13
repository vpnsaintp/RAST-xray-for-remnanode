use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;

use crate::geodata::Geodata;
use crate::routing::Domains;
use crate::tls_stream::TlsStream;

const CACHE_LIMIT: usize = 4096;
const QUERY_TIMEOUT: Duration = Duration::from_millis(1400);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    servers: Vec<ServerConfig>,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    disable_cache: bool,
    #[serde(default)]
    query_strategy: Strategy,
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ServerConfig {
    Address(String),
    WithDomains {
        address: String,
        port: Option<u16>,
        #[serde(default)]
        domains: Vec<String>,
    },
}

#[derive(Default, Clone, Copy, Deserialize)]
enum Strategy {
    #[default]
    UseIP,
    UseIPv4,
    UseIPv6,
}

enum ServerAddress {
    System,
    Udp(SocketAddr),
    Tls(TlsUpstream),
}

struct TlsUpstream {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
}

impl TlsUpstream {
    fn parse(address: &str, port: Option<u16>) -> Result<Self> {
        let address = address.strip_suffix('/').unwrap_or(address);
        let (host, explicit_port) = if let Some(bracketed) = address.strip_prefix('[') {
            let (host, suffix) = bracketed
                .split_once(']')
                .context("invalid DoT IPv6 endpoint")?;
            host.parse::<std::net::Ipv6Addr>()
                .context("invalid DoT IPv6 address")?;
            let port = if suffix.is_empty() {
                None
            } else {
                Some(
                    suffix
                        .strip_prefix(':')
                        .context("invalid DoT endpoint suffix")?,
                )
            };
            (host, port)
        } else if address.parse::<IpAddr>().is_ok() {
            (address, None)
        } else {
            address
                .rsplit_once(':')
                .map_or((address, None), |(host, port)| (host, Some(port)))
        };
        let explicit_port = explicit_port
            .map(|value| value.parse::<u16>().context("invalid DoT port"))
            .transpose()?;
        ensure!(
            port.zip(explicit_port)
                .is_none_or(|(left, right)| left == right),
            "conflicting DoT ports"
        );
        let port = explicit_port.or(port).unwrap_or(853);
        ensure!(port != 0, "invalid DoT port");
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let server_name = ServerName::try_from(host.clone()).context("invalid DoT server name")?;
        Ok(Self {
            host,
            port,
            server_name,
        })
    }
}

fn system_tls_config() -> Result<Arc<ClientConfig>> {
    let bundle = if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
        std::fs::read(path).context("read configured system CA bundle")?
    } else {
        [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        ]
        .into_iter()
        .find_map(|path| std::fs::read(path).ok())
        .context("system CA bundle is unavailable for DoT")?
    };
    let mut roots = RootCertStore::empty();
    let (loaded, _) = roots
        .add_parsable_certificates(CertificateDer::pem_slice_iter(&bundle).filter_map(Result::ok));
    ensure!(loaded != 0, "system CA bundle has no usable certificates");
    let config = ClientConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
        .with_root_certificates(roots)
        .with_no_client_auth()?;
    Ok(Arc::new(config))
}

struct Server {
    address: ServerAddress,
    domains: Domains,
}

struct CachedAnswer {
    ips: Vec<IpAddr>,
    expires: Instant,
}

pub struct Resolver {
    servers: Vec<Server>,
    strategy: Strategy,
    pub tag: String,
    cache: Option<Mutex<HashMap<(String, bool), CachedAnswer>>>,
    tls: Option<Arc<ClientConfig>>,
}

impl Resolver {
    pub fn compile(config: Config, geodata: &mut Geodata) -> Result<Self> {
        let servers = config
            .servers
            .into_iter()
            .map(|server| {
                let (address, port, domains) = match server {
                    ServerConfig::Address(address) => (address, None, Vec::new()),
                    ServerConfig::WithDomains {
                        address,
                        port,
                        domains,
                    } => (address, port, domains),
                };
                let address = if address == "localhost" {
                    ServerAddress::System
                } else if let Some(authority) = address.strip_prefix("tls://") {
                    ServerAddress::Tls(TlsUpstream::parse(authority, port)?)
                } else {
                    let ip = address
                        .parse()
                        .context("DNS upstream must be an IP, localhost or tls://")?;
                    let port = port.unwrap_or(53);
                    ensure!(port != 0, "invalid DNS upstream port");
                    ServerAddress::Udp(SocketAddr::new(ip, port))
                };
                Ok(Server {
                    address,
                    domains: Domains::compile(domains, geodata)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!servers.is_empty(), "no DNS servers configured");
        let tls = servers
            .iter()
            .any(|server| matches!(server.address, ServerAddress::Tls(_)))
            .then(system_tls_config)
            .transpose()?;
        Ok(Self {
            servers,
            strategy: config.query_strategy,
            tag: config.tag,
            cache: (!config.disable_cache).then(Mutex::default),
            tls,
        })
    }

    pub async fn lookup(
        &self,
        name: &str,
        ipv4_only: bool,
        allow_udp: impl Fn(SocketAddr) -> bool,
        allow_tcp: impl Fn(SocketAddr) -> bool,
    ) -> Result<Vec<IpAddr>> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let query = Name::from_ascii(format!("{name}."))?;
        let (v4, v6) = match self.strategy {
            Strategy::UseIP => (true, !ipv4_only),
            Strategy::UseIPv4 => (true, false),
            Strategy::UseIPv6 if !ipv4_only => (false, true),
            Strategy::UseIPv6 => bail!("DNS strategy excludes IPv4"),
        };
        let key = (name, ipv4_only);
        if let Some(cache) = &self.cache {
            if let Some(answer) = cache.lock().unwrap().get(&key) {
                if answer.expires > Instant::now() {
                    return Ok(answer.ips.clone());
                }
            }
        }
        let priority = |server: &&Server| {
            server.domains.matches(&key.0)
                || matches!(server.address, ServerAddress::System)
                    && (!key.0.contains('.')
                        || key.0.ends_with(".localhost")
                        || key.0.ends_with(".local")
                        || key.0.ends_with(".home.arpa"))
        };
        let ordered = self
            .servers
            .iter()
            .filter(priority)
            .chain(self.servers.iter().filter(|server| !priority(server)));
        for server in ordered {
            let (mut ips, ttl) = match &server.address {
                ServerAddress::System => {
                    let Ok(Ok(addresses)) =
                        timeout(QUERY_TIMEOUT, lookup_host((key.0.as_str(), 0))).await
                    else {
                        continue;
                    };
                    let ips = addresses
                        .map(|addr| addr.ip())
                        .filter(|ip| (v4 && ip.is_ipv4()) || (v6 && ip.is_ipv6()))
                        .collect::<Vec<_>>();
                    (ips, 0)
                }
                address => {
                    let transport = match address {
                        ServerAddress::Udp(address) if allow_udp(*address) => {
                            QueryTransport::Udp(*address)
                        }
                        ServerAddress::Tls(upstream) => QueryTransport::Tls(
                            upstream,
                            self.tls
                                .as_ref()
                                .context("DoT client configuration unavailable")?,
                        ),
                        _ => continue,
                    };
                    resolve_records(transport, &query, v4, v6, &allow_tcp).await
                }
            };
            if ips.is_empty() {
                continue;
            }
            ips.dedup();
            if let Some(cache) = &self.cache {
                if ttl != 0 {
                    let mut cache = cache.lock().unwrap();
                    if cache.len() >= CACHE_LIMIT && !cache.contains_key(&key) {
                        let now = Instant::now();
                        cache.retain(|_, answer| answer.expires > now);
                        if cache.len() >= CACHE_LIMIT {
                            if let Some(oldest) = cache.keys().next().cloned() {
                                cache.remove(&oldest);
                            }
                        }
                    }
                    cache.insert(
                        key,
                        CachedAnswer {
                            ips: ips.clone(),
                            expires: Instant::now()
                                + Duration::from_secs(u64::from(ttl.min(86400))),
                        },
                    );
                }
            }
            return Ok(ips);
        }
        bail!("no address from configured DNS servers")
    }
}

#[derive(Clone, Copy)]
enum QueryTransport<'a> {
    Udp(SocketAddr),
    Tls(&'a TlsUpstream, &'a Arc<ClientConfig>),
}

async fn resolve_records(
    transport: QueryTransport<'_>,
    query: &Name,
    v4: bool,
    v6: bool,
    allow_tcp: &impl Fn(SocketAddr) -> bool,
) -> (Vec<IpAddr>, u32) {
    let find = |enabled, kind| async move {
        if enabled {
            timeout(
                QUERY_TIMEOUT,
                resolve(transport, query.clone(), kind, allow_tcp),
            )
            .await
            .ok()
            .and_then(Result::ok)
        } else {
            None
        }
    };
    let (a, aaaa) = tokio::join!(find(v4, RecordType::A), find(v6, RecordType::AAAA));
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for (mut records, expires) in [a, aaaa].into_iter().flatten() {
        if !records.is_empty() {
            ips.append(&mut records);
            ttl = ttl.min(expires);
        }
    }
    (ips, ttl)
}

async fn resolve(
    transport: QueryTransport<'_>,
    mut name: Name,
    kind: RecordType,
    allow_tcp: impl Fn(SocketAddr) -> bool,
) -> Result<(Vec<IpAddr>, u32)> {
    let mut ttl = u32::MAX;
    for _ in 0..8 {
        let answer = exchange(transport, Query::query(name.clone(), kind), &allow_tcp).await?;
        let mut found_alias = false;
        for _ in 0..8 {
            let mut ips = Vec::new();
            let mut alias = None;
            for record in answer.answers.iter().filter(|record| record.name == name) {
                match (kind, &record.data) {
                    (RecordType::A, RData::A(ip)) => ips.push(IpAddr::V4(ip.0)),
                    (RecordType::AAAA, RData::AAAA(ip)) => ips.push(IpAddr::V6(ip.0)),
                    (_, RData::CNAME(target)) => alias = Some(target.0.clone()),
                    _ => continue,
                }
                ttl = ttl.min(record.ttl);
            }
            if !ips.is_empty() {
                return Ok((ips, ttl));
            }
            let Some(target) = alias else { break };
            name = target;
            found_alias = true;
        }
        if !found_alias {
            return Ok((Vec::new(), 0));
        }
    }
    bail!("DNS CNAME chain is too long")
}

async fn exchange(
    transport: QueryTransport<'_>,
    query: Query,
    allow_tcp: impl Fn(SocketAddr) -> bool,
) -> Result<Message> {
    let mut random = [0u8; 2];
    aws_lc_rs::rand::fill(&mut random)
        .map_err(|_| anyhow::anyhow!("DNS query ID generation failed"))?;
    let id = u16::from_ne_bytes(random);
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(query.clone());
    let bytes = message.to_vec()?;
    let reply = match transport {
        QueryTransport::Udp(address) => {
            udp_exchange(address, &bytes, id, &query, allow_tcp).await?
        }
        QueryTransport::Tls(upstream, tls) => {
            // Bootstrap with system DNS so resolving the DoT name never recurses into itself.
            let addresses: Vec<_> = lookup_host((upstream.host.as_str(), upstream.port))
                .await?
                .filter(|address| allow_tcp(*address))
                .collect();
            ensure!(!addresses.is_empty(), "DoT upstream is blocked by routing");
            let socket = TcpStream::connect(addresses.as_slice()).await?;
            let mut stream = TlsStream::connect(socket, tls.clone(), upstream.server_name.clone())
                .await
                .context("DoT TLS handshake failed")?;
            checked_reply(&tcp_exchange(&mut stream, &bytes).await?, id, &query)?
        }
    };
    ensure!(
        !reply.metadata.truncation && reply.metadata.response_code == ResponseCode::NoError,
        "DNS upstream did not return a successful answer"
    );
    Ok(reply)
}

async fn udp_exchange(
    address: SocketAddr,
    bytes: &[u8],
    id: u16,
    query: &Query,
    allow_tcp: impl Fn(SocketAddr) -> bool,
) -> Result<Message> {
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(address).await?;
    socket.send(bytes).await?;
    let mut buffer = [0u8; 4096];
    let size = socket.recv(&mut buffer).await?;
    let reply = checked_reply(&buffer[..size], id, query)?;
    if !reply.metadata.truncation {
        return Ok(reply);
    }
    ensure!(allow_tcp(address), "DNS TCP fallback is blocked by routing");
    let mut stream = TcpStream::connect(address).await?;
    checked_reply(&tcp_exchange(&mut stream, bytes).await?, id, query)
}

async fn tcp_exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<Vec<u8>> {
    stream.write_u16(u16::try_from(bytes.len())?).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    let mut response = vec![0; usize::from(stream.read_u16().await?)];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

fn checked_reply(bytes: &[u8], id: u16, query: &Query) -> Result<Message> {
    let reply = Message::from_vec(bytes)?;
    ensure!(
        reply.metadata.id == id
            && reply.metadata.message_type == MessageType::Response
            && reply.metadata.op_code == OpCode::Query
            && reply.queries.as_slice() == std::slice::from_ref(query),
        "DNS reply does not match the query"
    );
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Record, rdata::A};
    use std::net::Ipv4Addr;

    #[test]
    fn dot_endpoint_preserves_identity_and_selects_the_port() -> Result<()> {
        let endpoint = TlsUpstream::parse("DNS.Quad9.Net.", None)?;
        assert_eq!(
            (endpoint.host.as_str(), endpoint.port),
            ("dns.quad9.net", 853)
        );
        let endpoint = TlsUpstream::parse("[2620:fe::fe]:8853", None)?;
        assert_eq!(
            (endpoint.host.as_str(), endpoint.port),
            ("2620:fe::fe", 8853)
        );
        assert!(TlsUpstream::parse("dns.quad9.net:853", Some(8853)).is_err());
        assert!(TlsUpstream::parse("dns.quad9.net:0", None).is_err());
        assert!(TlsUpstream::parse("dns.quad9.net/dns-query", None).is_err());
        Ok(())
    }

    async fn reply_once(socket: UdpSocket, ip: Ipv4Addr) -> Result<()> {
        let mut bytes = [0; 512];
        let (size, peer) = socket.recv_from(&mut bytes).await?;
        let mut reply = Message::from_vec(&bytes[..size])?;
        let question = &reply.queries[0];
        assert_eq!(question.query_type(), RecordType::A);
        let answer = Record::from_rdata(question.name().clone(), 60, RData::A(A(ip)));
        reply.metadata.message_type = MessageType::Response;
        reply.add_answer(answer);
        socket.send_to(&reply.to_vec()?, peer).await?;
        Ok(())
    }

    #[tokio::test]
    async fn matched_resolver_precedes_fallback_and_caches_ipv4() -> Result<()> {
        let fallback = UdpSocket::bind("127.0.0.1:0").await?;
        let matched = UdpSocket::bind("127.0.0.1:0").await?;
        let upstream = |socket: &UdpSocket, domains| -> Result<ServerConfig> {
            Ok(ServerConfig::WithDomains {
                address: "127.0.0.1".into(),
                port: Some(socket.local_addr()?.port()),
                domains,
            })
        };
        let resolver = Resolver::compile(
            Config {
                servers: vec![
                    upstream(&fallback, vec![])?,
                    upstream(&matched, vec!["domain:ru".into()])?,
                ],
                tag: "dns_inbound".into(),
                disable_cache: false,
                query_strategy: Strategy::UseIPv4,
            },
            &mut Geodata::default(),
        )?;
        let fallback_ip = Ipv4Addr::new(1, 2, 3, 4);
        let matched_ip = Ipv4Addr::new(4, 3, 2, 1);
        let fallback = tokio::spawn(reply_once(fallback, fallback_ip));
        let matched = tokio::spawn(reply_once(matched, matched_ip));
        let lookup = |name| resolver.lookup(name, false, |_| true, |_| true);
        assert_eq!(lookup("example.ru").await?, [IpAddr::V4(matched_ip)]);
        assert_eq!(lookup("EXAMPLE.RU.").await?, [IpAddr::V4(matched_ip)]);
        assert_eq!(lookup("example.com").await?, [IpAddr::V4(fallback_ip)]);
        fallback.await??;
        matched.await??;
        Ok(())
    }
}
