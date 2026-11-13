use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;
use tokio::net::lookup_host;

use crate::backend::Flow;
use crate::dns::{self, Resolver};
use crate::egress::Egress;
pub use crate::egress::Outbound;
use crate::geodata::Geodata;
use crate::sniff::{Detected, Sniffing};
use crate::webhook::{Webhook, WebhookConfig};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

pub(crate) fn validate_domain(domain: &str) -> Result<&str> {
    let name = domain.trim_end_matches('.');
    ensure!(
        !name.is_empty()
            && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)),
        "invalid destination domain"
    );
    Ok(name)
}

impl Target {
    pub async fn addresses(&self) -> Result<Vec<SocketAddr>> {
        match &self.host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, self.port)]),
            Host::Name(name) => Ok(lookup_host((name.as_str(), self.port)).await?.collect()),
        }
    }

    pub fn authority(&self) -> String {
        match &self.host {
            Host::Ip(ip) => SocketAddr::new(*ip, self.port).to_string(),
            Host::Name(name) => format!("{name}:{}", self.port),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default)]
    domain_strategy: String,
    #[serde(default)]
    rules: Vec<RuleConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleConfig {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    rule_tag: String,
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    ip: Vec<String>,
    #[serde(default)]
    network: String,
    #[serde(default)]
    port: serde_json::Value,
    #[serde(default)]
    inbound_tag: Vec<String>,
    #[serde(default)]
    user: Vec<String>,
    #[serde(default)]
    protocol: Vec<String>,
    #[serde(default)]
    webhook: Option<WebhookConfig>,
    outbound_tag: String,
}

#[derive(Default)]
pub(crate) struct Domains {
    exact: HashSet<String>,
    suffix: HashSet<String>,
    other: Vec<DomainRule>,
}

enum DomainRule {
    Keyword(String),
    Regex(Regex),
}

impl Domains {
    pub(crate) fn compile(items: Vec<String>, geodata: &mut Geodata) -> Result<Self> {
        let mut result = Self::default();
        for item in items {
            if let Some(group) = geodata.domains(&item)? {
                for domain in group {
                    result.add(&domain)?;
                }
            } else {
                result.add(&item)?;
            }
        }
        Ok(result)
    }

    fn add(&mut self, value: &str) -> Result<()> {
        match value.split_once(':') {
            Some(("full", text)) => {
                self.exact.insert(text.to_ascii_lowercase());
            }
            Some(("domain", text)) => {
                self.suffix.insert(text.to_ascii_lowercase());
            }
            Some(("keyword" | "plain", text)) => self
                .other
                .push(DomainRule::Keyword(text.to_ascii_lowercase())),
            Some(("regexp", text)) => self.other.push(DomainRule::Regex(Regex::new(text)?)),
            Some(_) => bail!("unsupported domain matcher"),
            None => self
                .other
                .push(DomainRule::Keyword(value.to_ascii_lowercase())),
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix.is_empty() && self.other.is_empty()
    }

    pub(crate) fn matches(&self, name: &str) -> bool {
        self.exact.contains(name)
            || self.suffix.contains(name)
            || name
                .match_indices('.')
                .any(|(dot, _)| self.suffix.contains(&name[dot + 1..]))
            || self.other.iter().any(|rule| match rule {
                DomainRule::Keyword(pattern) => name.contains(pattern),
                DomainRule::Regex(pattern) => pattern.is_match(name),
            })
    }
}

struct IpGroup {
    v4: Vec<ipnet::Ipv4Net>,
    v6: Vec<ipnet::Ipv6Net>,
    inverse: bool,
}

impl IpGroup {
    fn new(networks: Vec<IpNet>, inverse: bool) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for network in IpNet::aggregate(&networks) {
            match network {
                IpNet::V4(net) => v4.push(net),
                IpNet::V6(net) => v6.push(net),
            }
        }
        v4.sort_unstable_by_key(|net| net.network());
        v6.sort_unstable_by_key(|net| net.network());
        Self { v4, v6, inverse }
    }

    fn matches(&self, ip: IpAddr) -> bool {
        let matched = match ip {
            IpAddr::V4(ip) => {
                let n = self.v4.partition_point(|net| net.network() <= ip);
                n > 0 && self.v4[n - 1].contains(&ip)
            }
            IpAddr::V6(ip) => {
                let n = self.v6.partition_point(|net| net.network() <= ip);
                n > 0 && self.v6[n - 1].contains(&ip)
            }
        };
        matched != self.inverse
    }
}

struct Rule {
    domains: Domains,
    ips: Vec<IpGroup>,
    ports: Vec<(u16, u16)>,
    networks: Vec<String>,
    inbounds: Vec<String>,
    users: Vec<String>,
    protocols: Vec<String>,
    webhook: Option<Webhook>,
    tag: String,
}

impl Rule {
    fn compile(config: RuleConfig, geodata: &mut Geodata) -> Result<Self> {
        ensure!(
            matches!(config.kind.as_str(), "" | "field"),
            "unsupported routing rule type"
        );
        let domains = Domains::compile(config.domain, geodata)?;
        let mut ips = Vec::new();
        let mut standalone = Vec::new();
        for item in config.ip {
            if let Some((networks, inverse)) = geodata.cidrs(&item)? {
                ips.push(IpGroup::new(networks, inverse));
            } else {
                standalone.push(
                    item.parse::<IpNet>()
                        .or_else(|_| item.parse::<IpAddr>().map(IpNet::from))
                        .context("unsupported IP matcher")?,
                );
            }
        }
        if !standalone.is_empty() {
            ips.push(IpGroup::new(standalone, false));
        }
        let ports = match config.port {
            serde_json::Value::Null => Vec::new(),
            serde_json::Value::Number(number) => {
                let port = number
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok())
                    .context("invalid port")?;
                vec![(port, port)]
            }
            serde_json::Value::String(text) => text
                .split(',')
                .map(|value| {
                    let (start, end) = value.split_once('-').unwrap_or((value, value));
                    let (start, end) = (start.trim().parse()?, end.trim().parse()?);
                    ensure!(start <= end, "invalid port range");
                    Ok((start, end))
                })
                .collect::<Result<Vec<_>>>()?,
            _ => bail!("unsupported port matcher"),
        };
        let networks: Vec<_> = config
            .network
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .collect();
        ensure!(
            networks.iter().all(|v| matches!(v.as_str(), "tcp" | "udp")),
            "invalid route network"
        );
        let _ = config.rule_tag;
        Ok(Self {
            domains,
            ips,
            ports,
            networks,
            inbounds: config.inbound_tag,
            users: config.user,
            protocols: config.protocol,
            webhook: config.webhook.map(Webhook::compile).transpose()?,
            tag: config.outbound_tag,
        })
    }

    fn matches(
        &self,
        target: &Target,
        ip: Option<IpAddr>,
        network: &str,
        inbound: &str,
        user: &str,
        protocol: &str,
    ) -> bool {
        (self.domains.is_empty()
            || matches!(&target.host, Host::Name(name) if self.domains.matches(name)))
            && (self.ips.is_empty()
                || ip.is_some_and(|ip| self.ips.iter().any(|group| group.matches(ip))))
            && (self.ports.is_empty()
                || self
                    .ports
                    .iter()
                    .any(|&(start, end)| (start..=end).contains(&target.port)))
            && (self.networks.is_empty() || self.networks.iter().any(|value| value == network))
            && (self.inbounds.is_empty() || self.inbounds.iter().any(|value| value == inbound))
            && (self.users.is_empty() || self.users.iter().any(|value| value == user))
            && (self.protocols.is_empty()
                || self
                    .protocols
                    .iter()
                    .any(|value| protocol.starts_with(value)))
    }
}

pub struct Router {
    policy: RwLock<Policy>,
    default: String,
    resolve_before: bool,
    resolve_on_miss: bool,
    allow: Option<Vec<SocketAddr>>,
    dns: Option<Resolver>,
}

struct Policy {
    rules: Vec<Rule>,
    outbounds: HashMap<String, Egress>,
}

pub struct Route {
    pub tag: String,
    pub target: Target,
    pub egress: Egress,
    pub addresses: Vec<SocketAddr>,
}

impl Router {
    pub fn new(
        config: RoutingConfig,
        outbounds: Vec<Outbound>,
        allow: Option<Vec<SocketAddr>>,
        dns: Option<dns::Config>,
    ) -> Result<Self> {
        let default = outbounds.first().context("no outbounds")?.tag.clone();
        let mut handlers = HashMap::new();
        for outbound in outbounds {
            let tag = outbound.tag.clone();
            let egress =
                Egress::compile(outbound).with_context(|| format!("configure outbound {tag}"))?;
            ensure!(
                handlers.insert(tag, egress).is_none(),
                "duplicate outbound tag"
            );
        }
        let mut geodata = Geodata::default();
        let dns = dns
            .map(|config| Resolver::compile(config, &mut geodata))
            .transpose()?;
        let rules = config
            .rules
            .into_iter()
            .filter(|rule| rule.outbound_tag != "REMNAWAVE_API")
            .map(|rule| Rule::compile(rule, &mut geodata))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            rules.iter().all(|rule| handlers.contains_key(&rule.tag)),
            "rule references an unknown outbound"
        );
        let (resolve_before, resolve_on_miss) = match config.domain_strategy.as_str() {
            "" | "AsIs" => (false, false),
            "IPIfNonMatch" => (false, true),
            "IPOnDemand" => (true, false),
            _ => bail!("unsupported domain strategy"),
        };
        Ok(Self {
            policy: RwLock::new(Policy {
                rules,
                outbounds: handlers,
            }),
            default,
            resolve_before,
            resolve_on_miss,
            allow,
            dns,
        })
    }

    pub async fn resolve(
        &self,
        target: &Target,
        configured: bool,
        ipv4_only: bool,
    ) -> Result<Vec<SocketAddr>> {
        if let Host::Name(name) = &target.host {
            if let Some(dns) = self.dns.as_ref().filter(|_| configured) {
                let ips = dns
                    .lookup(
                        name,
                        ipv4_only,
                        |address| self.direct_dns(&dns.tag, address, "udp"),
                        |address| self.direct_dns(&dns.tag, address, "tcp"),
                    )
                    .await?;
                return Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, target.port))
                    .collect());
            }
        }
        let mut addresses = target.addresses().await?;
        if ipv4_only {
            addresses.retain(SocketAddr::is_ipv4);
        }
        Ok(addresses)
    }

    fn direct_dns(&self, inbound: &str, address: SocketAddr, network: &str) -> bool {
        let target = Target {
            host: Host::Ip(address.ip()),
            port: address.port(),
        };
        let policy = self.policy.read().unwrap();
        let tag = policy
            .rules
            .iter()
            .find(|rule| rule.matches(&target, Some(address.ip()), network, inbound, "", ""))
            .map_or(self.default.as_str(), |rule| rule.tag.as_str());
        matches!(policy.outbounds.get(tag), Some(Egress::Direct(_)))
    }

    pub async fn route(
        &self,
        target: &Target,
        network: &str,
        flow: Flow<'_>,
        sniffing: &Sniffing,
        detected: &Detected,
    ) -> Result<Route> {
        let sniffed = sniffing.routing_domain(detected).map(|name| Target {
            host: Host::Name(name.into()),
            port: target.port,
        });
        let route_target = sniffed.as_ref().unwrap_or(target);
        let connect_target = if sniffing.route_only {
            target
        } else {
            route_target
        };
        let ip = match connect_target.host {
            Host::Ip(ip) => Some(ip),
            Host::Name(_) => None,
        };
        let matches = |rule: &Rule, ip| {
            rule.matches(
                route_target,
                ip,
                network,
                flow.inbound,
                flow.email,
                detected.protocol,
            )
        };
        let needs_dns = ip.is_none()
            && (self.resolve_before
                || self.resolve_on_miss && {
                    let policy = self.policy.read().unwrap();
                    !policy.rules.iter().any(|rule| matches(rule, None))
                });
        let ips = if needs_dns {
            self.resolve(connect_target, true, false)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let (tag, egress) = {
            let policy = self.policy.read().unwrap();
            let rule = policy.rules.iter().find(|rule| {
                matches(rule, ip) || ips.iter().any(|addr| matches(rule, Some(addr.ip())))
            });
            let tag = rule.map_or(self.default.as_str(), |rule| rule.tag.as_str());
            if let Some(webhook) = rule.and_then(|rule| rule.webhook.as_ref()) {
                webhook.fire(flow, detected.protocol, network, target, route_target, tag);
            }
            let egress = policy
                .outbounds
                .get(tag)
                .context("outbound unavailable")?
                .clone();
            (tag.to_owned(), egress)
        };
        ensure!(
            !matches!(egress, Egress::Block),
            "routing blocked the destination"
        );
        let mut addresses = Vec::new();
        if let Egress::Direct(direct) = &egress {
            addresses = direct
                .addresses(self, connect_target, self.allow.is_some())
                .await?;
            addresses.retain(|address| {
                self.allow
                    .as_ref()
                    .is_none_or(|allow| allow.contains(address))
            });
            ensure!(!addresses.is_empty(), "destination not permitted");
        }
        Ok(Route {
            tag,
            target: connect_target.clone(),
            egress,
            addresses,
        })
    }

    pub fn disable_torrent(&self) {
        let mut policy = self.policy.write().unwrap();
        let tag = crate::go_router::TORRENT_OUTBOUND;
        policy
            .rules
            .retain(|rule| rule.tag != tag || rule.webhook.is_none());
        policy.outbounds.remove(tag);
    }
}
