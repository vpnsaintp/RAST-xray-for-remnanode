use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use prost::Message;

#[derive(Clone, Message)]
struct Sites {
    #[prost(message, repeated, tag = "1")]
    groups: Vec<Site>,
}

#[derive(Clone, Message)]
struct Site {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    domains: Vec<Domain>,
}

#[derive(Clone, Message)]
struct Domain {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attributes: Vec<Attribute>,
}

#[derive(Clone, Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
}

#[derive(Clone, Message)]
struct Ips {
    #[prost(message, repeated, tag = "1")]
    groups: Vec<IpGroup>,
}

#[derive(Clone, Message)]
struct IpGroup {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    cidrs: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    inverse: bool,
}

#[derive(Clone, Message)]
struct Cidr {
    #[prost(bytes, tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Default)]
pub struct Geodata {
    sites: HashMap<String, Sites>,
    ips: HashMap<String, Ips>,
}

impl Geodata {
    pub fn domains(&mut self, matcher: &str) -> Result<Option<Vec<String>>> {
        let Some((file, name)) = reference(matcher, "geosite", "geosite.dat")? else {
            return Ok(None);
        };
        if !self.sites.contains_key(file) {
            self.sites
                .insert(file.into(), Sites::decode(asset(file)?.as_slice())?);
        }
        let mut parts = name.split('@');
        let code = parts.next().context("missing GeoSite group")?;
        let attrs: Vec<_> = parts.collect();
        let group = self.sites[file]
            .groups
            .iter()
            .find(|group| group.code.eq_ignore_ascii_case(code))
            .with_context(|| format!("GeoSite group missing: {code}"))?;
        let domains = group
            .domains
            .iter()
            .filter(|domain| {
                attrs.iter().all(|attr| {
                    let (key, invert) = attr
                        .strip_prefix('!')
                        .map_or((*attr, false), |key| (key, true));
                    domain
                        .attributes
                        .iter()
                        .any(|item| item.key.eq_ignore_ascii_case(key))
                        != invert
                })
            })
            .map(|domain| {
                let kind = match domain.kind {
                    0 => "keyword",
                    1 => "regexp",
                    2 => "domain",
                    3 => "full",
                    _ => bail!("unsupported GeoSite matcher"),
                };
                Ok(format!("{kind}:{}", domain.value))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!domains.is_empty(), "empty GeoSite group {name}");
        Ok(Some(domains))
    }

    pub fn cidrs(&mut self, matcher: &str) -> Result<Option<(Vec<IpNet>, bool)>> {
        let Some((file, name)) = reference(matcher, "geoip", "geoip.dat")? else {
            return Ok(None);
        };
        if !self.ips.contains_key(file) {
            self.ips
                .insert(file.into(), Ips::decode(asset(file)?.as_slice())?);
        }
        let (code, invert) = name
            .strip_prefix('!')
            .map_or((name, false), |code| (code, true));
        let group = self.ips[file]
            .groups
            .iter()
            .find(|group| group.code.eq_ignore_ascii_case(code))
            .with_context(|| format!("GeoIP group missing: {code}"))?;
        let cidrs = group
            .cidrs
            .iter()
            .map(|item| {
                let ip = match item.ip.as_slice() {
                    [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                    bytes if bytes.len() == 16 => {
                        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes)?))
                    }
                    _ => bail!("invalid GeoIP address"),
                };
                Ok(IpNet::new(ip, u8::try_from(item.prefix)?)?)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!cidrs.is_empty(), "empty GeoIP group {name}");
        Ok(Some((cidrs, group.inverse || invert)))
    }
}

fn reference<'a>(
    matcher: &'a str,
    kind: &str,
    default: &'static str,
) -> Result<Option<(&'a str, &'a str)>> {
    let Some((prefix, value)) = matcher.split_once(':') else {
        return Ok(None);
    };
    match prefix {
        prefix if prefix == kind => Ok(Some((default, value))),
        "ext" | "ext-domain" | "ext-ip" => Ok(Some(
            value
                .split_once(':')
                .context("invalid external geodata matcher")?,
        )),
        _ => Ok(None),
    }
}

fn asset(file: &str) -> Result<Vec<u8>> {
    ensure!(
        Path::new(file).file_name().is_some_and(|name| name == file),
        "invalid geodata filename"
    );
    let executable = std::env::current_exe()?;
    let candidates = std::env::var_os("XRAY_LOCATION_ASSET")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            executable
                .parent()
                .context("missing executable directory")?
                .to_owned(),
            PathBuf::from("/usr/local/share/xray"),
            PathBuf::from("/usr/share/xray"),
        ]);
    for dir in candidates {
        let path = dir.join(file);
        match std::fs::read(&path) {
            Ok(bytes) => return Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        }
    }
    bail!("geodata file not found: {file}")
}
