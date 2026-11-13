use std::time::Duration;

use rustls::quic::{Side, Suite, Version};
use rustls::server::RealityClientHelloProbe;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, timeout_at};

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Sniffing {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    dest_override: Vec<String>,
    #[serde(default)]
    domains_excluded: Vec<String>,
    #[serde(default)]
    pub route_only: bool,
    #[serde(default)]
    metadata_only: bool,
}

#[derive(Default)]
pub struct Detected {
    pub protocol: &'static str,
    pub domain: Option<String>,
}

impl Sniffing {
    pub fn routing_domain<'a>(&self, result: &'a Detected) -> Option<&'a str> {
        result.domain.as_deref().filter(|name| {
            self.dest_override
                .iter()
                .any(|protocol| protocol == result.protocol)
                && !self
                    .domains_excluded
                    .iter()
                    .any(|domain| name.eq_ignore_ascii_case(domain))
        })
    }

    pub async fn tcp(
        &self,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> std::io::Result<(Vec<u8>, Detected)> {
        let mut prefix = Vec::new();
        if self.enabled && !self.metadata_only {
            let deadline = Instant::now() + Duration::from_millis(200);
            let mut buffer = [0; 4096];
            while prefix.len() < 16 * 1024 {
                let Ok(count) = timeout_at(deadline, reader.read(&mut buffer)).await else {
                    break;
                };
                let count = count?;
                if count == 0 {
                    break;
                }
                prefix.extend_from_slice(&buffer[..count]);
                if let Some(result) = tcp_protocol(&prefix) {
                    return Ok((prefix, result));
                }
            }
        }
        Ok((prefix, Detected::default()))
    }

    pub(crate) fn udp_bittorrent(&self, packet: &[u8]) -> bool {
        self.enabled && !self.metadata_only && (utp(packet) || dht(packet))
    }

    pub fn udp_quic(&self, packet: &[u8]) -> (Detected, Option<QuicProbe>) {
        if !self.enabled || self.metadata_only {
            return (Detected::default(), None);
        }
        let mut probe = QuicProbe::default();
        if let Some(result) = probe.push(packet) {
            let pending = result.domain.is_none().then_some(probe);
            return (result, pending);
        }
        (Detected::default(), None)
    }
}

fn tcp_protocol(bytes: &[u8]) -> Option<Detected> {
    if bytes.starts_with(b"\x13BitTorrent protocol") {
        return Some(Detected {
            protocol: "bittorrent",
            domain: None,
        });
    }
    if bytes.starts_with(&[22, 3]) {
        return match RealityClientHelloProbe::from_tls_records(bytes) {
            Ok(Some(hello)) => Some(Detected {
                protocol: "tls",
                domain: hello.server_name().and_then(normalize),
            }),
            Ok(None) => None,
            Err(_) => Some(Detected::default()),
        };
    }
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"HEAD ",
        b"OPTIONS ",
        b"DELETE ",
        b"CONNECT ",
        b"TRACE ",
        b"PRI ",
    ];
    if METHODS.iter().any(|method| bytes.starts_with(method)) {
        let end = bytes.windows(4).position(|part| part == b"\r\n\r\n")?;
        let text = std::str::from_utf8(&bytes[..end]).ok()?;
        let domain = text
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case("host"))
            .and_then(|(_, value)| normalize(value.trim().split(':').next().unwrap_or_default()));
        return Some(Detected {
            protocol: "http",
            domain,
        });
    }
    if b"\x13BitTorrent protocol".starts_with(bytes)
        || METHODS.iter().any(|method| method.starts_with(bytes))
        || [22, 3].starts_with(bytes)
    {
        return None;
    }
    Some(Detected::default())
}

fn normalize(domain: &str) -> Option<String> {
    let name = domain.trim_end_matches('.');
    (!name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)))
    .then(|| name.to_ascii_lowercase())
}

fn utp(data: &[u8]) -> bool {
    if data.len() < 20 || data[0] != 0x41 || data[1] > 1 || data[18..20] != [0, 0] {
        return false;
    }
    let mut extension = data[1];
    let mut rest = &data[20..];
    while extension != 0 {
        if extension != 1 || rest.len() < 2 {
            return false;
        }
        extension = rest[0];
        let Some(next) = rest.get(2 + usize::from(rest[1])..) else {
            return false;
        };
        rest = next;
    }
    rest.is_empty()
}

fn dht(packet: &[u8]) -> bool {
    fn node_id(value: &[u8]) -> bool {
        let mut valid_id = false;
        bencode_fields(value, |key, mut field| {
            if key == b"id" {
                valid_id = bencode_string(&mut field).is_some_and(|id| id.len() == 20);
            }
        })
        .is_some()
            && valid_id
    }

    if packet.first() != Some(&b'd') {
        return false;
    }
    let (mut transaction, mut kind, mut method) = (None, None, None);
    let (mut arguments, mut response) = (None, None);
    if bencode_fields(packet, |key, mut value| match key {
        b"t" => transaction = bencode_string(&mut value),
        b"y" => kind = bencode_string(&mut value),
        b"q" => method = bencode_string(&mut value),
        b"a" => arguments = Some(value),
        b"r" => response = Some(value),
        _ => {}
    })
    .is_none()
        || !transaction.is_some_and(|id| !id.is_empty())
    {
        return false;
    }
    match kind {
        Some(b"q") => {
            matches!(
                method,
                Some(
                    b"ping" | b"find_node" | b"get_peers" | b"announce_peer" | b"get" | b"put"
                        | b"sample_infohashes"
                )
            ) && arguments.is_some_and(node_id)
        }
        Some(b"r") => response.is_some_and(node_id),
        _ => false,
    }
}

fn bencode_fields<'a>(
    mut input: &'a [u8],
    mut field: impl FnMut(&'a [u8], &'a [u8]),
) -> Option<()> {
    if take(&mut input, 1)? != b"d" {
        return None;
    }
    while input.first() != Some(&b'e') {
        let key = bencode_string(&mut input)?;
        let value = input;
        skip_bencode_value(&mut input, 8)?;
        field(key, &value[..value.len() - input.len()]);
    }
    take(&mut input, 1)?;
    input.is_empty().then_some(())
}

fn bencode_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let digits = input.iter().position(|&byte| !byte.is_ascii_digit())?;
    if digits == 0 || input[digits] != b':' || (digits > 1 && input[0] == b'0') {
        return None;
    }
    let length = input[..digits].iter().try_fold(0usize, |value, &digit| {
        value.checked_mul(10)?.checked_add(usize::from(digit - b'0'))
    })?;
    take(input, digits + 1)?;
    take(input, length)
}

fn skip_bencode_value(input: &mut &[u8], depth: usize) -> Option<()> {
    match *input.first()? {
        b'0'..=b'9' => {
            bencode_string(input)?;
        }
        b'i' => {
            take(input, 1)?;
            let end = input.iter().position(|&byte| byte == b'e')?;
            std::str::from_utf8(take(input, end)?)
                .ok()?
                .parse::<i64>()
                .ok()?;
            take(input, 1)?;
        }
        kind @ (b'd' | b'l') if depth > 0 => {
            take(input, 1)?;
            while input.first() != Some(&b'e') {
                if kind == b'd' {
                    bencode_string(input)?;
                }
                skip_bencode_value(input, depth - 1)?;
            }
            take(input, 1)?;
        }
        _ => return None,
    }
    Some(())
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    let (item, rest) = input.split_at_checked(count)?;
    *input = rest;
    Some(item)
}

fn prefixed<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = usize::from(take(input, 1)?[0]);
    take(input, length)
}

fn varint(input: &mut &[u8]) -> Option<usize> {
    let length = 1 << (input.first()? >> 6);
    let bytes = take(input, length)?;
    let number = bytes[1..]
        .iter()
        .fold(u64::from(bytes[0] & 0x3f), |n, byte| {
            (n << 8) | u64::from(*byte)
        });
    usize::try_from(number).ok()
}

#[derive(Default)]
pub struct QuicProbe {
    id: Vec<u8>,
    crypto: Vec<u8>,
    present: Vec<bool>,
}

impl QuicProbe {
    pub fn push(&mut self, datagram: &[u8]) -> Option<Detected> {
        if datagram.len() < 1200 {
            return None;
        }
        let mut packets = datagram;
        let mut matched = false;
        while let Some((rest, id, plain)) = quic_initial(packets) {
            packets = rest;
            if self.id.is_empty() {
                self.id.extend_from_slice(id);
            }
            if self.id != id {
                break;
            }
            matched = true;
            self.merge(&plain);
        }
        if !matched {
            return None;
        }
        let contiguous = self.present.iter().take_while(|byte| **byte).count();
        let bytes = &self.crypto[..contiguous];
        let mut records = vec![22, 3, 3];
        records.extend((bytes.len() as u16).to_be_bytes());
        records.extend_from_slice(bytes);
        let domain = RealityClientHelloProbe::from_tls_records(&records)
            .ok()
            .flatten()
            .and_then(|hello| hello.server_name().and_then(normalize));
        Some(Detected {
            protocol: "quic",
            domain,
        })
    }

    fn merge(&mut self, mut plaintext: &[u8]) -> Option<()> {
        while !plaintext.is_empty() {
            match varint(&mut plaintext)? {
                0 | 1 => {}
                kind @ (2 | 3) => {
                    varint(&mut plaintext)?;
                    varint(&mut plaintext)?;
                    let ranges = varint(&mut plaintext)?;
                    varint(&mut plaintext)?;
                    for _ in 0..ranges {
                        varint(&mut plaintext)?;
                        varint(&mut plaintext)?;
                    }
                    if kind == 3 {
                        for _ in 0..3 {
                            varint(&mut plaintext)?;
                        }
                    }
                }
                6 => {
                    let offset = varint(&mut plaintext)?;
                    let length = varint(&mut plaintext)?;
                    let end = offset.checked_add(length).filter(|end| *end <= 16 * 1024)?;
                    let part = take(&mut plaintext, length)?;
                    if self.crypto.len() < end {
                        self.crypto.resize(end, 0);
                        self.present.resize(end, false);
                    }
                    self.crypto[offset..end].copy_from_slice(part);
                    self.present[offset..end].fill(true);
                }
                _ => break,
            }
        }
        Some(())
    }
}

fn quic_initial(datagram: &[u8]) -> Option<(&[u8], &[u8], Vec<u8>)> {
    let mut input = datagram;
    let first = take(&mut input, 1)?[0];
    let version = u32::from_be_bytes(take(&mut input, 4)?.try_into().ok()?);
    let version = match (version, first & 0xf0) {
        (1, 0xc0) => Version::V1,
        (0x6b3343cf, 0xd0) => Version::V2,
        _ => return None,
    };
    let dcid = prefixed(&mut input)?;
    if dcid.is_empty() || dcid.len() > 20 || prefixed(&mut input)?.len() > 20 {
        return None;
    }
    let token_len = varint(&mut input)?;
    take(&mut input, token_len)?;
    let packet_len = varint(&mut input)?;
    let pn_offset = datagram.len() - input.len();
    let suite = Suite::try_from(rustls_aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256).ok()?;
    let keys = suite.keys(dcid, Side::Server, version).remote;
    let mut number = input.get(..4)?.to_vec();
    let mut first = first;
    keys.header
        .decrypt_in_place(
            input.get(4..4 + keys.header.sample_len())?,
            &mut first,
            &mut number,
        )
        .ok()?;
    let number_len = usize::from(first & 3) + 1;
    let mut header = datagram.get(..pn_offset)?.to_vec();
    header[0] = first;
    header.extend_from_slice(&number[..number_len]);
    let packet_number = number[..number_len]
        .iter()
        .fold(0, |n, byte| (n << 8) | u64::from(*byte));
    let mut encrypted = input.get(number_len..packet_len)?.to_vec();
    let plaintext = keys
        .packet
        .decrypt_in_place(packet_number, &header, &mut encrypted, None)
        .ok()?;
    Some((input.get(packet_len..)?, dcid, plaintext.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn recognizes_dht_without_matching_unrelated_bencoded_data() {
        let ping = b"d1:ad2:id20:01234567890123456789e1:q4:ping1:t2:aa1:y1:qe";
        let reply = b"d1:rd2:id20:01234567890123456789e1:t2:aa1:y1:re";
        assert!(dht(ping));
        assert!(dht(reply));
        assert!(!dht(&ping[..ping.len() - 1]));
        assert!(!dht(b"d1:ad2:id5:shorte1:q4:ping1:t2:aa1:y1:qe"));
        assert!(!dht(b"d1:ad2:id20:01234567890123456789e1:q4:test1:t2:aa1:y1:qe"));
        assert!(!dht(b"d1:ad2:id999999999999999999999:1ae1:q4:ping1:t2:aa1:y1:qe"));
    }

    #[test]
    fn detects_tls_sni_and_reassembles_quic_initials() {
        let config = Arc::new(
            rustls::ClientConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth()
                .unwrap(),
        );
        let mut wire = Vec::new();
        let _conn = config
            .connect("probe.example.com".try_into().unwrap())
            .build(&mut wire)
            .unwrap();
        assert_eq!(
            tcp_protocol(&wire).unwrap().domain.as_deref(),
            Some("probe.example.com")
        );
        let hello = RealityClientHelloProbe::from_tls_records(&wire)
            .unwrap()
            .unwrap();
        let bytes = hello.handshake();
        let offset = bytes.len() / 2;
        for version in [Version::V1, Version::V2] {
            let mut probe = QuicProbe::default();
            let tail = initial(version, 1, offset, &bytes[offset..]);
            let head = initial(version, 0, 0, &bytes[..offset]);
            assert!(probe.push(&tail).unwrap().domain.is_none());
            let result = probe.push(&head).unwrap();
            assert_eq!(result.domain.as_deref(), Some("probe.example.com"));
            assert_eq!(result.protocol, "quic");
        }
    }

    fn initial(version: Version, number: u8, offset: usize, fragment: &[u8]) -> Vec<u8> {
        let id = b"probe-id";
        let (first, version_id): (u8, u32) = match version {
            Version::V1 => (0xc0, 1),
            Version::V2 => (0xd0, 0x6b3343cf),
            _ => unreachable!(),
        };
        let varint = |number: usize| (0x4000 | u16::try_from(number).unwrap()).to_be_bytes();
        let mut header = vec![first];
        header.extend(version_id.to_be_bytes());
        header.push(id.len() as u8);
        header.extend(id);
        header.extend([0, 0]); // Empty SCID and token.
        let payload_size = 1200 - header.len() - 2 - 1 - 16;
        header.extend(varint(payload_size + 1 + 16));
        header.push(number);
        let mut data = vec![6];
        data.extend(varint(offset));
        data.extend(varint(fragment.len()));
        data.extend(fragment);
        data.resize(payload_size, 0);
        let suite =
            Suite::try_from(rustls_aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256).unwrap();
        let keys = suite.keys(id, Side::Client, version).local;
        let tag = keys
            .packet
            .encrypt_in_place(number.into(), &header, &mut data, None)
            .unwrap();
        data.extend(tag.as_ref());
        let (first, rest) = header.split_first_mut().unwrap();
        let pn = rest.last_mut().unwrap();
        keys.header
            .encrypt_in_place(
                &data[3..3 + keys.header.sample_len()],
                first,
                std::slice::from_mut(pn),
            )
            .unwrap();
        header.extend(data);
        header
    }
}
