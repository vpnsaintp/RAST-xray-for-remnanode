//! One-shot protocol evidence for authenticated, attributed TCP uplink bytes.
//!
//! The detector sees only bytes already decoded from the client's Vision
//! frames and forwarded toward the destination. Its state is bounded by the
//! fixed BitTorrent prefix; it never stores application payload.

use std::net::IpAddr;

use crate::logging::{LogEvent, Logger};
use crate::protocol::vless::{Address, Destination};

use super::bittorrent_sniff::{BitTorrentSniffer, Verdict};

pub(super) struct BitTorrentMonitor<'session> {
    logger: &'session Logger,
    source_ip: IpAddr,
    panel_user_id: u64,
    entry: &'session str,
    destination: &'session Destination,
    sniffer: BitTorrentSniffer,
    finished: bool,
}

impl<'session> BitTorrentMonitor<'session> {
    pub(super) fn new(
        logger: &'session Logger,
        source_ip: IpAddr,
        panel_user_id: u64,
        entry: &'session str,
        destination: &'session Destination,
    ) -> Self {
        Self {
            logger,
            source_ip,
            panel_user_id,
            entry,
            destination,
            sniffer: BitTorrentSniffer::default(),
            finished: false,
        }
    }

    pub(super) fn observe_forwarded(&mut self, plaintext: &[u8]) {
        if self.finished {
            return;
        }
        match self.sniffer.observe(plaintext) {
            Verdict::Pending => {}
            Verdict::Other => self.finished = true,
            Verdict::BitTorrent => {
                self.finished = true;
                let address = match self.destination.address() {
                    Address::Ipv4(ip) => ip.to_string(),
                    Address::Ipv6(ip) => format!("[{ip}]"),
                    Address::Domain(domain) => domain.clone(),
                };
                let _ = self.logger.emit(&LogEvent::ProtocolDetected {
                    entry: self.entry.to_owned(),
                    panel_user_id: self.panel_user_id,
                    source_ip: self.source_ip,
                    source_attribution: "proxy_v1_verified",
                    network: "tcp",
                    destination: format!("{address}:{}", self.destination.port()),
                    protocol: "bittorrent",
                    proof: "client_tcp_handshake_prefix_v1",
                });
            }
        }
    }
}
