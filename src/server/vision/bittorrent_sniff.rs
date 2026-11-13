//! Bounded recognition of the first decrypted client bytes of a TCP session.
//!
//! This module has no I/O. Its caller feeds only client-to-destination
//! plaintext, in order, after forwarding. A match is an explicit protocol
//! signature; a route, port, or
//! remote peer handshake alone must never set this verdict.

const HANDSHAKE_PREFIX: &[u8; 20] = b"\x13BitTorrent protocol";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    Pending,
    BitTorrent,
    Other,
}

/// Tracks at most one prefix position per TCP connection, with no payload copy.
#[derive(Debug, Default)]
pub(crate) struct BitTorrentSniffer {
    matched: u8,
    verdict: Option<Verdict>,
}

impl BitTorrentSniffer {
    pub(crate) fn observe(&mut self, plaintext: &[u8]) -> Verdict {
        if let Some(verdict) = self.verdict {
            return verdict;
        }
        for &byte in plaintext {
            if byte != HANDSHAKE_PREFIX[usize::from(self.matched)] {
                self.verdict = Some(Verdict::Other);
                return Verdict::Other;
            }
            self.matched += 1;
            if usize::from(self.matched) == HANDSHAKE_PREFIX.len() {
                self.verdict = Some(Verdict::BitTorrent);
                return Verdict::BitTorrent;
            }
        }
        Verdict::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::{BitTorrentSniffer, Verdict};

    #[test]
    fn complete_handshake_matches() {
        let mut detector = BitTorrentSniffer::default();
        assert_eq!(
            detector.observe(b"\x13BitTorrent protocol\x00\x00"),
            Verdict::BitTorrent
        );
        assert_eq!(detector.observe(b"later data"), Verdict::BitTorrent);
    }

    #[test]
    fn fragmented_handshake_matches() {
        let mut detector = BitTorrentSniffer::default();
        assert_eq!(detector.observe(b""), Verdict::Pending);
        assert_eq!(detector.observe(b"\x13Bit"), Verdict::Pending);
        assert_eq!(detector.observe(b"Torrent pro"), Verdict::Pending);
        assert_eq!(detector.observe(b"tocol"), Verdict::BitTorrent);
    }

    #[test]
    fn wrong_prefix_is_final_other() {
        let mut detector = BitTorrentSniffer::default();
        assert_eq!(detector.observe(b"GET / HTTP/1.1"), Verdict::Other);
        assert_eq!(detector.observe(b"\x13BitTorrent protocol"), Verdict::Other);
    }

    #[test]
    fn near_match_is_not_protocol_proof() {
        let mut detector = BitTorrentSniffer::default();
        assert_eq!(detector.observe(b"\x13BitTorrent protocOl"), Verdict::Other);
    }
}
