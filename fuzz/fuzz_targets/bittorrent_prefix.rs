#![no_main]

use libfuzzer_sys::fuzz_target;

// Exercise the exact production parser without adding a production fuzz hook.
#[path = "../../src/server/vision/bittorrent_sniff.rs"]
mod bittorrent_sniff;
use bittorrent_sniff::{BitTorrentSniffer, Verdict};

const PREFIX: &[u8; 20] = b"\x13BitTorrent protocol";

fn expected(input: &[u8]) -> Verdict {
    if input.iter().zip(PREFIX).any(|(actual, wanted)| actual != wanted) {
        Verdict::Other
    } else if input.len() >= PREFIX.len() {
        Verdict::BitTorrent
    } else {
        Verdict::Pending
    }
}

fn check_fragments(input: &[u8]) {
    let target = expected(input);
    for boundary in 0..=input.len() {
        let mut sniffer = BitTorrentSniffer::default();
        let _ = sniffer.observe(&input[..boundary]);
        assert_eq!(sniffer.observe(&input[boundary..]), target);
        if target != Verdict::Pending {
            assert_eq!(sniffer.observe(b"unrelated later data"), target);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let input = &data[..data.len().min(64)];
    check_fragments(input);

    // Keep the positive and one-byte-near-positive paths reachable from any
    // corpus, while the arbitrary input above covers general rejection.
    let mut candidate = *PREFIX;
    if let Some(&position) = data.first() {
        let index = usize::from(position) % PREFIX.len();
        candidate[index] ^= data.get(1).copied().unwrap_or(1);
    }
    check_fragments(&candidate);
});
