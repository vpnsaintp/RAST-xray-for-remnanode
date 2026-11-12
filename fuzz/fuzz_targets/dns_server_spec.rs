#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::server::dns::{DnsServerSpec, parse_server_spec};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(DnsServerSpec::Tls {
        address,
        server_name,
    }) = parse_server_spec(text)
    {
        assert!(address.port() > 0);
        assert!(!server_name.is_empty());
        assert!(server_name.is_ascii());
    }
    // Exercise the TLS prefix independently of how often random input happens
    // to contain it. The same production parser owns both syntax and errors.
    if data.len() <= 256 {
        let candidate = format!("tls://dns.example/{text}");
        let _ = parse_server_spec(&candidate);
    }
});
