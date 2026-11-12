# Rust core and RemnaNode review snapshot

This branch is a source review package. It is not a production release or an
instruction to deploy it to customer nodes.

## Provenance

- The `main` commit imports a source snapshot of
  [`jacek4yang/rust-reality`](https://github.com/jacek4yang/rust-reality) at
  local source commit `6c2d9986b9f01ee0f6fada39806b6dbc5bb0b389`.
  The Rust project retains its MIT/Apache-2.0 licenses.
- The next commit applies the final 33-file Rust patch. Those 33 files were
  compared byte for byte with the source tree used for the tested release
  binary, SHA-256
  `6ef14d08ac973c49f53d7fa15131ef38630dceca223f58f3752f9aab115f3c50`.
- `integrations/remnanode/` contains a separate patch against the Remnawave
  Node 3.4.1 pilot source. That code is covered by AGPL-3.0; it is not
  relicensed as part of the Rust crate.

## Verification and limits

The exact Rust source passed `cargo fmt --all -- --check`, 1,131 release
library tests (0 failed, 9 ignored), integration-test compilation, 19 XUDP
adversarial tests, Firefox-fingerprint UDP echo in both Handoff and NXR modes,
and a locked release build. An isolated 100-session HTTPS comparison completed
without request failures, but its CPU, memory and timing measurements do not
establish real customer capacity or Internet latency.

The full `cargo dev check --all` gate did not complete because the test host
reached its disk safety threshold. Isolated live revocation/accounting and
the actual Happ and Incy mobile-app checks remain open. These are release
gates, not claims of failure.

Benchmark evidence archives, local plans, logs, credentials, customer
configuration, subscription URLs, binaries and container images are excluded
from this repository. The omitted upstream evidence files are not required
for `cargo build --release --locked --bin rust-reality`, but some historical
tooling and evidence tests need them. Their omission should be considered
when interpreting a full repository test run.

## Review focus

1. REALITY/VLESS/Vision and Mihomo interoperability with `firefox` uTLS.
2. Dynamic user reload, revocation, per-user accounting and restart recovery.
3. Handoff and NXR bridge behavior, including source attribution for torrent
   monitoring.
4. Bounded XUDP sockets, FD budget and Linux `splice` fallback behavior.
5. DNS source-IP policy for standalone nodes with separate ingress and egress
   IPv4 addresses.
