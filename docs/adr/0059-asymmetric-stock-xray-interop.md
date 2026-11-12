# ADR 0059: Asymmetric stock Xray interop

Status: Accepted

## Context

Release work briefly treated bidirectional UDP/XUDP with unmodified stock
Xray-core as a gate (rust-reality client → Xray server as well as Xray client →
rust-reality server). Owner clarification: the product only guarantees
**ingress** compatibility with stock Xray clients. Driving an unmodified Xray
**server** from the rust-reality client is not a present or future contract and
must not block CI, Native, Frozen, or release acceptance.

Historical probes (ClientHello parse failures, SetFlushNext response ordering,
freedom private-IP defaults) remain useful evidence; they are not acceptance
criteria.

## Decision

1. **Required:** rust-reality Client ↔ rust-reality Server (TCP Vision and
   UDP/XUDP, including `allowUdp443` policy and UDP/443 verification without
   TCP CONNECT fallback where the environment can bind `:443`).
2. **Required:** unmodified stock Xray-core Client → rust-reality Server for
   supported VLESS + REALITY + Vision + XUDP ingress. Exact-head Native and
   related gates exercise this direction.
3. **Not required:** rust-reality Client → stock Xray-core Server. No guarantee
   now or later. Strip from mandatory gates; keep at most `#[ignore]` / docs
   historical notes.
4. Future native capabilities use explicit authenticated boundaries; do not
   silently alter Xray-compatible ingress or add insecure downgrade paths.
5. No second protocol, duplicate configuration schema, or speculative
   compatibility framework for the non-required direction (AGENTS.md §6 / §8).

## Consequences

- AGENTS.md §6 states the directional table as binding law.
- `tests/xudp_stock_xray_interop.rs` marks Xray→rust-reality
  (`stock_xray_client_udp_echo_via_rust_reality_entry`) `#[ignore]` so default
  nextest cannot green-pass a missing fixture; Exact-head Native pins stock
  Xray, sets `XRAY_BIN`, and runs that one test with `--ignored --exact`,
  failing closed on skip/zero cases. rust-reality→Xray stays ignored historical
  and is never part of the mandatory filter.
- Optimizations that preserve Xray-client ingress remain in scope; work whose
  only purpose is rust-reality→Xray server fidelity is out of scope.
- Mandatory rust↔rust UDP/443 + genuine HTTP/3 over XUDP is enforced by
  Exact-head Native via `tests/quic_h3_udp443_e2e.rs` (capability-gated;
  fail-closed without bind privilege).

- Mandatory adversarial XUDP lifecycle and routing qualification is enforced by
  Exact-head Native via `tests/xudp_adversarial_lifecycle.rs` (rewrite security,
  GlobalID ownership/capacity, incomplete frames, payload bounds, cancel/recovery,
  malformed/pressure, fail-detection demos).

\n