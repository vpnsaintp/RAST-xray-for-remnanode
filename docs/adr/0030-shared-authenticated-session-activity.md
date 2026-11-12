# ADR 0030: Shared authenticated session activity

Status: Accepted

## Context

A direction-local read deadline is not connection inactivity. In particular,
SSE, WebSocket, gRPC streaming, long HTTP responses and SSH-like asymmetric
streams can have a quiet uplink while the downlink remains healthy, or the
reverse. Using the fallback lifetime for such a deadline also crosses the
authentication boundary: fallback policy must not govern authenticated data.

The comparison reference is Xray-core commit
`b26a91de4f3294e26a0ad0a970b81a386a41f789`: `common/signal/timer.go`,
`common/buf/copy.go`, VLESS inbound/outbound, Freedom and `proxy/proxy.go`.
Its shared ActivityTimer, UpdateActivity copy hooks, EOF-driven half-close
transitions and long raw/splice backstop establish the relevant distinction.
We do not copy its exact timeout values or socket ownership model.

## Decision

The neutral I/O activity module owns a shared observation-only object; it
exposes no transport or protocol capability. TLS application I/O and raw
transport both report progress to it. The Vision runtime adapter owns one
connection-level coordinator. Every successful nonempty socket read,
partial write or splice operation marks activity once. A relaxed atomic flag
avoids clock reads, locks, allocations and cross-direction timer resets on
progress. The coordinator samples every five minutes, reclaiming completely
inactive framed sessions within two sampling windows. This deliberately trades
exact idle-deadline precision for a cheap, bounded observation mechanism.

A raw ownership transfer monotonically disables that coordinator for the
whole connection, including a still-framed peer direction. Both buffered and
splice raw transfers use ordinary TCP lifetime, the existing kernel keepalive
policy and admission/FD limits, not directional read-idle deadlines. A live,
quiet raw peer may retain its admitted resources indefinitely; that is a valid
connection, not grounds to manufacture an EOF. No extra leak timer is added.

Pending writes have a separate, fixed 120-second stall bound, renewed only
after actual partial-write progress. Opposite-direction activity cannot excuse
a stuck write. EOF shuts down only that direction; existing transfer-ledger,
resource-release and abort-guard rules still govern real errors. No short
post-FIN deadline is introduced: the remaining direction may drain normally.

The pre-authentication, authenticated request handshake, connect, cover,
fallback, DNS, replay and admission contracts are unchanged. Configuration has
no new fields, aliases or normalization. In particular, fallbackTimeoutMs
continues to control fallback lifetime only, not authenticated inactivity.

## Validation and tradeoffs

Focused tests exercise framed Handoff continuation, asymmetric and alternating
traffic, directional and bilateral raw relays, Linux splice, FIN draining,
actual write stalls, fail-closed errors, and paused-time whole-session
inactivity/raw-transition behavior. A counted-allocator test pins zero
allocations for activity progress; the existing TLS allocation gates remain.

There is one shared allocation per session plus constant-sized atomic state.
An I/O progress event adds one relaxed store; no per-byte work, task, mutex,
clock query or timer operation is added. Raw reads lose their timer polling.
This is a lifecycle correctness correction, not a claimed throughput
optimization; per-write accounting also records partial progress before an
error instead of waiting for an entire buffer to finish.
