# ADR 0074: Attribute TCP protocol proof to a verified PROXY source

Status: Accepted

## Context

ADR 0073 distinguishes destination records from proof that a user sent a
specific application protocol. A public bridge can carry the original client
address in a PROXY v1 header, but a bare socket peer address or an unverified
header must not be presented as a verified customer source. Torrent activity
monitoring needs a bounded, auditable proof with no logged payload or peer ID.

## Decision

The authenticated Vision TCP uplink checks only the first 20 decrypted
client-to-destination bytes for `0x13` followed by `BitTorrent protocol`. The
incremental detector holds one prefix position, never a copy of the payload.
The entry emits one `protocol_detected` Info event only after the matching
bytes have been forwarded and only when the session has a positive numeric
panel user ID and its source came from a successfully parsed, loopback-only
PROXY v1 prelude. The source provenance is passed explicitly from the public
connection handler; it is never inferred from the IP value. The event contains
the configured entry tag, panel ID, verified source IP, destination, fixed
protocol/proof strings, and no payload, peer ID, or info hash.

The detector observes prefetched and subsequent Vision-framed uplink writes
and bytes already pending at a Direct handoff. Once the raw Direct relay owns
the sockets, it does not inspect later bytes. It does not inspect UDP/XUDP or
uTP. A matching prefix completed only in that later raw phase is not reported.
The downstream operator collector treats this proof as notification-only
until its own attribution and action policy pass a safe live canary.

## Consequences

The hot path adds no payload allocation and logs at most one protocol event
per eligible session. The event is stronger than a route or peer-density
heuristic, but it is narrower than a full Xray protocol verdict and does not
prove a file transfer or its volume. A Direct raw-prefix inspection would
require a separately measured liveness and performance change to the raw
relay boundary; it is deliberately outside this decision.
