# ADR 0075: Import external proxy features through owned protocol boundaries

Status: Accepted

## Context

The `wsq222222/xray-fork` prototype adds TLS, WebSocket, Shadowsocks and DNS
over TLS around a Rust Xray-compatible implementation. Its source at
`cb2f0c790a93704ed571ed0af462c29f2a882268` is a useful reference, but
its listener, outbound and control paths have different ownership from this
repository. In particular, this repository already owns Handoff and NXR,
global admission, dynamic users, verified source attribution, and a
`directSourceIp` guarantee for direct TCP, UDP and DNS traffic. Replacing the
runtime wholesale would discard these independently tested properties.

## Decision

This repository remains the canonical implementation. Import each externally
useful protocol behavior into its owning layer: syntax and validation under
`src/config/`, wire parsing under `src/protocol/`, runtime admission and
accounting under `src/server/`, and transport I/O under `src/transport/`.
External source is a reference, not a second runtime or a compatibility mode.

For every imported listener or outbound, authentication and resource admission
must precede expensive work. A new direct egress path must bind the configured
source IPv4, or fail closed, for TCP, UDP and resolver traffic. A transport must
preserve the existing VLESS/REALITY/Vision path and Firefox client fingerprint.
Per-user traffic, online IPs, revocation and torrent proof must remain
attributable under the RemnaNode adapter. A feature is not accepted merely
because its parser compiles: it needs protocol tests, parser fuzz coverage,
an authenticated client test, and a paired performance comparison with the
current release.

Any source copied from the external MPL-2.0 project retains its original
notices and file-level license. The separately modified RemnaNode adapter
remains AGPL-3.0; neither license is silently assigned to this Rust crate.

## Consequences

TLS, WebSocket, Shadowsocks and DNS over TLS can be added independently.
Their availability in the external prototype does not establish support here.
The official fork preserves a reviewable upstream history, while this
repository accepts only tested changes. A raw TCP relay such as Nginx stream
is an operational bridge alternative, not an implementation of RemnaNode
control or user accounting on the entry server.
