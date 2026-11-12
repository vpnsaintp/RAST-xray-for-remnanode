# ADR 0073: Keep panel accounting on a local read-only boundary

Status: Accepted

## Context

A panel-managed VLESS identity needs traffic attribution, online status and
destination evidence. A Handoff entry knows the real client IP but the landing
owns the transferred plaintext data path. The proxy must remain independent of
panel credentials and control-plane availability.

## Decision

An entry user may carry a positive numeric `panelUserId`. The Handoff landing
may map the same UUID to that ID in `accountingUsers`. Session counters live
across immutable config generations and count successful application writes.
The entry does not count transferred Handoff bytes; the landing does. The entry
emits destination events with the panel ID and original client IP for operator
monitoring.

The core exposes cumulative counters, online IPs, boot identity, generation and
active panel IDs through a private mode `0600` Unix socket. It does not accept
management commands over that socket. A separate adapter owns panel polling,
durable cursors, identity updates, and the `SIGHUP` reload acknowledgement.
The core retains no panel API token or billing state.

## Consequences

Panel availability does not interrupt the data path. Cumulative snapshots
avoid discarding bytes when a reader disconnects, but a core crash can lose
bytes since the prior poll. The panel reset API has no separate acknowledgement:
if a response is lost after the adapter advances its durable cursor, that
interval can also be missed. A restarted consumer must detect the new boot ID
and surface that accounting gap. Destination records provide attribution, not
proof of torrent protocol use.
