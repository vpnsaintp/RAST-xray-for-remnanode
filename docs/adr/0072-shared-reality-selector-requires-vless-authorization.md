# ADR 0072: A shared REALITY selector requires VLESS user authorization

Status: Accepted

## Context

Remnawave subscriptions commonly distribute one REALITY short ID to many
different VLESS UUIDs. The previous Rust server assigned each short ID to
exactly one UUID. That model rejected otherwise valid stock Xray and Mihomo
clients from a panel-managed subscription.

## Decision

An entry may declare `reality.sharedShortIds`. Each such short ID authenticates
the REALITY handshake but does not identify a user. After VLESS decoding, the
request UUID must belong to the same immutable configuration snapshot's user
registry. Exclusively owned per-user short IDs keep their exact-owner check.
The two selector sets may not overlap. A user with no exclusive short ID is
valid only while at least one shared short ID is configured.

Reload replaces the selector index and the user registry as one generation;
an existing session retains the generation that admitted it. A panel adapter
must remove expired or revoked UUIDs from the next generation. This decision
does not make the short ID a substitute for the VLESS UUID, and it does not
authorize a client missing from the current registry.

## Consequences

The per-connection selector lookup clones one enum value; the shared variant
clones an `Arc` to the registry. This has to be included in the fork's
performance measurements. The panel adapter and per-user accounting remain
separate implementation work and are required before production use.
