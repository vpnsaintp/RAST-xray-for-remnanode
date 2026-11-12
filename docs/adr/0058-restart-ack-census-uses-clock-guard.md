# ADR 0058: Restart ACK/census ordering uses clock_guard across guests

Status: Accepted

## Context

Frozen run `38145481092` on `6f0cc67` fail-closed `handoff/ordinary` with
Class B `landing abort ACK predates LINE-A census` after `rtt-100-loss-1`.
The other three QEMU cells PASS. Retained receipts show a correct ACK-driven
handshake (ADR 0041 / 0047) on the wire:

| Event | unix_ms (guest) |
|---|---|
| LANDING ACK receive completed | 1791731119695 |
| LINE-A `ss` census completed | 1791731119696 |
| LINE-A ACK send started | 1791731119696 |
| LINE-A ACK send completed | 1791731119738 |

Same-guest LINE-A ordering is sound: census completion ≤ ACK send start.
LANDING's receive completing one millisecond "before" LINE-A's census is
impossible on a shared clock and is cross-guest REALTIME skew (each guest is
only bound to the host within `clock_max_offset_ms`). ADR 0047 correctly
switched the barrier to census command time, but still compared absolute
timestamps from two guests without the project's established `clock_guard_ms`
uncertainty.

## Decision

1. Keep ADR 0047's census command time (not LINE-A action completion).
2. Keep same-guest `restart_ingress` checks (census ≤ ACK send start; peer/boot match).
3. Offline `product_logs` orders LANDING ACK vs LINE-A census with
   `ack_completed + clock_guard_ms >= census_completed` via
   `restart_ack_follows_census`. Inversion beyond the guard still fail-closes.
4. No sleep, hold, or wall-clock amplification. Runtime handshake unchanged.

## Consequences

Harness Class B from 1 ms cross-guest inversion is removed without loosening
product checks: empty census, peer mismatch, same-guest ACK-before-census,
and missing ACK still fail closed. Historical INVALID evidence stays immutable.
