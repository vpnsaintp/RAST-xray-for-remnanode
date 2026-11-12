# ADR 0031: Handoff transfers KeyUpdate-capable TLS state

- Status: Accepted
- Date: 2026-10-06

## Context

RFC 8446 KeyUpdate evolves each directional application traffic secret with
`HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)`. A resumed Handoff
session therefore cannot continue correctly from only the currently derived
AEAD key and IV: it must retain the current traffic secret, its record sequence,
and whether a received `update_requested` still requires a response.

The version-1 continuation blob carried derived `TrafficKeys` and sequences.
Keeping those fields beside the generation secret would create two canonical
representations of one live record generation, widen secret lifetime, and allow
the representations to diverge. Reconstructing a synthetic traffic secret from
a key and IV is cryptographically impossible.

ADR 0005 retained continuation-state version 1 because its sequence-boundary
change did not alter the encoded state. KeyUpdate does alter the state required
to resume a session, so that compatibility decision no longer applies to the
continuation-state version. Its sequence-zero-or-one boundary remains in force.

## Decision

Keep the `HND1` framing and Handoff protocol version 1. Replace the encrypted
continuation blob with the one current state contract, version 2. In each
direction it carries exactly:

- the current application traffic secret, whose length is the negotiated
  suite hash length;
- the next record sequence under that secret.

The blob also carries one strict `0`/`1` value recording whether the server
writer owes the peer a KeyUpdate response, followed by the existing user,
destination, pending ciphertext, and prefetched plaintext fields. Derived AEAD
keys and IVs are not serialized.

Export consumes each live record layer. Decoding owns each traffic secret once,
and installation moves those secrets into replacement record layers; temporary
zero-valued secrets exist only as drop-safe replacements inside the consuming
zeroizing continuation value. Secrets, serialized plaintext, and intermediate
key material remain redacted from `Debug` and are zeroized on drop.

A landing derives the current cipher and IV from the transferred secret before
installing its transferred sequence. Later KeyUpdate derives the next secret,
key, IV, and cipher completely before replacing live state, then resets the
sequence to zero. A derivation failure leaves the old generation unchanged.
An ambiguous or cancelled record write instead poisons the writer's record
layer, preventing further output, rekeying, or export of uncertain state.

Version 1 is not accepted alongside version 2. A header state-version mismatch
returns `HandoffError::Version` before body reading, replay reservation, or
authentication work. An authenticated blob with an inconsistent inner version
returns `HandoffError::State`. Both close silently with zero response bytes,
before destination DNS or connect. There is no version-dispatched parser.

## Consequences

Handoff round trips preserve future KeyUpdate capability rather than only the
current AEAD generation. A request received immediately before transfer still
produces its required response after landing. There is no optional secret,
TrafficKeys-based continuation API, compatibility parser, or duplicated
key-plus-secret representation.

The encrypted blob size changes by cipher suite, but remains within the existing
bounded message cap. Every reachable LINE→LANDING pair must implement the same
continuation-state contract. Matching configuration or release family alone is
insufficient. Credential-rotation overlap does not accept old state versions.

Upgrade and rollback cross an admission-and-drain boundary: stop new sessions,
drain or terminate active sessions and retire unused warm connections, deploy
matching endpoints, then reopen admission. Isolated cohorts may coexist only
when routing cannot cross contracts. An older binary cannot import version-2
state or assume ownership of a live resumed session. Sessions survive only
while their original owners remain running. The current operator contract is
documented in [Handoff](../en/configuration/handoff.md), not a migration archive.
