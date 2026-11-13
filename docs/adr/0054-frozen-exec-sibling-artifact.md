# ADR 0054: Frozen executable sibling artifact

Status: Accepted

## Context

Frozen run `38093809868` on `4241e78` completed packages, KVM probe, shared
QEMU prepare, all four QEMU cells, and merge (ADR 0051 Class B payload path
already green). Step 9 (`Verify frozen executable identities before execution`)
then failed with:

```text
Invalid frozen executable path
```

The `hosted-qemu-campaign-*` zip still contained top-level `rust-reality` /
`rr-dev` / `xray` / `openssl` whose digests match `evidence.json` identity.
Those binaries are zip entries near the end, after ~26 GiB / ~45k files of
four-cell trees. Campaign download on the failing job logged no digest-complete
line (package receipts on the same job did). Prior same-sized campaigns on
`96ea8bc` passed this verify, so this is a Class B restore reliability hazard
for trailing top-level files inside a huge artifact, not Class A product
failure and not a repeat of ADR 0053 `host_kernel` (that path never ran).

Historical `4241e78` / `38093809868` verdict remains immutable.

## Decision

1. Keep the historical full `hosted-qemu-campaign-${HEAD_SHA}` artifact for
   merge evidence and cell trees.
2. After merge copies identity executables into the campaign root, also stage
   and upload `hosted-qemu-frozen-exec-${HEAD_SHA}` containing only
   `rr-dev`, `rust-reality`, `xray`, `openssl`, and `environment.json`.
3. Frozen acceptance restores the campaign, then restores the frozen-exec
   artifact into the same bundle path so verify and native receipts bind
   executables from the small sibling even if trailing campaign entries are
   missing locally.
4. Verify failures MUST name which identity key failed and whether the path
   exists / is a symlink / is a file (plus a short top-level listing).

## Consequences and limits

Frozen step 9 no longer depends solely on extracting trailing binaries from a
26 GiB campaign zip. This does not slim the campaign artifact, does not change
identity digests, does not authorize sleep or Python CI shells, and does not
relabel `38093809868` as PASS.
