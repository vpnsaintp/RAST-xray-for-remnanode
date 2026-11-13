# ADR 0055: Relocated OpenSSL uses colocated OPENSSL_CONF

Status: Accepted

## Context

Frozen run `38102035607` on `8a04c04` completed packages, KVM probe, shared
QEMU prepare, all four QEMU cells, merge, frozen-exec identity verify
(ADR 0054), full gate, and lifecycle. Native interop then failed immediately:

```text
Can't open "<RUNNER_TEMP>/rr-qemu-prepare/tools/openssl/ssl/openssl.cnf"
for reading, No such file or directory
```

`openssl req` could not mint the cover CA, so `required-native-interop/output.json`
stayed empty and mechanism / pressure / resources never ran.

Root cause is Class B packaging/path, not product TLS:

1. Prepare builds OpenSSL 3.5.6 with `--openssldir=$RUNNER_TEMP/rr-qemu-prepare/tools/openssl/ssl`,
   baking that absolute `OPENSSLDIR` into the binary.
2. Campaign / frozen-exec historically copied only `tools/openssl/bin/openssl`.
3. Receipts host has neither that absolute tree nor a colocated `openssl.cnf`.
4. `OPENSSL_CONF` was never set by `rr-dev` when launching the fixture openssl.

QEMU cells still succeed because they restore the full prepare prefix where the
baked `OPENSSLDIR` exists. Historical `38102035607` verdict remains immutable.

## Decision

1. Stage `openssl.cnf` next to campaign / frozen-exec `openssl` (copied from the
   prepare install `ssl/openssl.cnf`).
2. `rr-dev` resolves a colocated config (flat sibling, `ssl/openssl.cnf`, or
   install-layout `../ssl/openssl.cnf`) and sets child `OPENSSL_CONF` when the
   process environment does not already define it. Certificate minting and
   long-lived `s_server` covers both apply the same pairs.
3. Frozen identity verify fails closed if `openssl.cnf` is missing next to the
   frozen `openssl` binary.
4. Do not rewrite the openssl binary digest via a relative `--openssldir` solely
   for this Class B; `OPENSSL_CONF` is the portable relocation contract.

## Consequences and limits

Frozen native interop no longer depends on prepare-runner absolute paths for
OpenSSL config. This does not change openssl binary digests, does not authorize
sleep or Python CI shells, does not dispatch Frozen from agents, and does not
relabel `38102035607` as PASS.
