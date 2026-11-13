# ADR 0053: Native identity environment omits host_kernel

Status: Accepted

## Context

Frozen run `38083242003` on `96ea8bc` completed all four QEMU cells, merge
evaluation, lifecycle receipts (ADR 0052), and local-full-gate, then failed
**Step 11** (`native-interop` / mechanism / pressure / resources) instantly with:

```text
missing field `host_kernel` at line 5 column 1
```

Identity-bound `environment.json` after ADR 0042 contains only pinned tool
digests (`xray_sha256`, `xray_identity`, `openssl_sha256`). Per-runner `uname`
lives in non-identity `controller-host.json` so matrix cells share one
environment digest. Offline `native_interop::Environment` still required
`host_kernel` on that same identity file and treated emptiness as a bind
failure. Class B harness schema drift, not Class A product failure. Exact-head
Native PASS does not exercise this Frozen identity-environment parse path.
Historical `96ea8bc` / `38083242003` verdict remains immutable.

## Decision

1. Keep ADR 0042: identity `environment.json` binds tool digests only;
   `controller-host.json` retains observational `host_kernel`.
2. `native_interop::Environment` accepts missing `host_kernel` (`#[serde(default)]`)
   and still accepts legacy receipts that embed it.
3. Binding helpers and `verify` require non-empty Xray/OpenSSL digests and
   identity strings; they MUST NOT require `host_kernel`.
4. Unit fixtures and parse regressions use the ADR 0042 digest-only shape.

## Consequences and limits

Frozen native interop/mechanism/pressure/resources can Pass once the evaluator
matches the identity file ADR 0042 already freezes. This does not move kernel
strings back into the identity digest, does not loosen external-image binding,
and does not authorize sleep or Python CI shells.
