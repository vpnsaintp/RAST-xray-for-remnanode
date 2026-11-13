# ADR 0057: ThreadSanitizer stays; Vision accumulation uses current_thread

Status: Accepted

## Context

Branch rulesets still require the Security job named
`Replay and warm-transport race sanitizer`. ADR 0035 removed that job on the
stability lineage after Tokio I/O registration repeatedly reported under
ThreadSanitizer; `main` never absorbed that removal, so restoring the job was
required to merge the integration branch without weakening the ruleset.

On `integrate/next-release`, the restored job failed on
`server::vision::tests::three_downlink_chunks_accumulate` (Security run
38138910790). Both stacks stayed inside `tokio-1.53.0`: one thread allocated
`Arc<ScheduledIo>` during `TcpListener::bind` (`tcp_pair` → `open_framed`),
while a multi-thread worker called `ScheduledIo::set_readiness`. No
`rust-reality` product atomics appeared. The same job on `main` stays green
because `main` has no non-ignored `multi_thread` Vision test; this accumulation
proof was added later for the 600-second matrix scaffolding and does not need
worker threads for its sequential chunk contract.

## Decision

1. Keep the ThreadSanitizer job and its fail-closed `halt_on_error=1` contract.
   Do not delete the suite, do not introduce suppression files, and do not
   rename a TSan failure as success.
2. Run `three_downlink_chunks_accumulate` on `current_thread`, matching the
   other non-ignored Vision proofs. Ignored multi-thread diagnostics and the
   ignored 600-second matrix retain `multi_thread` where concurrency is the
   point of the test.
3. ADR 0035's removal of the gate is superseded for job presence: the ruleset
   and this ADR restore active TSan coverage. ADR 0035's prohibition on
   suppressions and on reclassifying historical failures remains in force.

## Consequences

Product concurrent races (replay winner, Handoff/NXR/outbound/pre-auth/
warm-pool/Vision current-thread proofs) stay under TSan. A future non-ignored
test that truly requires `multi_thread` plus Tokio TCP registration must either
prove the race is product-owned or isolate the harness without suppressions.
ASan/LSan, fuzzing, and ordinary suites are unchanged.

## References

- [ADR 0035](0035-remove-thread-sanitizer-gate.md)
- Security job failure: https://github.com/jacek4yang/rust-reality/actions/runs/38138910790/job/114468486637
- [Tokio ScheduledIo](https://docs.rs/tokio/1.53.0/tokio/)
