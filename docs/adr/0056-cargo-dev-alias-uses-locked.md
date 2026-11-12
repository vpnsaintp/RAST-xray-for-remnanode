# ADR 0056: `cargo dev` alias uses `--locked`

Status: Accepted

## Context

Native Exact-head on integration PR #279 head `08a5f56` failed Class B during
`cargo dev perf freeze`:

```text
perf freeze: worktree is not clean, so the artifact would not match <sha>:
 M tools/Cargo.lock
```

CI / Security / Candidate packages had already passed on that SHA.

Root cause is bootstrap order, not freeze's own `--locked` production build:

1. Root `.cargo/config.toml` defined `dev = "run --quiet --manifest-path tools/Cargo.toml …"` **without** `--locked`.
2. Qualification invokes `cargo dev perf freeze`, which expands to unlocked `cargo run` against the `tools/` workspace.
3. After production Hickory moved to 0.26.3, `tools/Cargo.lock` still recorded path-dep transitive `hickory-*` at 0.26.1. Unlocked resolution rewrote the lock **before** freeze's clean-worktree check ran.
4. Freeze correctly refused to build a dirty tree; the dirt was created by the unlocked alias itself.

Historical Native FAIL on `08a5f56` remains immutable evidence. Relabeling it PASS is forbidden.

## Decision

1. The root `cargo dev` alias MUST pass `--locked` to `cargo run` so bootstrap cannot rewrite `tools/Cargo.lock`.
2. `tools/Cargo.lock` MUST stay consistent with the tools manifest and path-dep resolution under `--locked` (refresh via unlocked resolution only when intentionally updating the lock, then commit).
3. `cargo dev repo check` asserts the `[alias] dev` value contains `--locked` so the contract cannot regress silently.
4. Freeze continues to refuse dirty worktrees and continues to build the production binary with `--locked`; this ADR does not weaken either check.

## Consequences and limits

CI/Native freeze can no longer dirty the worktree merely by starting `rr-dev`.
Developers who need to refresh `tools/Cargo.lock` must do so explicitly (for
example unlocked `cargo generate-lockfile --manifest-path tools/Cargo.toml` or
an equivalent scoped update) and commit the result. This does not authorize
sleep, Python CI shells, Frozen dispatch from agents, tag/publish, or claiming
`08a5f56` Native PASS.
