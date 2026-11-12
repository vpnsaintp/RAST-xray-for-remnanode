# RemnaNode adapter patch

`rust-node-adapter.patch` changes five files in the Remnawave Node 3.4.1 pilot
source to keep Rust-core reload acknowledgement, node health, dynamic-user
updates and traffic accounting consistent. It is a patch for the archived
pilot source, not a patch guaranteed to apply to the current upstream `main`.
`baseline-hashes.json` records the SHA-256 preimage and result for each changed
file without including the private pilot archive.

The patch passed `git apply --check` against that baseline. Its isolated Node
test suite passed 11/11, and TypeScript type checking and formatting passed.
The Rust core and this Node adapter were subsequently combined for an
owner/tester pilot; that does not complete all release gates listed in the
root `REVIEW.md`.

The underlying Remnawave Node source and this modification are distributed
under AGPL-3.0. The license text is included as `LICENCE-AGPL-3.0`.

Source project: <https://github.com/remnawave/node>.
