# Contributing

Keep changes inside the product brief. The project is a focused Rust CLI and
library. Do not add a frontend, hosted service, cloud backend, telemetry, or
unrelated compatibility surface.

## Local gates

Run these commands from the repository root:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked
cargo package --locked
cargo audit
```

When changing fuzz support, also run the bounded command in
[`docs/release.md`](docs/release.md). Record exact outputs and any validation
limit in the private `qa/evidence/` record.

## Change discipline

Plan the change and define a testable success condition. Read back every
changed file. Add a focused test for a new parser or report rule. Keep output
deterministic and avoid absolute paths in serialized evidence.

Review `git diff --check` and the complete diff before committing. Commits and
pushes are made only after the applicable gates pass and the repository owner
has reviewed the changes.

## Evidence formats

New evidence formats need a documented schema, malformed-input tests, and an
explicit statement of whether missing evidence changes the report status.
Prefer a small local fixture over network access in tests.
