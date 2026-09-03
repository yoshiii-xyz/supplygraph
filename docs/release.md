# Release process

The release target is `v0.1.0`. This file is the operational record to follow
for every published version.

## Local gates

From the repository root, run:

```text
git diff --check
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked
cargo package --locked
cargo publish --dry-run --locked
cargo audit
cargo audit --file fuzz/Cargo.lock
```

Run the bounded fuzz smoke test with a hard wall-clock limit:

```text
timeout --foreground 60s env RUSTUP_TOOLCHAIN=nightly cargo fuzz run policy -- -max_total_time=10 -verbosity=0 -print_final_stats=1
```

The command must exit `0` before the 60 second limit and report no crash.

Inspect the package archive with `cargo package --list --locked`. Record the
archive hash and exact command outputs in the private ignored file
`qa/evidence/iteration-YYYY-MM-DD.md`.

## Publication order

1. Review the full diff and local evidence record.
2. Commit on `main` only after the local gates pass.
3. Push `main` and wait for CI, security, and CodeQL workflows.
4. Publish the crate with `cargo publish --locked` when the package and dry
   run gates pass.
5. Verify the crate and docs are reachable from crates.io and docs.rs.
6. Push an annotated `v0.1.0` tag.
7. Wait for the tag package workflow and create the GitHub release with the
   changelog.
8. Download the published crate independently, hash it, install it into a
   fresh temporary `CARGO_HOME`, and run the CLI smoke commands.
9. Record commit, tag, workflow URLs, artifact hashes, and known limits.

## Hosted gates

The required main-branch checks are `checks`, `audit`, and `analyze`. The
repository settings must require one approving review, dismiss stale reviews,
enforce the rules for administrators, require a current branch, enforce
linear history and conversation resolution, and disallow force pushes and
deletions.

The repository must enable vulnerability alerts, Dependabot security updates,
secret scanning, and push protection. Dependabot update pull requests are
reviewed as maintenance work after the release; they are not silently closed.

## Release evidence

A release is complete only when local and hosted gates pass, the working tree
is clean, the artifact is independently verified, and the evidence record
states exactly what was not tested. Human usability, adoption, and physical
device validation remain outside this project's release claim.
