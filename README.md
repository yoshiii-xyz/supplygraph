# supplygraph

Local Rust supply-chain evidence engine.

Status: released `v0.1.0`.

## Install

From crates.io:

```text
cargo install supplygraph --locked
```

From a checkout:

```text
cargo install --path . --locked
```

## Quick start

```text
supplygraph explain serde
supplygraph inspect Cargo.lock
supplygraph export --format json
```

Add local evidence when it is available:

```text
supplygraph explain serde \
  --advisories fixtures/advisories.json \
  --audits fixtures/audits.toml \
  --licenses fixtures/licenses.json \
  --binary fixtures/binary.json
```

## What it solves

Rust dependency review often has several separate evidence sources. `supplygraph`
joins package identity, dependency edges, Cargo source and checksum data,
advisory matches, license metadata, selected features, audit records, and
binary evidence into one deterministic report.

The report answers which package was selected, where Cargo resolved it from,
which evidence was supplied, which package edges are direct or transitive, and
which conclusions remain unresolved.

## How it works

The tool reads `Cargo.lock` and invokes `cargo metadata --format-version 1
--locked` when a nearby or explicit `Cargo.toml` is available. Optional local
evidence files are parsed without network access. Reports are sorted by stable
package, edge, and diagnostic keys.

Supported local evidence formats are documented in
[`docs/design.md`](docs/design.md). The sample files in `fixtures/` are small
shape examples, not a current vulnerability database.

## Commands and output

- `explain PACKAGE` shows matching package versions and incoming and outgoing
  edges.
- `inspect LOCKFILE` shows the complete graph report.
- `export` emits the graph report and defaults to JSON.

Use `--format text` for a human-readable report or `--format json` for a
machine-readable report. Exit status `0` means the report is complete, `2`
means a risk finding is present, and `3` means evidence is incomplete,
unresolved, or the command failed. A report is still printed for normal
incomplete, unresolved, and risk results.

## Safety and data handling

The tool reads the requested lockfile, manifest metadata, and explicitly named
evidence files. It does not download advisory databases, send telemetry, or
retain a local cache. Absolute workspace paths are redacted in report fields;
license file paths are reduced to a filename. Do not pass secrets or private
audit material into tracked fixtures or committed output.

## Limits and non-goals

See [`docs/limits.md`](docs/limits.md). This MVP is not a resolver, package
manager, remote database client, binary provenance attestor, license lawyer,
or replacement for `cargo-deny` or `cargo-vet`. It does not add a frontend,
hosted service, cloud backend, telemetry, or broad compatibility promise.

## Testing and development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the local gates and
[`docs/release.md`](docs/release.md) for the release protocol.

## License

MIT. See [`LICENSE`](LICENSE).
