# Research notes

Research was recorded on 2026-09-03. The sources below are primary or
maintainer documentation for the input formats used by this MVP.

## Cargo metadata and lockfiles

The [Cargo metadata reference](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)
defines the JSON fields used for package identity, source, license metadata,
dependency declarations, resolved nodes, dependency kinds, and features. The
implementation requests format version 1 with `--locked` and treats IDs as
opaque strings except where it needs stable package labels.

The [Cargo lockfile guide](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html)
and [Cargo lockfile schema](https://doc.rust-lang.org/nightly/nightly-rustc/src/cargo_util_schemas/lockfile.rs.html)
document exact versions, package sources, checksums, and lockfile dependency
entries. That evidence supports the MVP's source and checksum fields without
turning the tool into a resolver.

## Advisories

[RustSec](https://rustsec.org/) describes the Rust security advisory ecosystem
and [the advisory database README](https://github.com/rustsec/advisory-db/blob/main/README.md)
describes the advisory records commonly consumed by Rust tooling.

The [OSV schema](https://ossf.github.io/osv-schema/) provides the ecosystem,
package, affected version, and range-event model used by the local advisory
parser. The MVP imports a JSON subset locally, preserves unresolved range
types as unresolved, and does not fetch or claim freshness for a database.

## Audits and licenses

The [Cargo Vet configuration reference](https://mozilla.github.io/cargo-vet/config.html)
and [recording audits guide](https://mozilla.github.io/cargo-vet/recording-audits.html)
show why package version and criteria are useful evidence dimensions. The MVP
uses a smaller, explicit local format so it does not pretend to be a complete
Cargo Vet implementation or duplicate its policy engine.

The [SPDX license expression specification](https://github.com/spdx/spdx-spec/blob/develop/docs/annexes/spdx-license-expressions.md)
and [`spdx` expression API](https://docs.rs/spdx/latest/spdx/expression/struct.Expression.html)
support treating license strings as structured identifiers in future work.
This release records and compares strings only. It does not make legal or
expression-compatibility judgments.

## Design decisions

- Use Cargo's own metadata and lockfile as the identity boundary.
- Keep evidence sources local and explicit so missing evidence is visible.
- Use exact package and version joins so multiple versions remain distinct.
- Emit JSON and text from one report model so deterministic ordering applies to
  both formats.
- Keep the audit and license joins narrow enough to explain their limits.
- Keep binary evidence descriptive rather than presenting an unverified
  provenance claim.
