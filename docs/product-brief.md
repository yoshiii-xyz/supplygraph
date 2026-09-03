# Product brief

## Mission

Explain why a Rust dependency is acceptable by joining source, checksum,
advisory, license, audit, feature, and binary evidence.

## Target user

The target user is a Rust maintainer or reviewer who already has a local
`Cargo.lock`, a manifest, and one or more locally generated evidence files.
The user needs a deterministic report that keeps positive evidence separate
from missing or conflicting evidence.

## MVP commands

```text
supplygraph explain serde
supplygraph inspect Cargo.lock
supplygraph export --format json
```

Each command accepts optional local evidence paths for advisories, audits,
licenses, and binary records. `explain` filters the complete report to one
package name and includes incoming and outgoing graph edges.

## First evidence nodes

The MVP reports these nodes and relationships:

- package identity and exact version
- dependency edges and dependency kind
- Cargo source URL and lockfile checksum
- active advisory state from a local JSON database
- Cargo license metadata and optional imported license evidence
- active feature selection and declared dependency features
- local audit record presence, criteria, or violation
- direct versus transitive use
- binary evidence presence and named binaries
- unresolved evidence and explicit missing evidence

## Acceptance criteria

The implementation must:

1. Parse a lockfile and, when available, Cargo metadata without mutating the
   project.
2. Join multiple versions, git dependencies, path dependencies, missing
   checksums, advisory matches, malformed audits, license conflicts, feature
   edges, and local evidence fixtures.
3. Produce stable text and JSON output for the same inputs.
4. Use exit status `0` for complete reports, `2` for risk reports, and `3`
   for incomplete, unresolved, or command-error results.
5. Redact absolute workspace paths from serialized report fields.
6. Keep the evidence model distinct from package resolution and from the
   policy vocabularies of larger tools.

## Explicit non-goals

This project does not add a frontend, hosted service, cloud backend,
telemetry, remote evidence fetching, package resolution, binary attestation,
legal license interpretation, or broad compatibility promises. Human
usability and physical-device validation are outside this MVP.
