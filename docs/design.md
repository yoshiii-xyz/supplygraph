# Design

## Pipeline

The report pipeline has five bounded stages:

1. Read `Cargo.lock` into an exact package and dependency index.
2. Run `cargo metadata --format-version 1 --locked` when an explicit or
   adjacent manifest exists.
3. Parse each explicitly named local evidence file.
4. Join evidence to packages by package name and exact version.
5. Sort packages, edges, and diagnostics before rendering text or JSON.

The process does not contact a remote advisory service and does not edit the
manifest, lockfile, or evidence files.

## Cargo inputs

`Cargo.lock` supplies exact package versions, source identifiers, registry
checksums, and lockfile dependency strings. Cargo metadata supplies package
license fields, license file paths, dependency declarations, workspace
membership, resolved package IDs, selected features, and dependency kinds.

When metadata is unavailable, the tool falls back to lockfile packages and
marks the report incomplete because directness and feature resolution are not
known.

## Evidence inputs

All evidence is local and optional. The command flags are:

```text
--advisories PATH
--audits PATH
--licenses PATH
--binary PATH
```

Advisories use a small OSV-compatible JSON subset. The file may be an array of
advisories, an object with an `advisories` array, or one advisory object. Each
advisory ID must be unique. Exact affected versions and `SEMVER` range events
are evaluated. A malformed range event is an input error.

Audits use a deliberately small local TOML shape:

```toml
[audits]
serde = [
  { version = "1.0.228", criteria = ["safe-to-run"] },
  { violation = "<1.0.0" },
]
```

Each record has exactly one of `version`, `delta`, or `violation`. A positive
record contributes criteria. A matching violation produces a risk finding.
This is not a claim of full `cargo-vet` file compatibility.

License evidence is JSON:

```json
{
  "packages": [
    {
      "name": "serde",
      "version": "1.0.228",
      "license": "MIT OR Apache-2.0"
    }
  ]
}
```

The imported license string is compared with Cargo's declared `license`
string when both exist. A mismatch is a conflict. Cargo's separate
`license_file` field is reported as metadata and is not treated as a conflict
with `license`.

Binary evidence is JSON:

```json
{
  "packages": [
    {
      "name": "supplygraph",
      "version": "0.1.0",
      "binaries": ["supplygraph"]
    }
  ]
}
```

Binary records show supplied names only. They do not prove how a binary was
built or which source produced it.

## Report model

Every package has a source kind of `workspace`, `path`, `registry`, `git`, or
`unknown`. Registry packages include a lockfile checksum state of `present` or
`missing`. Git and path packages use `not-applicable` for checksum state.

Each edge includes the dependency name, normal/build/dev kind, optional target,
declared features, and whether default features are enabled. A package is
direct when its resolved package ID is named by a workspace member's resolved
dependency list. Other resolved packages are transitive.

The JSON schema version is `1`. Fields are sorted through deterministic data
structures and explicit sort keys. Absolute workspace paths are reduced to a
stable placeholder or a workspace-relative path before serialization.

## Status semantics

The highest-severity diagnostic determines report status:

| Status | Meaning | Exit |
| --- | --- | --- |
| `complete` | No risk, incomplete, or unresolved diagnostics | 0 |
| `risk` | An advisory, audit violation, or license conflict is present | 2 |
| `incomplete` | Required evidence is absent or a checksum or record is missing | 3 |
| `unresolved` | Package identity, source, or evidence could not be resolved | 3 |

Supplying an empty evidence database is different from omitting it. An empty
database lets the tool report absence for that evidence source. An omitted
database produces a not-supplied diagnostic.
