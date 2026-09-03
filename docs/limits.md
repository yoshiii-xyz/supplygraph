# Limits and non-goals

This document describes what the MVP does not establish.

- Advisory evidence is only as current as the local file supplied by the
  caller. The tool does not fetch, refresh, or authenticate an advisory DB.
- The advisory matcher covers exact versions and the implemented `SEMVER`
  event subset. Unsupported range types are unresolved, not silently treated
  as safe.
- A checksum proves that Cargo recorded a checksum for a registry package. It
  does not prove that the source was reviewed or that a build used that exact
  source.
- A declared or imported license string is not legal advice. The MVP compares
  strings and does not evaluate SPDX expression compatibility, license files,
  notices, exceptions, or obligations.
- Audit records are a small local format. They are not a complete import of
  `cargo-vet`, and a positive record does not prove a reviewer identity or
  review quality.
- Binary evidence records presence and names supplied by the caller. It does
  not attest to build inputs, reproducibility, signatures, or runtime origin.
- Missing evidence is surfaced as incomplete. It is not converted into a
  positive assertion that a package is safe.
- The tool does not resolve dependency requirements, modify Cargo files,
  inspect compiled machine code, or run a package's build script.
- The tool does not provide a server, database, dashboard, remote cache,
  telemetry, or user account system.
- Human usability studies, adoption measurement, and physical-device checks
  are outside the MVP validation boundary.
