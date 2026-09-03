# Security policy

## Scope

Report security issues in the code, release artifacts, evidence parsers, or
workflow configuration. The tool is local and does not provide a hosted
service.

## Reporting

Do not include secrets, private audit records, or sensitive lockfiles in a
public issue. Use the repository's private security reporting channel when it
is available. If it is not available, open a minimal public issue that only
describes the affected version and a safe reproduction summary.

Please include the version, operating system, Rust toolchain, command, input
shape, and observed behavior. Redact private paths and package data.

## Handling

Maintainers will acknowledge a report when they can reproduce it, assess the
impact, and publish a fix or mitigation with a changelog entry. Do not run the
tool against production data as part of a report.
