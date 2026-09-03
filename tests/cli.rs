use std::{fs, path::PathBuf, process::Command};

use supplygraph::{EvidencePaths, explain, inspect, render_json};

#[test]
fn inspect_current_lockfile_is_deterministic_json() {
    let lockfile = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let first = inspect(
        &lockfile,
        Some(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")),
        &EvidencePaths::default(),
    )
    .expect("inspect report");
    let second = inspect(
        &lockfile,
        Some(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")),
        &EvidencePaths::default(),
    )
    .expect("inspect report");
    assert_eq!(
        render_json(&first).expect("json"),
        render_json(&second).expect("json")
    );
    assert!(first.packages.iter().any(|package| package.name == "serde"));
    assert!(!first.edges.is_empty());
}

#[test]
fn explain_unknown_package_is_unresolved() {
    let lockfile = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let report = explain(
        &lockfile,
        "not-a-real-package",
        None,
        &EvidencePaths::default(),
    )
    .expect("explain report");
    assert_eq!(report.status, "unresolved");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "package-not-found")
    );
}

#[test]
fn cli_export_defaults_to_json_and_keeps_evidence_states() {
    let output = Command::new(env!("CARGO_BIN_EXE_supplygraph"))
        .args(["export", "--lockfile", "Cargo.lock"])
        .output()
        .expect("export command");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["tool"], "supplygraph");
    assert_eq!(value["evidence_sources"]["advisories"], "not-supplied");
}

#[test]
fn cli_explain_renders_text_and_separates_stderr() {
    let output = Command::new(env!("CARGO_BIN_EXE_supplygraph"))
        .args(["explain", "serde", "--lockfile", "Cargo.lock"])
        .output()
        .expect("explain command");
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("supplygraph schema=1"));
    assert!(text.contains("package_query: serde"));
    assert!(output.stderr.is_empty());
}

#[test]
fn license_fixture_can_be_imported_for_a_matching_package() {
    let path = std::env::temp_dir().join(format!(
        "supplygraph-license-{}-{}.json",
        std::process::id(),
        "serde"
    ));
    let contents =
        r#"{"packages":[{"name":"serde","version":"1.0.228","license":"MIT OR Apache-2.0"}]}"#;
    fs::write(&path, contents).expect("write license fixture");
    assert_eq!(
        fs::read_to_string(&path).expect("read license fixture"),
        contents
    );
    let lockfile = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let report = explain(
        &lockfile,
        "serde",
        None,
        &EvidencePaths {
            licenses: Some(path),
            ..EvidencePaths::default()
        },
    )
    .expect("explain report");
    assert!(report.matches.iter().any(|package| package.name == "serde"));
}
