use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Default)]
pub struct EvidencePaths {
    pub advisories: Option<PathBuf>,
    pub audits: Option<PathBuf>,
    pub licenses: Option<PathBuf>,
    pub binary: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AdvisoryMatch {
    pub id: String,
    pub summary: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AuditMatch {
    pub selector: String,
    pub kind: String,
    pub criteria: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PackageReport {
    pub name: String,
    pub version: String,
    pub source_kind: String,
    pub source: String,
    pub source_ref: String,
    pub checksum: Option<String>,
    pub checksum_state: String,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub license_evidence: Option<String>,
    pub license_state: String,
    pub advisories: Vec<AdvisoryMatch>,
    pub advisory_state: String,
    pub features: Vec<String>,
    pub audit_records: Vec<AuditMatch>,
    pub audit_state: String,
    pub audit_criteria: Vec<String>,
    pub binary_state: String,
    pub binary_names: Vec<String>,
    pub direct: bool,
    pub workspace_member: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub dependency_name: String,
    pub kind: String,
    pub target: Option<String>,
    pub features: Vec<String>,
    pub uses_default_features: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: String,
    pub code: String,
    pub package: Option<String>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GraphReport {
    pub schema_version: u8,
    pub tool: String,
    pub status: String,
    pub workspace: String,
    pub lockfile: String,
    pub evidence_sources: BTreeMap<String, String>,
    pub packages: Vec<PackageReport>,
    pub edges: Vec<GraphEdge>,
    pub diagnostics: Vec<Diagnostic>,
}

impl GraphReport {
    pub fn exit_code(&self) -> i32 {
        status_exit_code(&self.status)
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ExplainReport {
    pub schema_version: u8,
    pub tool: String,
    pub status: String,
    pub package_query: String,
    pub evidence_sources: BTreeMap<String, String>,
    pub matches: Vec<PackageReport>,
    pub incoming: Vec<GraphEdge>,
    pub outgoing: Vec<GraphEdge>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ExplainReport {
    pub fn exit_code(&self) -> i32 {
        status_exit_code(&self.status)
    }
}

#[derive(Debug)]
pub enum SupplyError {
    Io(String),
    Cargo(String),
    Metadata(String),
    Lockfile(String),
    Advisory(String),
    Audit(String),
    License(String),
    Binary(String),
}

impl std::fmt::Display for SupplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(detail) => write!(formatter, "I/O error: {detail}"),
            Self::Cargo(detail) => write!(formatter, "cargo metadata failed: {detail}"),
            Self::Metadata(detail) => write!(formatter, "invalid cargo metadata: {detail}"),
            Self::Lockfile(detail) => write!(formatter, "invalid Cargo.lock evidence: {detail}"),
            Self::Advisory(detail) => write!(formatter, "invalid advisory evidence: {detail}"),
            Self::Audit(detail) => write!(formatter, "invalid audit evidence: {detail}"),
            Self::License(detail) => write!(formatter, "invalid license evidence: {detail}"),
            Self::Binary(detail) => write!(formatter, "invalid binary evidence: {detail}"),
        }
    }
}

impl std::error::Error for SupplyError {}

#[derive(Clone, Debug, Deserialize)]
struct MetadataDocument {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
    workspace_root: String,
    resolve: Option<ResolveDocument>,
}

#[derive(Clone, Debug, Deserialize)]
struct MetadataPackage {
    name: String,
    version: String,
    id: String,
    source: Option<String>,
    manifest_path: String,
    license: Option<String>,
    license_file: Option<String>,
    #[serde(default)]
    dependencies: Vec<MetadataDependency>,
}

#[derive(Clone, Debug, Deserialize)]
struct MetadataDependency {
    name: String,
    source: Option<String>,
    rename: Option<String>,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    uses_default_features: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct ResolveDocument {
    nodes: Vec<ResolveNode>,
}

#[derive(Clone, Debug, Deserialize)]
struct ResolveNode {
    id: String,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    deps: Vec<ResolveDependency>,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ResolveDependency {
    name: String,
    pkg: String,
    #[serde(default)]
    dep_kinds: Vec<ResolveDependencyKind>,
}

#[derive(Clone, Debug, Deserialize)]
struct ResolveDependencyKind {
    kind: Option<String>,
    target: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Lockfile {
    package: Option<Vec<LockPackage>>,
}

#[derive(Clone, Debug, Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    dependencies: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default)]
struct LockIndex {
    packages: BTreeMap<(String, String, Option<String>), LockEvidence>,
}

#[derive(Clone, Debug)]
struct LockEvidence {
    checksum: Option<String>,
    dependencies: Vec<String>,
}

#[derive(Clone, Debug)]
struct SourceInfo {
    kind: String,
    source: String,
    source_ref: String,
    checksum: Option<String>,
    checksum_state: String,
}

#[derive(Clone, Debug, Default)]
struct EvidenceData {
    advisories: Option<Vec<OsvAdvisory>>,
    audits: Option<Vec<(String, AuditRecord)>>,
    licenses: Option<Vec<LicenseRecord>>,
    binaries: Option<Vec<BinaryRecord>>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvAdvisory {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    withdrawn: Option<serde_json::Value>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AuditRecord {
    kind: String,
    selector: String,
    criteria: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct LicenseRecord {
    name: String,
    version: String,
    license: String,
}

#[derive(Clone, Debug, Deserialize)]
struct BinaryRecord {
    name: String,
    version: String,
    #[serde(default)]
    binaries: Vec<String>,
}

pub fn inspect(
    lockfile_path: &Path,
    manifest_path: Option<&Path>,
    evidence_paths: &EvidencePaths,
) -> Result<GraphReport, SupplyError> {
    let candidate_manifest = manifest_path
        .map(Path::to_path_buf)
        .or_else(|| infer_manifest_path(lockfile_path));
    let metadata = match candidate_manifest.as_deref() {
        Some(path) if path.exists() => Some(run_cargo_metadata(path)?),
        _ => None,
    };
    let effective_lockfile = if lockfile_path.exists() {
        lockfile_path.to_path_buf()
    } else if let Some(metadata) = metadata.as_ref() {
        PathBuf::from(&metadata.workspace_root).join("Cargo.lock")
    } else {
        lockfile_path.to_path_buf()
    };
    let lock = load_lockfile(&effective_lockfile)?;
    let evidence = load_evidence(evidence_paths)?;
    Ok(build_report(
        metadata.as_ref(),
        &lock,
        &effective_lockfile,
        &evidence,
    ))
}

pub fn explain(
    lockfile_path: &Path,
    package_query: &str,
    manifest_path: Option<&Path>,
    evidence_paths: &EvidencePaths,
) -> Result<ExplainReport, SupplyError> {
    let report = inspect(lockfile_path, manifest_path, evidence_paths)?;
    let matches = report
        .packages
        .iter()
        .filter(|package| package.name == package_query)
        .cloned()
        .collect::<Vec<_>>();
    let labels = matches.iter().map(package_label).collect::<BTreeSet<_>>();
    let incoming = report
        .edges
        .iter()
        .filter(|edge| labels.contains(&edge.to))
        .cloned()
        .collect::<Vec<_>>();
    let outgoing = report
        .edges
        .iter()
        .filter(|edge| labels.contains(&edge.from))
        .cloned()
        .collect::<Vec<_>>();
    let mut diagnostics = report
        .diagnostics
        .into_iter()
        .filter(|diagnostic| {
            diagnostic.package.is_none() || diagnostic.package.as_deref() == Some(package_query)
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        diagnostics.push(Diagnostic {
            severity: "unresolved".to_owned(),
            code: "package-not-found".to_owned(),
            package: Some(package_query.to_owned()),
            detail: "package name was not present in the supplied Cargo evidence".to_owned(),
        });
    }
    sort_diagnostics(&mut diagnostics);
    let status = if matches.is_empty() {
        "unresolved".to_owned()
    } else {
        status_from_diagnostics(&diagnostics)
    };
    Ok(ExplainReport {
        schema_version: SCHEMA_VERSION,
        tool: "supplygraph".to_owned(),
        status,
        package_query: package_query.to_owned(),
        evidence_sources: report.evidence_sources,
        matches,
        incoming,
        outgoing,
        diagnostics,
    })
}

pub fn render_json<T: Serialize>(value: &T) -> serde_json::Result<String> {
    serde_json::to_string_pretty(value)
}

pub fn render_graph_text(report: &GraphReport) -> String {
    let mut output = String::new();
    output.push_str("supplygraph schema=1\n");
    output.push_str(&format!("status: {}\n", report.status));
    output.push_str(&format!("workspace: {}\n", report.workspace));
    output.push_str(&format!("lockfile: {}\n", report.lockfile));
    append_evidence_sources(&mut output, &report.evidence_sources);
    output.push_str(&format!("packages: {}\n", report.packages.len()));
    for package in &report.packages {
        append_package_text(&mut output, package);
    }
    output.push_str(&format!("edges: {}\n", report.edges.len()));
    for edge in &report.edges {
        output.push_str(&format!(
            "- {} -> {} dep={} kind={} target={} features={} default_features={}\n",
            edge.from,
            edge.to,
            edge.dependency_name,
            edge.kind,
            optional_value(edge.target.as_deref()),
            list_value(&edge.features),
            edge.uses_default_features
        ));
    }
    append_diagnostics(&mut output, &report.diagnostics);
    output
}

pub fn render_explain_text(report: &ExplainReport) -> String {
    let mut output = String::new();
    output.push_str("supplygraph schema=1\n");
    output.push_str(&format!("status: {}\n", report.status));
    output.push_str(&format!("package_query: {}\n", report.package_query));
    append_evidence_sources(&mut output, &report.evidence_sources);
    if report.matches.is_empty() {
        output.push_str("matches: none\n");
    } else {
        output.push_str(&format!("matches: {}\n", report.matches.len()));
        for package in &report.matches {
            append_package_text(&mut output, package);
        }
    }
    output.push_str(&format!("incoming_edges: {}\n", report.incoming.len()));
    for edge in &report.incoming {
        output.push_str(&format!(
            "- {} -> {} dep={}\n",
            edge.from, edge.to, edge.dependency_name
        ));
    }
    output.push_str(&format!("outgoing_edges: {}\n", report.outgoing.len()));
    for edge in &report.outgoing {
        output.push_str(&format!(
            "- {} -> {} dep={}\n",
            edge.from, edge.to, edge.dependency_name
        ));
    }
    append_diagnostics(&mut output, &report.diagnostics);
    output
}

fn build_report(
    metadata: Option<&MetadataDocument>,
    lock: &LockIndex,
    lockfile_path: &Path,
    evidence: &EvidenceData,
) -> GraphReport {
    let mut packages = Vec::new();
    let mut edges = Vec::new();
    let mut diagnostics = Vec::new();
    let mut evidence_sources = BTreeMap::new();
    evidence_sources.insert(
        "advisories".to_owned(),
        evidence_state(evidence.advisories.is_some()),
    );
    evidence_sources.insert(
        "audits".to_owned(),
        evidence_state(evidence.audits.is_some()),
    );
    evidence_sources.insert(
        "licenses".to_owned(),
        evidence_state(evidence.licenses.is_some()),
    );
    evidence_sources.insert(
        "binary".to_owned(),
        evidence_state(evidence.binaries.is_some()),
    );

    let (workspace, package_inputs, member_ids, direct_ids) = if let Some(metadata) = metadata {
        let member_ids = metadata
            .workspace_members
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let node_map = metadata
            .resolve
            .as_ref()
            .map(|resolve| {
                resolve
                    .nodes
                    .iter()
                    .map(|node| (node.id.clone(), node))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let mut direct_ids = BTreeSet::new();
        for member_id in &member_ids {
            if let Some(node) = node_map.get(member_id) {
                direct_ids.extend(node.dependencies.iter().cloned());
            }
        }
        if let Some(resolve) = metadata.resolve.as_ref() {
            for node in &resolve.nodes {
                let Some(from) = metadata
                    .packages
                    .iter()
                    .find(|package| package.id == node.id)
                else {
                    continue;
                };
                for dependency in resolve_dependencies(node) {
                    let Some(to) = metadata
                        .packages
                        .iter()
                        .find(|package| package.id == dependency.pkg)
                    else {
                        edges.push(GraphEdge {
                            from: metadata_package_label(from),
                            to: format!("<unresolved> {}", dependency.pkg),
                            dependency_name: dependency.name,
                            kind: "unresolved".to_owned(),
                            target: None,
                            features: Vec::new(),
                            uses_default_features: false,
                        });
                        continue;
                    };
                    let declaration =
                        find_dependency_declaration(from, &dependency.name, to.source.as_deref());
                    edges.push(GraphEdge {
                        from: metadata_package_label(from),
                        to: metadata_package_label(to),
                        dependency_name: dependency.name,
                        kind: dependency.kind,
                        target: dependency.target,
                        features: declaration
                            .map(|dependency| dependency.features.clone())
                            .unwrap_or_default(),
                        uses_default_features: declaration
                            .map(|dependency| dependency.uses_default_features)
                            .unwrap_or(false),
                    });
                }
            }
        } else {
            diagnostics.push(Diagnostic {
                severity: "incomplete".to_owned(),
                code: "resolve-not-supplied".to_owned(),
                package: None,
                detail: "Cargo metadata did not contain a resolved graph".to_owned(),
            });
        }
        (
            redact_absolute_path(&metadata.workspace_root),
            metadata
                .packages
                .iter()
                .map(|package| {
                    let node = node_map.get(&package.id).copied();
                    (PackageInput::Metadata(package), node)
                })
                .collect::<Vec<_>>(),
            member_ids,
            direct_ids,
        )
    } else {
        diagnostics.push(Diagnostic {
            severity: "incomplete".to_owned(),
            code: "metadata-not-supplied".to_owned(),
            package: None,
            detail: "no Cargo.toml was available to resolve package metadata".to_owned(),
        });
        let package_inputs = lock
            .packages
            .iter()
            .map(|((name, version, source), _evidence)| {
                (
                    LockOnlyPackage {
                        name: name.clone(),
                        version: version.clone(),
                        source: source.clone(),
                    },
                    None,
                )
            })
            .collect::<Vec<_>>();
        for ((name, version, _source), evidence) in &lock.packages {
            let from = format!("{name} {version}");
            for dependency in &evidence.dependencies {
                edges.push(GraphEdge {
                    from: from.clone(),
                    to: dependency_name_from_lock(dependency),
                    dependency_name: dependency_name_from_lock(dependency),
                    kind: "unknown".to_owned(),
                    target: None,
                    features: Vec::new(),
                    uses_default_features: false,
                });
            }
        }
        (
            "<unknown>".to_owned(),
            package_inputs
                .iter()
                .map(|package| (PackageInput::LockOnly(package.0.clone()), package.1))
                .collect::<Vec<_>>(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
    };

    for (package, node) in package_inputs {
        let (name, version, source, manifest_path, license, license_file, features, id) =
            match package {
                PackageInput::Metadata(package) => (
                    package.name.clone(),
                    package.version.clone(),
                    package.source.clone(),
                    Some(package.manifest_path.clone()),
                    package.license.clone(),
                    package.license_file.clone(),
                    node.map(|node| sorted_strings(node.features.clone()))
                        .unwrap_or_default(),
                    Some(package.id.clone()),
                ),
                PackageInput::LockOnly(package) => (
                    package.name,
                    package.version,
                    package.source,
                    None,
                    None,
                    None,
                    Vec::new(),
                    None,
                ),
            };
        let workspace_member = id.as_ref().is_some_and(|id| member_ids.contains(id));
        let direct = id.as_ref().is_some_and(|id| direct_ids.contains(id));
        let lock_evidence = lock
            .packages
            .get(&(name.clone(), version.clone(), source.clone()));
        let source_info = source_info(
            source.as_deref(),
            workspace_member,
            manifest_path.as_deref(),
            metadata.map(|metadata| metadata.workspace_root.as_str()),
            lock_evidence,
        );
        if source_info.kind == "unknown" {
            diagnostics.push(Diagnostic {
                severity: "unresolved".to_owned(),
                code: "source-unresolved".to_owned(),
                package: Some(name.clone()),
                detail: format!("could not classify source for {name} {version}"),
            });
        }
        if source_info.checksum_state == "missing" {
            diagnostics.push(Diagnostic {
                severity: "incomplete".to_owned(),
                code: "missing-checksum".to_owned(),
                package: Some(name.clone()),
                detail: "registry package has no checksum in Cargo.lock".to_owned(),
            });
        }
        let license_file = license_file.map(|value| redact_license_file(&value));
        let (license_evidence, license_state) = license_state(
            evidence.licenses.as_deref(),
            &name,
            &version,
            license.as_deref(),
            &mut diagnostics,
        );
        if license.is_none() && license_file.is_none() && license_state == "missing" {
            diagnostics.push(Diagnostic {
                severity: "incomplete".to_owned(),
                code: "missing-license".to_owned(),
                package: Some(name.clone()),
                detail: "package has no license or license-file metadata".to_owned(),
            });
        }
        let (advisories, advisory_state) = advisory_state(
            evidence.advisories.as_deref(),
            &name,
            &version,
            &mut diagnostics,
        );
        let (audit_records, audit_state, audit_criteria) = audit_state(
            evidence.audits.as_deref(),
            &name,
            &version,
            &mut diagnostics,
        );
        let (binary_state, binary_names) =
            binary_state(evidence.binaries.as_deref(), &name, &version);
        packages.push(PackageReport {
            name,
            version,
            source_kind: source_info.kind,
            source: source_info.source,
            source_ref: source_info.source_ref,
            checksum: source_info.checksum,
            checksum_state: source_info.checksum_state,
            license,
            license_file,
            license_evidence,
            license_state,
            advisories,
            advisory_state,
            features,
            audit_records,
            audit_state,
            audit_criteria,
            binary_state,
            binary_names,
            direct,
            workspace_member,
        });
    }
    packages.sort_by(|left, right| {
        (
            &left.name,
            &left.version,
            &left.source_kind,
            &left.source_ref,
        )
            .cmp(&(
                &right.name,
                &right.version,
                &right.source_kind,
                &right.source_ref,
            ))
    });
    add_multiple_version_diagnostics(&packages, &mut diagnostics);
    edges.sort_by(|left, right| {
        (
            &left.from,
            &left.to,
            &left.dependency_name,
            &left.kind,
            &left.target,
            &left.features,
        )
            .cmp(&(
                &right.from,
                &right.to,
                &right.dependency_name,
                &right.kind,
                &right.target,
                &right.features,
            ))
    });
    edges.dedup();
    add_missing_evidence_diagnostics(evidence, !packages.is_empty(), &mut diagnostics);
    sort_diagnostics(&mut diagnostics);
    let status = status_from_diagnostics(&diagnostics);
    GraphReport {
        schema_version: SCHEMA_VERSION,
        tool: "supplygraph".to_owned(),
        status,
        workspace,
        lockfile: redact_absolute_path(&lockfile_path.to_string_lossy()),
        evidence_sources,
        packages,
        edges,
        diagnostics,
    }
}

enum PackageInput<'a> {
    Metadata(&'a MetadataPackage),
    LockOnly(LockOnlyPackage),
}

#[derive(Clone, Debug)]
struct LockOnlyPackage {
    name: String,
    version: String,
    source: Option<String>,
}

fn resolve_dependencies(node: &ResolveNode) -> Vec<ResolvedDependency> {
    if node.deps.is_empty() {
        return node
            .dependencies
            .iter()
            .map(|pkg| ResolvedDependency {
                name: package_name_from_id(pkg),
                pkg: pkg.clone(),
                kind: "normal".to_owned(),
                target: None,
            })
            .collect();
    }
    let mut dependencies = Vec::new();
    for dependency in &node.deps {
        if dependency.dep_kinds.is_empty() {
            dependencies.push(ResolvedDependency {
                name: dependency.name.clone(),
                pkg: dependency.pkg.clone(),
                kind: "normal".to_owned(),
                target: None,
            });
        } else {
            for kind in &dependency.dep_kinds {
                dependencies.push(ResolvedDependency {
                    name: dependency.name.clone(),
                    pkg: dependency.pkg.clone(),
                    kind: kind.kind.clone().unwrap_or_else(|| "normal".to_owned()),
                    target: kind.target.clone(),
                });
            }
        }
    }
    dependencies
}

#[derive(Clone, Debug)]
struct ResolvedDependency {
    name: String,
    pkg: String,
    kind: String,
    target: Option<String>,
}

fn find_dependency_declaration<'a>(
    package: &'a MetadataPackage,
    name: &str,
    target_source: Option<&str>,
) -> Option<&'a MetadataDependency> {
    package.dependencies.iter().find(|dependency| {
        (dependency.name == name || dependency.rename.as_deref() == Some(name))
            && (dependency.source.is_none() || dependency.source.as_deref() == target_source)
    })
}

fn source_info(
    source: Option<&str>,
    workspace_member: bool,
    manifest_path: Option<&str>,
    workspace_root: Option<&str>,
    lock_evidence: Option<&LockEvidence>,
) -> SourceInfo {
    if workspace_member {
        return SourceInfo {
            kind: "workspace".to_owned(),
            source: "workspace".to_owned(),
            source_ref: "workspace".to_owned(),
            checksum: None,
            checksum_state: "not-applicable".to_owned(),
        };
    }
    let Some(source) = source else {
        return SourceInfo {
            kind: "path".to_owned(),
            source: "path".to_owned(),
            source_ref: match (manifest_path, workspace_root) {
                (Some(path), Some(root)) => display_path(Path::new(path), Path::new(root)),
                _ => "path".to_owned(),
            },
            checksum: None,
            checksum_state: "not-applicable".to_owned(),
        };
    };
    if source.starts_with("registry+") || source.starts_with("sparse+") {
        let endpoint = normalize_registry_endpoint(source);
        let label = if endpoint == "https://github.com/rust-lang/crates.io-index" {
            "crates.io".to_owned()
        } else {
            endpoint_display(&endpoint)
        };
        return SourceInfo {
            kind: "registry".to_owned(),
            source: label,
            source_ref: endpoint_display(&endpoint),
            checksum: lock_evidence.and_then(|evidence| evidence.checksum.clone()),
            checksum_state: if lock_evidence
                .and_then(|evidence| evidence.checksum.as_ref())
                .is_some()
            {
                "present".to_owned()
            } else {
                "missing".to_owned()
            },
        };
    }
    if source.starts_with("git+") {
        let source_ref = normalize_git_reference(source);
        return SourceInfo {
            kind: "git".to_owned(),
            source: source_ref.clone(),
            source_ref,
            checksum: None,
            checksum_state: "not-applicable".to_owned(),
        };
    }
    SourceInfo {
        kind: "unknown".to_owned(),
        source: "unknown".to_owned(),
        source_ref: source.to_owned(),
        checksum: None,
        checksum_state: "unresolved".to_owned(),
    }
}

fn advisory_state(
    advisories: Option<&[OsvAdvisory]>,
    name: &str,
    version: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<AdvisoryMatch>, String) {
    let Some(advisories) = advisories else {
        return (Vec::new(), "not-supplied".to_owned());
    };
    let mut matches = Vec::new();
    for advisory in advisories {
        if advisory.withdrawn.is_some() {
            continue;
        }
        let mut affected = false;
        for entry in &advisory.affected {
            if entry.package.ecosystem != "crates.io" || entry.package.name != name {
                continue;
            }
            if entry.versions.iter().any(|candidate| candidate == version) {
                affected = true;
                break;
            }
            for range in &entry.ranges {
                match range_matches(range, version) {
                    Ok(true) => {
                        affected = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(detail) => diagnostics.push(Diagnostic {
                        severity: "unresolved".to_owned(),
                        code: "advisory-range-unresolved".to_owned(),
                        package: Some(name.to_owned()),
                        detail,
                    }),
                }
            }
            if affected {
                break;
            }
        }
        if affected {
            matches.push(AdvisoryMatch {
                id: advisory.id.clone(),
                summary: advisory.summary.clone(),
            });
        }
    }
    matches.sort_by(|left, right| (&left.id, &left.summary).cmp(&(&right.id, &right.summary)));
    matches.dedup();
    if matches.is_empty() {
        (matches, "none".to_owned())
    } else {
        diagnostics.push(Diagnostic {
            severity: "risk".to_owned(),
            code: "active-advisory".to_owned(),
            package: Some(name.to_owned()),
            detail: format!(
                "active local advisory records: {}",
                matches
                    .iter()
                    .map(|advisory| advisory.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
        (matches, "present".to_owned())
    }
}

fn range_matches(range: &OsvRange, version: &str) -> Result<bool, String> {
    if range.kind != "SEMVER" {
        return Err(format!(
            "cannot evaluate {} advisory range for Cargo version {version}",
            range.kind
        ));
    }
    let version = Version::parse(version)
        .map_err(|error| format!("invalid Cargo version {version}: {error}"))?;
    let mut events = Vec::new();
    for event in &range.events {
        let values = [
            event.introduced.as_ref(),
            event.fixed.as_ref(),
            event.last_affected.as_ref(),
            event.limit.as_ref(),
        ];
        if values.iter().filter(|value| value.is_some()).count() != 1 {
            return Err("OSV range event must contain exactly one boundary".to_owned());
        }
        let (kind, value) = if let Some(value) = event.introduced.as_ref() {
            (0_u8, value)
        } else if let Some(value) = event.fixed.as_ref() {
            (1_u8, value)
        } else if let Some(value) = event.last_affected.as_ref() {
            (2_u8, value)
        } else {
            (3_u8, event.limit.as_ref().expect("validated limit"))
        };
        let parsed =
            if value == "0" || value == "*" {
                None
            } else {
                Some(Version::parse(value).map_err(|error| {
                    format!("invalid SEMVER advisory boundary {value}: {error}")
                })?)
            };
        events.push((parsed, kind, value.clone()));
    }
    events.sort_by(|left, right| (&left.0, left.1, &left.2).cmp(&(&right.0, right.1, &right.2)));
    let mut vulnerable = false;
    for (boundary, kind, raw) in events {
        match kind {
            0 => {
                if raw == "0"
                    || boundary
                        .as_ref()
                        .is_some_and(|boundary| version >= *boundary)
                {
                    vulnerable = true;
                }
            }
            1 => {
                if boundary
                    .as_ref()
                    .is_some_and(|boundary| version >= *boundary)
                {
                    vulnerable = false;
                }
            }
            2 => {
                if boundary
                    .as_ref()
                    .is_some_and(|boundary| version > *boundary)
                {
                    vulnerable = false;
                }
            }
            3 => {
                if raw != "*"
                    && boundary
                        .as_ref()
                        .is_some_and(|boundary| version >= *boundary)
                {
                    vulnerable = false;
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(vulnerable)
}

fn audit_state(
    audits: Option<&[(String, AuditRecord)]>,
    name: &str,
    version: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<AuditMatch>, String, Vec<String>) {
    let Some(audits) = audits else {
        return (Vec::new(), "not-supplied".to_owned(), Vec::new());
    };
    let mut records = Vec::new();
    let mut criteria = BTreeSet::new();
    let mut violation = false;
    for (package_name, record) in audits {
        if package_name != name || !audit_selector_matches(record, version) {
            continue;
        }
        if record.kind == "violation" {
            violation = true;
        } else {
            criteria.extend(record.criteria.iter().cloned());
        }
        records.push(AuditMatch {
            selector: record.selector.clone(),
            kind: record.kind.clone(),
            criteria: sorted_strings(record.criteria.clone()),
        });
    }
    records.sort_by(|left, right| {
        (&left.kind, &left.selector, &left.criteria).cmp(&(
            &right.kind,
            &right.selector,
            &right.criteria,
        ))
    });
    records.dedup();
    let criteria = criteria.into_iter().collect::<Vec<_>>();
    if violation {
        diagnostics.push(Diagnostic {
            severity: "risk".to_owned(),
            code: "audit-violation".to_owned(),
            package: Some(name.to_owned()),
            detail: "matching local audit record marks this package as a violation".to_owned(),
        });
        (records, "violation".to_owned(), criteria)
    } else if records.is_empty() {
        diagnostics.push(Diagnostic {
            severity: "incomplete".to_owned(),
            code: "audit-record-absent".to_owned(),
            package: Some(name.to_owned()),
            detail: "no matching local audit record was supplied".to_owned(),
        });
        (records, "absent".to_owned(), criteria)
    } else {
        (records, "present".to_owned(), criteria)
    }
}

fn audit_selector_matches(record: &AuditRecord, version: &str) -> bool {
    match record.kind.as_str() {
        "version" => record.selector == version,
        "delta" => record
            .selector
            .split_once("->")
            .is_some_and(|(_, right)| right.trim() == version),
        "violation" => {
            record.selector == "*"
                || VersionReq::parse(&record.selector)
                    .ok()
                    .and_then(|requirement| {
                        Version::parse(version)
                            .ok()
                            .map(|version| requirement.matches(&version))
                    })
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn license_state(
    licenses: Option<&[LicenseRecord]>,
    name: &str,
    version: &str,
    declared: Option<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Option<String>, String) {
    let Some(licenses) = licenses else {
        return (
            None,
            if declared.is_some() {
                "declared".to_owned()
            } else {
                "missing".to_owned()
            },
        );
    };
    let evidence = licenses
        .iter()
        .find(|record| record.name == name && record.version == version);
    let Some(evidence) = evidence else {
        diagnostics.push(Diagnostic {
            severity: "incomplete".to_owned(),
            code: "license-evidence-absent".to_owned(),
            package: Some(name.to_owned()),
            detail: "no matching local license evidence was supplied".to_owned(),
        });
        return (None, "external-missing".to_owned());
    };
    if let Some(declared) = declared {
        if declared != evidence.license {
            diagnostics.push(Diagnostic {
                severity: "risk".to_owned(),
                code: "license-conflict".to_owned(),
                package: Some(name.to_owned()),
                detail: format!(
                    "Cargo metadata declares `{declared}` but local evidence declares `{}`",
                    evidence.license
                ),
            });
            return (Some(evidence.license.clone()), "conflict".to_owned());
        }
        (Some(evidence.license.clone()), "verified".to_owned())
    } else {
        (Some(evidence.license.clone()), "external-only".to_owned())
    }
}

fn binary_state(
    binaries: Option<&[BinaryRecord]>,
    name: &str,
    version: &str,
) -> (String, Vec<String>) {
    let Some(binaries) = binaries else {
        return ("not-supplied".to_owned(), Vec::new());
    };
    let mut names = binaries
        .iter()
        .filter(|record| record.name == name && record.version == version)
        .flat_map(|record| record.binaries.clone())
        .collect::<Vec<_>>();
    names = sorted_strings(names);
    names.dedup();
    if names.is_empty() {
        ("absent".to_owned(), names)
    } else {
        ("present".to_owned(), names)
    }
}

fn add_missing_evidence_diagnostics(
    evidence: &EvidenceData,
    has_packages: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !has_packages {
        return;
    }
    if evidence.advisories.is_none() {
        diagnostics.push(Diagnostic {
            severity: "incomplete".to_owned(),
            code: "advisories-not-supplied".to_owned(),
            package: None,
            detail: "no local advisory database was supplied; absence of findings is unknown"
                .to_owned(),
        });
    }
    if evidence.audits.is_none() {
        diagnostics.push(Diagnostic {
            severity: "incomplete".to_owned(),
            code: "audits-not-supplied".to_owned(),
            package: None,
            detail: "no local audit record database was supplied".to_owned(),
        });
    }
    if evidence.licenses.is_none() {
        diagnostics.push(Diagnostic {
            severity: "incomplete".to_owned(),
            code: "licenses-not-supplied".to_owned(),
            package: None,
            detail: "no external license evidence was supplied; Cargo metadata is reported as-is"
                .to_owned(),
        });
    }
    if evidence.binaries.is_none() {
        diagnostics.push(Diagnostic {
            severity: "incomplete".to_owned(),
            code: "binary-evidence-not-supplied".to_owned(),
            package: None,
            detail: "binary provenance was not supplied".to_owned(),
        });
    }
}

fn add_multiple_version_diagnostics(packages: &[PackageReport], diagnostics: &mut Vec<Diagnostic>) {
    let mut versions = BTreeMap::<String, BTreeSet<String>>::new();
    for package in packages {
        versions
            .entry(package.name.clone())
            .or_default()
            .insert(package.version.clone());
    }
    for (name, versions) in versions {
        if versions.len() > 1 {
            diagnostics.push(Diagnostic {
                severity: "info".to_owned(),
                code: "multiple-versions".to_owned(),
                package: Some(name),
                detail: format!(
                    "{} versions are present: {}",
                    versions.len(),
                    versions.into_iter().collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }
}

fn load_evidence(paths: &EvidencePaths) -> Result<EvidenceData, SupplyError> {
    Ok(EvidenceData {
        advisories: paths
            .advisories
            .as_deref()
            .map(load_advisories)
            .transpose()?,
        audits: paths.audits.as_deref().map(load_audits).transpose()?,
        licenses: paths.licenses.as_deref().map(load_licenses).transpose()?,
        binaries: paths.binary.as_deref().map(load_binaries).transpose()?,
    })
}

fn load_advisories(path: &Path) -> Result<Vec<OsvAdvisory>, SupplyError> {
    let contents = fs::read_to_string(path).map_err(|error| SupplyError::Io(error.to_string()))?;
    let value: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|error| SupplyError::Advisory(error.to_string()))?;
    let advisories = if value.is_array() {
        serde_json::from_value::<Vec<OsvAdvisory>>(value)
    } else if value.get("advisories").is_some() {
        value
            .get("advisories")
            .cloned()
            .ok_or_else(|| serde_json::Error::io(std::io::Error::other("missing advisories")))
            .and_then(serde_json::from_value::<Vec<OsvAdvisory>>)
    } else {
        serde_json::from_value::<OsvAdvisory>(value).map(|advisory| vec![advisory])
    }
    .map_err(|error| SupplyError::Advisory(error.to_string()))?;
    let mut ids = BTreeSet::new();
    for advisory in &advisories {
        if advisory.id.is_empty() || !ids.insert(advisory.id.clone()) {
            return Err(SupplyError::Advisory(
                "advisory IDs must be nonempty and unique".to_owned(),
            ));
        }
        for affected in &advisory.affected {
            for range in &affected.ranges {
                for event in &range.events {
                    let count = [
                        event.introduced.as_ref(),
                        event.fixed.as_ref(),
                        event.last_affected.as_ref(),
                        event.limit.as_ref(),
                    ]
                    .iter()
                    .filter(|value| value.is_some())
                    .count();
                    if count != 1 {
                        return Err(SupplyError::Advisory(
                            "OSV range events must contain exactly one boundary".to_owned(),
                        ));
                    }
                }
            }
        }
    }
    Ok(advisories)
}

fn load_audits(path: &Path) -> Result<Vec<(String, AuditRecord)>, SupplyError> {
    let contents = fs::read_to_string(path).map_err(|error| SupplyError::Io(error.to_string()))?;
    let value: toml::Value =
        toml::from_str(&contents).map_err(|error| SupplyError::Audit(error.to_string()))?;
    let Some(audits) = value.get("audits") else {
        return Ok(Vec::new());
    };
    let Some(audits) = audits.as_table() else {
        return Err(SupplyError::Audit("[audits] must be a table".to_owned()));
    };
    let mut records = Vec::new();
    for (package, entries) in audits {
        let Some(entries) = entries.as_array() else {
            return Err(SupplyError::Audit(format!(
                "audits.{package} must be an array"
            )));
        };
        for entry in entries {
            let Some(entry) = entry.as_table() else {
                return Err(SupplyError::Audit(format!(
                    "audits.{package} entry must be a table"
                )));
            };
            let mut selectors = Vec::new();
            for kind in ["version", "delta", "violation"] {
                if let Some(value) = entry.get(kind) {
                    let Some(value) = value.as_str() else {
                        return Err(SupplyError::Audit(format!(
                            "audits.{package}.{kind} must be a string"
                        )));
                    };
                    selectors.push((kind, value.to_owned()));
                }
            }
            if selectors.len() != 1 {
                return Err(SupplyError::Audit(format!(
                    "audits.{package} entry must contain exactly one of version, delta, or violation"
                )));
            }
            let (kind, selector) = selectors.remove(0);
            if kind == "delta" && selector.split_once("->").is_none() {
                return Err(SupplyError::Audit(format!(
                    "audits.{package}.delta must use `old -> new` form"
                )));
            }
            if kind == "violation" && selector != "*" && VersionReq::parse(&selector).is_err() {
                return Err(SupplyError::Audit(format!(
                    "audits.{package}.violation is not a valid Cargo version requirement"
                )));
            }
            let criteria = match entry.get("criteria") {
                None => Vec::new(),
                Some(value) if value.is_str() => {
                    vec![value.as_str().unwrap_or_default().to_owned()]
                }
                Some(value) if value.is_array() => value
                    .as_array()
                    .expect("array checked")
                    .iter()
                    .map(|value| {
                        value.as_str().map(str::to_owned).ok_or_else(|| {
                            SupplyError::Audit(format!(
                                "audits.{package}.criteria entries must be strings"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                Some(_) => {
                    return Err(SupplyError::Audit(format!(
                        "audits.{package}.criteria must be a string or array"
                    )));
                }
            };
            records.push((
                package.clone(),
                AuditRecord {
                    kind: kind.to_owned(),
                    selector,
                    criteria: sorted_strings(criteria),
                },
            ));
        }
    }
    records.sort_by(|left, right| {
        (&left.0, &left.1.kind, &left.1.selector).cmp(&(&right.0, &right.1.kind, &right.1.selector))
    });
    Ok(records)
}

fn load_licenses(path: &Path) -> Result<Vec<LicenseRecord>, SupplyError> {
    let contents = fs::read_to_string(path).map_err(|error| SupplyError::Io(error.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|error| SupplyError::License(error.to_string()))?;
    let packages = value.get("packages").cloned().ok_or_else(|| {
        SupplyError::License("license evidence requires a packages array".to_owned())
    })?;
    let records = serde_json::from_value::<Vec<LicenseRecord>>(packages)
        .map_err(|error| SupplyError::License(error.to_string()))?;
    let mut keys = BTreeSet::new();
    for record in &records {
        if record.name.is_empty() || record.version.is_empty() || record.license.is_empty() {
            return Err(SupplyError::License(
                "license evidence records require name, version, and license".to_owned(),
            ));
        }
        if !keys.insert((record.name.clone(), record.version.clone())) {
            return Err(SupplyError::License(
                "license evidence package records must be unique".to_owned(),
            ));
        }
    }
    Ok(records)
}

fn load_binaries(path: &Path) -> Result<Vec<BinaryRecord>, SupplyError> {
    let contents = fs::read_to_string(path).map_err(|error| SupplyError::Io(error.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|error| SupplyError::Binary(error.to_string()))?;
    let packages = value.get("packages").cloned().ok_or_else(|| {
        SupplyError::Binary("binary evidence requires a packages array".to_owned())
    })?;
    let records = serde_json::from_value::<Vec<BinaryRecord>>(packages)
        .map_err(|error| SupplyError::Binary(error.to_string()))?;
    let mut keys = BTreeSet::new();
    for record in &records {
        if !keys.insert((record.name.clone(), record.version.clone())) {
            return Err(SupplyError::Binary(
                "binary evidence package records must be unique".to_owned(),
            ));
        }
    }
    Ok(records)
}

fn load_lockfile(path: &Path) -> Result<LockIndex, SupplyError> {
    let contents = fs::read_to_string(path).map_err(|error| SupplyError::Io(error.to_string()))?;
    let lockfile: Lockfile =
        toml::from_str(&contents).map_err(|error| SupplyError::Lockfile(error.to_string()))?;
    let mut index = LockIndex::default();
    for package in lockfile.package.unwrap_or_default() {
        let key = (package.name, package.version, package.source);
        if index
            .packages
            .insert(
                key.clone(),
                LockEvidence {
                    checksum: package.checksum,
                    dependencies: package.dependencies.unwrap_or_default(),
                },
            )
            .is_some()
        {
            return Err(SupplyError::Lockfile(format!(
                "duplicate package entry for {} {}",
                key.0, key.1
            )));
        }
    }
    Ok(index)
}

fn run_cargo_metadata(manifest_path: &Path) -> Result<MetadataDocument, SupplyError> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .map_err(|error| SupplyError::Cargo(error.to_string()))?;
    if !output.status.success() {
        return Err(SupplyError::Cargo(clean_process_output(&output.stderr)));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| SupplyError::Metadata(error.to_string()))
}

fn infer_manifest_path(lockfile_path: &Path) -> Option<PathBuf> {
    let parent = lockfile_path.parent().unwrap_or_else(|| Path::new("."));
    let manifest = parent.join("Cargo.toml");
    manifest.exists().then_some(manifest)
}

fn evidence_state(supplied: bool) -> String {
    if supplied {
        "supplied".to_owned()
    } else {
        "not-supplied".to_owned()
    }
}

fn status_from_diagnostics(diagnostics: &[Diagnostic]) -> String {
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == "unresolved")
    {
        "unresolved".to_owned()
    } else if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == "risk")
    {
        "risk".to_owned()
    } else if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == "incomplete")
    {
        "incomplete".to_owned()
    } else {
        "complete".to_owned()
    }
}

fn status_exit_code(status: &str) -> i32 {
    match status {
        "complete" => 0,
        "risk" => 2,
        _ => 3,
    }
}

fn sort_diagnostics(diagnostics: &mut [Diagnostic]) {
    diagnostics.sort_by(|left, right| {
        (&left.severity, &left.code, &left.package, &left.detail).cmp(&(
            &right.severity,
            &right.code,
            &right.package,
            &right.detail,
        ))
    });
}

fn package_label(package: &PackageReport) -> String {
    format!("{} {}", package.name, package.version)
}

fn metadata_package_label(package: &MetadataPackage) -> String {
    format!("{} {}", package.name, package.version)
}

fn package_name_from_id(id: &str) -> String {
    id.split('#')
        .next_back()
        .and_then(|value| value.split('@').next())
        .unwrap_or(id)
        .to_owned()
}

fn dependency_name_from_lock(value: &str) -> String {
    value.split_whitespace().next().unwrap_or(value).to_owned()
}

fn normalize_registry_endpoint(source: &str) -> String {
    source
        .strip_prefix("registry+")
        .or_else(|| source.strip_prefix("sparse+"))
        .unwrap_or(source)
        .trim_end_matches('/')
        .to_owned()
}

fn normalize_git_reference(source: &str) -> String {
    let source = source.strip_prefix("git+").unwrap_or(source);
    let source = source.split(['?', '#']).next().unwrap_or(source);
    let source = source
        .strip_prefix("https://")
        .or_else(|| source.strip_prefix("http://"))
        .or_else(|| source.strip_prefix("ssh://"))
        .unwrap_or(source);
    source
        .trim_start_matches("git@")
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_owned()
}

fn endpoint_display(endpoint: &str) -> String {
    endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .or_else(|| endpoint.strip_prefix("ssh://"))
        .unwrap_or(endpoint)
        .to_owned()
}

fn display_path(path: &Path, workspace_root: &Path) -> String {
    let directory = path.parent().unwrap_or(path);
    if let Ok(relative) = directory.strip_prefix(workspace_root) {
        let value = relative.to_string_lossy();
        if value.is_empty() {
            "workspace".to_owned()
        } else {
            value.replace('\\', "/")
        }
    } else {
        let name = directory
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "path".to_owned());
        format!("<external>/{name}")
    }
}

fn redact_license_file(value: &str) -> String {
    if value.starts_with('/') {
        let name = Path::new(value)
            .file_name()
            .map(|item| item.to_string_lossy().into_owned())
            .unwrap_or_else(|| "license".to_owned());
        format!("<absolute>/{name}")
    } else {
        value.replace('\\', "/")
    }
}

fn redact_absolute_path(value: &str) -> String {
    if value.starts_with('/') {
        let name = Path::new(value)
            .file_name()
            .map(|item| item.to_string_lossy().into_owned())
            .unwrap_or_else(|| "path".to_owned());
        format!("<absolute>/{name}")
    } else {
        value.to_owned()
    }
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn list_value(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(",")
    }
}

fn optional_value(value: Option<&str>) -> String {
    value.unwrap_or("none").to_owned()
}

fn append_evidence_sources(output: &mut String, sources: &BTreeMap<String, String>) {
    output.push_str("evidence_sources:\n");
    for (name, state) in sources {
        output.push_str(&format!("- {name}={state}\n"));
    }
}

fn append_package_text(output: &mut String, package: &PackageReport) {
    output.push_str(&format!(
        "- {} kind={} source={} ref={} checksum={} license={} license_state={} advisories={} audit={} binary={} features={} direct={} workspace_member={}\n",
        package_label(package),
        package.source_kind,
        package.source,
        package.source_ref,
        package.checksum_state,
        optional_value(package.license.as_deref()),
        package.license_state,
        package.advisory_state,
        package.audit_state,
        package.binary_state,
        list_value(&package.features),
        package.direct,
        package.workspace_member
    ));
}

fn append_diagnostics(output: &mut String, diagnostics: &[Diagnostic]) {
    if diagnostics.is_empty() {
        output.push_str("diagnostics: none\n");
    } else {
        output.push_str("diagnostics:\n");
        for diagnostic in diagnostics {
            output.push_str(&format!(
                "- severity={} code={} package={} detail={}\n",
                diagnostic.severity,
                diagnostic.code,
                optional_value(diagnostic.package.as_deref()),
                diagnostic.detail
            ));
        }
    }
}

fn clean_process_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_source() -> &'static str {
        "registry+https://github.com/rust-lang/crates.io-index"
    }

    fn metadata(package: MetadataPackage) -> MetadataDocument {
        MetadataDocument {
            packages: vec![package],
            workspace_members: Vec::new(),
            workspace_root: "/workspace".to_owned(),
            resolve: Some(ResolveDocument { nodes: Vec::new() }),
        }
    }

    fn package(name: &str, version: &str, license: Option<&str>) -> MetadataPackage {
        MetadataPackage {
            name: name.to_owned(),
            version: version.to_owned(),
            id: format!(
                "{}+https://example.invalid#{name}@{version}",
                registry_source()
            ),
            source: Some(registry_source().to_owned()),
            manifest_path: format!("/cache/{name}/Cargo.toml"),
            license: license.map(str::to_owned),
            license_file: None,
            dependencies: Vec::new(),
        }
    }

    fn lock(name: &str, version: &str, checksum: Option<&str>) -> LockIndex {
        let mut index = LockIndex::default();
        index.packages.insert(
            (
                name.to_owned(),
                version.to_owned(),
                Some(registry_source().to_owned()),
            ),
            LockEvidence {
                checksum: checksum.map(str::to_owned),
                dependencies: Vec::new(),
            },
        );
        index
    }

    #[test]
    fn active_osv_advisory_is_risk() {
        let advisories = vec![OsvAdvisory {
            id: "RUSTSEC-TEST-0001".to_owned(),
            summary: Some("fixture advisory".to_owned()),
            withdrawn: None,
            affected: vec![OsvAffected {
                package: OsvPackage {
                    ecosystem: "crates.io".to_owned(),
                    name: "dep".to_owned(),
                },
                versions: vec!["1.0.0".to_owned()],
                ranges: Vec::new(),
            }],
        }];
        let data = EvidenceData {
            advisories: Some(advisories),
            ..EvidenceData::default()
        };
        let report = build_report(
            Some(&metadata(package("dep", "1.0.0", Some("MIT")))),
            &lock("dep", "1.0.0", Some("sha")),
            Path::new("Cargo.lock"),
            &data,
        );
        assert_eq!(report.status, "risk");
        assert_eq!(report.packages[0].advisory_state, "present");
    }

    #[test]
    fn missing_checksum_is_incomplete() {
        let data = EvidenceData {
            advisories: Some(Vec::new()),
            audits: Some(Vec::new()),
            licenses: Some(Vec::new()),
            binaries: Some(Vec::new()),
        };
        let report = build_report(
            Some(&metadata(package("dep", "1.0.0", Some("MIT")))),
            &lock("dep", "1.0.0", None),
            Path::new("Cargo.lock"),
            &data,
        );
        assert_eq!(report.status, "incomplete");
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "missing-checksum")
        );
    }

    #[test]
    fn license_mismatch_is_a_conflict() {
        let data = EvidenceData {
            advisories: Some(Vec::new()),
            audits: Some(Vec::new()),
            licenses: Some(vec![LicenseRecord {
                name: "dep".to_owned(),
                version: "1.0.0".to_owned(),
                license: "GPL-3.0-only".to_owned(),
            }]),
            binaries: Some(Vec::new()),
        };
        let report = build_report(
            Some(&metadata(package("dep", "1.0.0", Some("MIT")))),
            &lock("dep", "1.0.0", Some("sha")),
            Path::new("Cargo.lock"),
            &data,
        );
        assert_eq!(report.status, "risk");
        assert_eq!(report.packages[0].license_state, "conflict");
    }

    #[test]
    fn audit_violation_and_positive_records_are_distinct() {
        let data = EvidenceData {
            audits: Some(vec![
                (
                    "dep".to_owned(),
                    AuditRecord {
                        kind: "version".to_owned(),
                        selector: "1.0.0".to_owned(),
                        criteria: vec!["safe-to-run".to_owned()],
                    },
                ),
                (
                    "dep".to_owned(),
                    AuditRecord {
                        kind: "violation".to_owned(),
                        selector: "*".to_owned(),
                        criteria: Vec::new(),
                    },
                ),
            ]),
            ..EvidenceData::default()
        };
        let mut diagnostics = Vec::new();
        let (records, state, criteria) =
            audit_state(data.audits.as_deref(), "dep", "1.0.0", &mut diagnostics);
        assert_eq!(state, "violation");
        assert_eq!(records.len(), 2);
        assert_eq!(criteria, vec!["safe-to-run"]);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "audit-violation")
        );
    }

    #[test]
    fn feature_and_direct_edge_data_is_reported() {
        let dep_id = format!("{}+https://example.invalid#dep@1.0.0", registry_source());
        let root = MetadataPackage {
            name: "root".to_owned(),
            version: "1.0.0".to_owned(),
            id: "path+file:///workspace#root@1.0.0".to_owned(),
            source: None,
            manifest_path: "/workspace/Cargo.toml".to_owned(),
            license: Some("MIT".to_owned()),
            license_file: None,
            dependencies: vec![MetadataDependency {
                name: "dep".to_owned(),
                source: Some(registry_source().to_owned()),
                rename: None,
                features: vec!["derive".to_owned()],
                uses_default_features: false,
            }],
        };
        let dep = package("dep", "1.0.0", Some("MIT"));
        let metadata = MetadataDocument {
            packages: vec![root, dep],
            workspace_members: vec!["path+file:///workspace#root@1.0.0".to_owned()],
            workspace_root: "/workspace".to_owned(),
            resolve: Some(ResolveDocument {
                nodes: vec![
                    ResolveNode {
                        id: "path+file:///workspace#root@1.0.0".to_owned(),
                        dependencies: vec![dep_id.clone()],
                        deps: vec![ResolveDependency {
                            name: "dep".to_owned(),
                            pkg: dep_id.clone(),
                            dep_kinds: vec![ResolveDependencyKind {
                                kind: None,
                                target: None,
                            }],
                        }],
                        features: vec!["default".to_owned()],
                    },
                    ResolveNode {
                        id: dep_id,
                        dependencies: Vec::new(),
                        deps: Vec::new(),
                        features: vec!["derive".to_owned()],
                    },
                ],
            }),
        };
        let data = EvidenceData {
            advisories: Some(Vec::new()),
            audits: Some(Vec::new()),
            licenses: Some(vec![LicenseRecord {
                name: "dep".to_owned(),
                version: "1.0.0".to_owned(),
                license: "MIT".to_owned(),
            }]),
            binaries: Some(Vec::new()),
        };
        let report = build_report(
            Some(&metadata),
            &lock("dep", "1.0.0", Some("sha")),
            Path::new("/workspace/Cargo.lock"),
            &data,
        );
        assert!(
            report
                .packages
                .iter()
                .any(|package| package.name == "dep" && package.direct)
        );
        assert_eq!(report.edges[0].features, vec!["derive"]);
        assert!(!report.edges[0].uses_default_features);
    }

    #[test]
    fn malformed_audit_record_is_rejected() {
        let result = load_audits_from_str("[audits.dep]\nversion = \"1.0.0\"\nviolation = \"*\"\n");
        assert!(result.is_err());
    }

    #[test]
    fn multiple_versions_are_sorted_deterministically() {
        let first = EvidenceData {
            advisories: Some(Vec::new()),
            audits: Some(Vec::new()),
            licenses: Some(Vec::new()),
            binaries: Some(Vec::new()),
        };
        let packages = vec![
            package("dep", "2.0.0", Some("MIT")),
            package("dep", "1.0.0", Some("MIT")),
        ];
        let mut metadata = metadata(packages[0].clone());
        metadata.packages = packages;
        let mut index = lock("dep", "1.0.0", Some("one"));
        index
            .packages
            .extend(lock("dep", "2.0.0", Some("two")).packages);
        let report = build_report(Some(&metadata), &index, Path::new("Cargo.lock"), &first);
        assert_eq!(report.packages[0].version, "1.0.0");
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "multiple-versions")
        );
        let json = render_json(&report).expect("json");
        assert_eq!(json, render_json(&report).expect("json"));
    }

    #[test]
    fn semver_osv_range_respects_fixed_version() {
        let range = OsvRange {
            kind: "SEMVER".to_owned(),
            events: vec![
                OsvEvent {
                    introduced: Some("0".to_owned()),
                    fixed: None,
                    last_affected: None,
                    limit: None,
                },
                OsvEvent {
                    introduced: None,
                    fixed: Some("1.2.0".to_owned()),
                    last_affected: None,
                    limit: None,
                },
            ],
        };
        assert!(range_matches(&range, "1.1.9").expect("range"));
        assert!(!range_matches(&range, "1.2.0").expect("range"));
    }

    #[test]
    fn git_source_is_reported_without_revision_as_identity() {
        let info = source_info(
            Some("git+https://github.com/example/dep?rev=abc123#abc123"),
            false,
            Some("/workspace/vendor/dep/Cargo.toml"),
            Some("/workspace"),
            None,
        );
        assert_eq!(info.kind, "git");
        assert_eq!(info.source_ref, "github.com/example/dep");
        assert_eq!(info.checksum_state, "not-applicable");
    }

    #[test]
    fn path_source_is_reported_relative_to_workspace() {
        let info = source_info(
            None,
            false,
            Some("/workspace/vendor/dep/Cargo.toml"),
            Some("/workspace"),
            None,
        );
        assert_eq!(info.kind, "path");
        assert_eq!(info.source_ref, "vendor/dep");
        assert_eq!(info.checksum_state, "not-applicable");
    }

    fn load_audits_from_str(contents: &str) -> Result<Vec<(String, AuditRecord)>, SupplyError> {
        let value: toml::Value = toml::from_str(contents).expect("fixture TOML");
        let path = std::env::temp_dir().join(format!(
            "supplygraph-audit-{}-{}.toml",
            std::process::id(),
            contents.len()
        ));
        fs::write(&path, contents).expect("write fixture");
        assert_eq!(fs::read_to_string(&path).expect("read fixture"), contents);
        let result = load_audits(&path);
        assert!(value.is_table());
        result
    }
}
