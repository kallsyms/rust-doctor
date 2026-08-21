//! Workspace discovery and scanning.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use cargo_metadata::{Metadata, MetadataCommand, Package, PackageId};

use crate::analysis;
use crate::config::Config;
use crate::diagnostic::Report;
use crate::rules::registry::{PackageManifest, Registry, RuleContext};
use crate::toolchain::run_toolchain;

pub struct Workspace {
    pub root: PathBuf,
    pub source_files: Vec<PathBuf>,
    metadata: Option<Metadata>,
    package_source_files: HashMap<PackageId, Vec<PathBuf>>,
    include_dependencies: bool,
}

impl Workspace {
    pub fn discover(path: &Path) -> anyhow::Result<Self> {
        Self::discover_with_dependencies(path, false)
    }

    pub fn discover_with_dependencies(
        path: &Path,
        include_dependencies: bool,
    ) -> anyhow::Result<Self> {
        let manifest_path = path.join("Cargo.toml");
        if !manifest_path.is_file() {
            let mut source_files = Vec::new();
            analysis::collect_rust_files(path, &mut source_files);
            source_files.sort();
            source_files.dedup();
            return Ok(Self {
                root: path.to_path_buf(),
                source_files,
                metadata: None,
                package_source_files: HashMap::new(),
                include_dependencies,
            });
        }

        let mut command = MetadataCommand::new();
        command.manifest_path(&manifest_path);
        if !include_dependencies {
            command.no_deps();
        }
        let metadata = command.exec()?;
        let root = metadata.workspace_root.clone().into_std_path_buf();
        let package_source_files = collect_package_source_files(&metadata.packages);
        let mut source_files = package_source_files
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        source_files.sort();
        source_files.dedup();

        Ok(Self {
            root,
            source_files,
            metadata: Some(metadata),
            package_source_files,
            include_dependencies,
        })
    }

    pub fn scan(self, config: &Config) -> anyhow::Result<Report> {
        let mut findings = Vec::new();

        if let Some(metadata) = self.metadata {
            let manifests = metadata
                .packages
                .iter()
                .filter_map(|package| {
                    let path = package.manifest_path.clone().into_std_path_buf();
                    std::fs::read_to_string(&path)
                        .ok()
                        .map(|content| PackageManifest {
                            package_name: package.name.clone(),
                            path,
                            content,
                        })
                })
                .collect();

            let ctx = RuleContext {
                workspace_root: self.root.clone(),
                metadata: &metadata,
                manifests,
                package_source_files: self.package_source_files,
            };

            for rule in Registry::new().iter() {
                if let Err(error) = rule.check(&ctx, &mut findings) {
                    eprintln!("warning: rule {} failed: {error}", rule.id());
                }
            }

            if config.scan.include_toolchain {
                findings.extend(run_toolchain(&metadata, config, self.include_dependencies));
            }
        }

        let mut seen = HashSet::new();
        findings.retain(|finding| {
            let location = finding.location.as_ref();
            seen.insert((
                finding.rule_id.clone(),
                finding.message.clone(),
                location.map(|location| location.path.clone()),
                location.and_then(|location| location.line),
                location.and_then(|location| location.column),
            ))
        });

        let mut report = Report::new(env!("CARGO_PKG_VERSION").to_string(), self.root);
        report.findings = findings;
        report.compute_summary();
        Ok(report)
    }
}

fn collect_package_source_files(packages: &[Package]) -> HashMap<PackageId, Vec<PathBuf>> {
    packages
        .iter()
        .map(|package| {
            let package_root = package
                .manifest_path
                .parent()
                .map(|path| path.to_path_buf().into_std_path_buf())
                .unwrap_or_default();
            let mut files = Vec::new();
            analysis::collect_rust_files(&package_root.join("src"), &mut files);
            files.extend(
                package
                    .targets
                    .iter()
                    .map(|target| target.src_path.clone().into_std_path_buf())
                    .filter(|path| path.is_file()),
            );
            files.sort();
            files.dedup();
            (package.id.clone(), files)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn default_scope_includes_all_workspace_members_and_excludes_path_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join("Cargo.toml"),
            r#"
[workspace]
members = ["crates/one", "crates/two"]
exclude = ["vendor/dependency"]
resolver = "2"
"#,
        );
        write(
            &temp.path().join("crates/one/Cargo.toml"),
            r#"
[package]
name = "one"
version = "0.1.0"
edition = "2021"

[dependencies]
dependency = { path = "../../vendor/dependency" }
"#,
        );
        write(&temp.path().join("crates/one/src/lib.rs"), "mod nested;\n");
        write(
            &temp.path().join("crates/one/src/nested.rs"),
            "pub struct VisibleModule;\n",
        );
        write(
            &temp.path().join("crates/two/Cargo.toml"),
            r#"
[package]
name = "two"
version = "0.1.0"
edition = "2021"
"#,
        );
        write(&temp.path().join("crates/two/src/lib.rs"), "");
        write(
            &temp.path().join("vendor/dependency/Cargo.toml"),
            r#"
[package]
name = "dependency"
version = "0.1.0"
edition = "2021"
"#,
        );
        write(
            &temp.path().join("vendor/dependency/src/lib.rs"),
            "pub struct Dependency;\n",
        );

        let workspace = Workspace::discover(temp.path()).unwrap();
        let package_names = workspace
            .metadata
            .as_ref()
            .unwrap()
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(package_names, ["one", "two"]);
        assert!(workspace
            .source_files
            .contains(&temp.path().join("crates/one/src/nested.rs")));
        assert!(!workspace
            .source_files
            .contains(&temp.path().join("vendor/dependency/src/lib.rs")));

        let report = workspace.scan(&Config::load(None, true)).unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "idiom.privacy-extensibility"
                && finding
                    .location
                    .as_ref()
                    .is_some_and(|location| location.path.ends_with("crates/one/src/nested.rs"))
        }));

        let workspace = Workspace::discover_with_dependencies(temp.path(), true).unwrap();
        assert!(workspace
            .metadata
            .as_ref()
            .unwrap()
            .packages
            .iter()
            .any(|package| package.name == "dependency"));
    }
}
