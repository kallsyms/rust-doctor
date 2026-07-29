//! Workspace discovery and scanning.

use std::path::{Path, PathBuf};

use cargo_metadata::MetadataCommand;

use crate::analysis;
use crate::config::Config;
use crate::diagnostic::Report;
use crate::rules::registry::{Registry, RuleContext};
use crate::toolchain::run_toolchain;

/// Represents a discovered Rust workspace with its packages and source files.
pub struct Workspace {
    pub root: PathBuf,
    pub packages: Vec<Package>,
    pub source_files: Vec<PathBuf>,
}

/// A single package within the workspace.
pub struct Package {
    pub name: String,
    pub manifest_path: PathBuf,
    pub source_lib: Option<PathBuf>,
    pub source_bins: Vec<PathBuf>,
    pub is_library: bool,
    pub is_binary: bool,
    pub publish: bool,
}

impl Workspace {
    /// Whether this workspace was discovered via a Cargo.toml manifest.
    pub fn has_manifest(&self) -> bool {
        !self.packages.is_empty()
    }

    /// Discover a workspace starting from the given path.
    ///
    /// If a Cargo.toml is found directly in the given path, uses `cargo_metadata`
    /// for full workspace discovery.  Otherwise falls back to loose Rust-file
    /// discovery in that directory.
    pub fn discover(path: &Path) -> anyhow::Result<Self> {
        // Only look for a Cargo.toml directly in the given path (not parent dirs).
        let manifest_path = path.join("Cargo.toml");
        if manifest_path.is_file() {
            let root = manifest_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or(path.to_path_buf());

            let metadata = MetadataCommand::new()
                .manifest_path(&manifest_path)
                .exec()?;

            let mut packages = Vec::new();
            let mut source_files = Vec::new();

            for pkg in &metadata.packages {
                let mut is_library = false;
                let mut is_binary = false;
                let mut source_lib = None;
                let mut source_bins = Vec::new();
                let mut publish = true;

                if let Ok(manifest_content) = std::fs::read_to_string(&pkg.manifest_path) {
                    if let Ok(table) = manifest_content.parse::<toml::Value>() {
                        if let Some(false) = table
                            .get("package")
                            .and_then(|p| p.get("publish"))
                            .and_then(|v| v.as_bool())
                        {
                            publish = false;
                        }
                    }
                }

                for target in &pkg.targets {
                    for kind in &target.kind {
                        match kind.as_str() {
                            "lib" => {
                                is_library = true;
                                if let Some(lib_target) = target.src_path.as_os_str().to_str() {
                                    source_lib = Some(PathBuf::from(lib_target));
                                }
                            }
                            "bin" => {
                                is_binary = true;
                                if let Some(bin_path) = target.src_path.as_os_str().to_str() {
                                    source_bins.push(PathBuf::from(bin_path));
                                }
                            }
                            _ => {}
                        }
                    }
                }

                packages.push(Package {
                    name: pkg.name.clone(),
                    manifest_path: pkg.manifest_path.clone().into(),
                    source_lib,
                    source_bins,
                    is_library,
                    is_binary,
                    publish,
                });
            }

            // Collect lib and bin source files first.
            for pkg in &packages {
                if let Some(ref lib_path) = pkg.source_lib {
                    if lib_path.is_file() {
                        source_files.push(lib_path.clone());
                    }
                }
                for bin_path in &pkg.source_bins {
                    if bin_path.is_file() {
                        source_files.push(bin_path.clone());
                    }
                }
            }

            // Now scan for module files under src/**/*.rs for each package.
            for pkg in &packages {
                let pkg_root = pkg
                    .manifest_path
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| pkg.manifest_path.clone());

                // Look for a src/ directory relative to the manifest.
                let src_dir = pkg_root.join("src");
                if src_dir.is_dir() {
                    let mut module_files = Vec::new();
                    analysis::collect_rust_files(&src_dir, &mut module_files);
                    for f in module_files {
                        // Avoid duplicates (lib.rs and main.rs may already be included).
                        if !source_files.contains(&f) {
                            source_files.push(f);
                        }
                    }
                }
            }

            Ok(Workspace {
                root,
                packages,
                source_files,
            })
        } else {
            // Fallback: discover loose .rs files in the directory tree.
            let mut source_files = Vec::new();
            analysis::collect_rust_files(path, &mut source_files);
            Ok(Workspace {
                root: path.to_path_buf(),
                packages: Vec::new(),
                source_files,
            })
        }
    }

    /// Run all custom rules against the workspace and return a report.
    pub fn scan(self, config: &Config) -> anyhow::Result<Report> {
        // Collect manifest contents for rules that need them.
        let manifests: std::collections::HashMap<String, String> = self
            .packages
            .iter()
            .filter_map(|pkg| {
                std::fs::read_to_string(&pkg.manifest_path)
                    .ok()
                    .map(|c| (pkg.name.clone(), c))
            })
            .collect();

        // Build metadata if we have a manifest.
        let metadata = if self.has_manifest() {
            let m = MetadataCommand::new()
                .manifest_path(self.root.join("Cargo.toml"))
                .exec()?;
            Some(m)
        } else {
            None
        };

        let registry = Registry::new();
        let mut findings = Vec::new();

        if let Some(ref metadata) = metadata {
            let ctx = RuleContext {
                workspace_root: self.root.clone(),
                metadata,
                manifests,
            };

            for rule in registry.iter() {
                if let Err(e) = rule.check(&ctx, &mut findings) {
                    eprintln!("warning: rule {} failed: {e}", rule.id());
                }
            }
        }
        // When there's no manifest, custom rules that need metadata are
        // simply skipped – loose-file scanning cannot satisfy them.

        // Run toolchain analysis if enabled.
        if config.scan.include_toolchain {
            let toolchain_findings = run_toolchain(&self.root, config);
            findings.extend(toolchain_findings);
        }

        let mut report = Report::new(env!("CARGO_PKG_VERSION").to_string(), self.root);
        report.findings = findings;
        report.compute_summary();

        Ok(report)
    }
}
