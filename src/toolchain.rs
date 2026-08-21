//! Toolchain integration: cargo check / cargo clippy JSON ingestion.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use cargo_metadata::diagnostic::{Diagnostic, DiagnosticLevel};
use cargo_metadata::{Message, Metadata, PackageId};

use crate::config;
use crate::diagnostic::{Category, Confidence, Finding, Location, Severity};

pub fn run_toolchain(
    metadata: &Metadata,
    config: &config::Config,
    include_dependencies: bool,
) -> Vec<Finding> {
    let mut findings = run_cargo_command(metadata, "check", include_dependencies);
    if config.scan.include_clippy {
        findings.extend(run_cargo_command(metadata, "clippy", include_dependencies));
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
    findings
}

fn run_cargo_command(
    metadata: &Metadata,
    subcommand: &str,
    include_dependencies: bool,
) -> Vec<Finding> {
    let workspace_root = metadata.workspace_root.as_std_path();
    let output = match Command::new("cargo")
        .arg(subcommand)
        .arg("--workspace")
        .arg("--all-targets")
        .arg("--message-format=json")
        .current_dir(workspace_root)
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("info: cargo {subcommand} is not available; skipping");
            return Vec::new();
        }
        Err(error) => {
            eprintln!("warning: could not run cargo {subcommand}: {error}");
            return Vec::new();
        }
    };

    let workspace_members = metadata
        .workspace_members
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    parse_rustc_diagnostics(
        output.stdout.as_slice(),
        workspace_root,
        metadata.target_directory.as_std_path(),
        &workspace_members,
        include_dependencies,
    )
}

fn parse_rustc_diagnostics(
    stdout: &[u8],
    workspace_root: &Path,
    target_directory: &Path,
    workspace_members: &HashSet<PackageId>,
    include_dependencies: bool,
) -> Vec<Finding> {
    Message::parse_stream(stdout)
        .filter_map(Result::ok)
        .filter_map(|message| match message {
            Message::CompilerMessage(message)
                if include_dependencies || workspace_members.contains(&message.package_id) =>
            {
                diagnostic_to_finding(&message.message, workspace_root, target_directory)
            }
            _ => None,
        })
        .collect()
}

fn diagnostic_to_finding(
    diagnostic: &Diagnostic,
    workspace_root: &Path,
    target_directory: &Path,
) -> Option<Finding> {
    let severity = match diagnostic.level {
        DiagnosticLevel::Error | DiagnosticLevel::Ice => Severity::Error,
        DiagnosticLevel::Warning => Severity::Warning,
        _ => return None,
    };

    let span = diagnostic
        .spans
        .iter()
        .find(|span| span.is_primary)
        .or_else(|| diagnostic.spans.first());
    let absolute_path = span.map(|span| {
        let path = PathBuf::from(&span.file_name);
        if path.is_absolute() {
            path
        } else {
            workspace_root.join(path)
        }
    });
    if absolute_path
        .as_deref()
        .is_some_and(|path| path.starts_with(target_directory))
    {
        return None;
    }

    let location = span.zip(absolute_path).map(|(span, path)| Location {
        path,
        line: Some(span.line_start as u32),
        column: Some(span.column_start as u32),
        end_line: Some(span.line_end as u32),
        end_column: Some(span.column_end as u32),
    });
    let rule_id = diagnostic.code.as_ref().map_or_else(
        || "toolchain.unknown".to_string(),
        |code| format!("toolchain.{}", code.code),
    );
    let suggestion = diagnostic
        .children
        .iter()
        .filter(|child| matches!(child.level, DiagnosticLevel::Help | DiagnosticLevel::Note))
        .map(|child| child.message.as_str())
        .collect::<Vec<_>>();
    let suggestion = (!suggestion.is_empty()).then(|| suggestion.join("\n"));
    let confidence = match severity {
        Severity::Error => Confidence::High,
        Severity::Warning => Confidence::Medium,
        Severity::Info => Confidence::Low,
    };

    Some(Finding {
        rule_id,
        title: diagnostic.message.clone(),
        category: Category::Toolchain,
        severity,
        confidence,
        location,
        message: diagnostic.message.clone(),
        why_it_matters: "Toolchain diagnostics indicate compilation issues that should be addressed for code quality and stability.".to_string(),
        suggestion,
        references: Vec::new(),
        llm_fix_prompt: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPILER_MESSAGE: &str = r#"{"reason":"compiler-message","package_id":"path+file:///workspace#member@0.1.0","manifest_path":"/workspace/Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"member","src_path":"/workspace/src/lib.rs","edition":"2021","doc":true,"doctest":true,"test":true},"message":{"rendered":"warning: test warning\n","$message_type":"diagnostic","children":[{"children":[],"code":null,"level":"help","message":"do the safer thing","rendered":null,"spans":[]}],"code":{"code":"clippy::test_lint","explanation":null},"level":"warning","message":"test warning","spans":[{"byte_end":3,"byte_start":0,"column_end":4,"column_start":1,"expansion":null,"file_name":"src/lib.rs","is_primary":true,"label":null,"line_end":2,"line_start":2,"suggested_replacement":null,"suggestion_applicability":null,"text":[{"highlight_end":4,"highlight_start":1,"text":"bad"}]}]}}"#;

    fn package_id(value: &str) -> PackageId {
        serde_json::from_str(&format!("{value:?}")).unwrap()
    }

    #[test]
    fn parses_cargo_compiler_message_envelope() {
        let member = package_id("path+file:///workspace#member@0.1.0");
        let findings = parse_rustc_diagnostics(
            COMPILER_MESSAGE.as_bytes(),
            Path::new("/workspace"),
            Path::new("/workspace/target"),
            &HashSet::from([member]),
            false,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "toolchain.clippy::test_lint");
        assert_eq!(
            findings[0].location.as_ref().unwrap().path,
            PathBuf::from("/workspace/src/lib.rs")
        );
        assert_eq!(
            findings[0].suggestion.as_deref(),
            Some("do the safer thing")
        );
    }

    #[test]
    fn excludes_non_members_and_generated_files() {
        let other = package_id("path+file:///workspace#other@0.1.0");
        let findings = parse_rustc_diagnostics(
            COMPILER_MESSAGE.as_bytes(),
            Path::new("/workspace"),
            Path::new("/workspace/src"),
            &HashSet::from([other.clone()]),
            false,
        );
        assert!(findings.is_empty());

        let findings = parse_rustc_diagnostics(
            COMPILER_MESSAGE.as_bytes(),
            Path::new("/workspace"),
            Path::new("/workspace/target"),
            &HashSet::from([other]),
            true,
        );
        assert_eq!(findings.len(), 1);

        let member = package_id("path+file:///workspace#member@0.1.0");
        let findings = parse_rustc_diagnostics(
            COMPILER_MESSAGE.as_bytes(),
            Path::new("/workspace"),
            Path::new("/workspace/src"),
            &HashSet::from([member]),
            false,
        );
        assert!(findings.is_empty());
    }
}
