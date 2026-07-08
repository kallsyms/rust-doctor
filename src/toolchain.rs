//! Toolchain integration: cargo check / cargo clippy JSON ingestion.
//!
//! When `config.scan.include_toolchain` / `include_clippy` is true the
//! runner spawns `cargo check --message-format=json` and
//! `cargo clippy --message-format=json` (if available) and converts the
//! JSON diagnostics into `rust-doctor` findings under the `Toolchain`
//! category.

use crate::diagnostic::{Category, Confidence, Finding, Location, Severity};
use std::path::PathBuf;
use std::process::Command;

use crate::config;

/// Run `cargo check --message-format=json` and return findings.
pub fn run_cargo_check(workspace_root: &std::path::Path) -> Vec<Finding> {
    let output = match Command::new("cargo")
        .arg("check")
        .arg("--message-format=json")
        .current_dir(workspace_root)
        .output()
    {
        Ok(o) if o.status.success() || o.stderr.is_empty() => o,
        Ok(o) => o, // Even on failure we may have partial JSON on stdout.
        Err(e) => {
            eprintln!("warning: could not run cargo check: {e}");
            return Vec::new();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_rustc_diagnostics(&stdout, workspace_root)
}

/// Run `cargo clippy --message-format=json` and return findings.
///
/// Returns an empty vec when clippy is not available.
pub fn run_cargo_clippy(workspace_root: &std::path::Path) -> Vec<Finding> {
    let output = match Command::new("cargo")
        .arg("clippy")
        .arg("--message-format=json")
        .current_dir(workspace_root)
        .output()
    {
        Ok(o) if o.status.success() || o.stderr.is_empty() => o,
        Ok(o) => o,
        Err(e) => {
            // Exit code 101 is common when clippy finds lints; treat as
            // "command ran successfully" for our purposes.
            if e.kind() == std::io::ErrorKind::NotFound {
                eprintln!("info: clippy not available; skipping toolchain.clippy analysis");
                return Vec::new();
            }
            eprintln!("warning: could not run cargo clippy: {e}");
            return Vec::new();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_rustc_diagnostics(&stdout, workspace_root)
}

/// Run both cargo check and clippy (if enabled) and return combined findings.
pub fn run_toolchain(workspace_root: &std::path::Path, cfg: &config::Config) -> Vec<Finding> {
    let mut findings = run_cargo_check(workspace_root);
    if cfg.scan.include_clippy {
        let clippy_findings = run_cargo_clippy(workspace_root);
        findings.extend(clippy_findings);
    }
    findings
}

// ---------------------------------------------------------------------------
// JSON diagnostics parsing
// ---------------------------------------------------------------------------

/// Parse rustc / clippy JSON diagnostics and convert to rust-doctor findings.
///
/// The JSON format is described at:
/// <https://doc.rust-lang.org/cargo/commands/cargo-rustc.html#json-format>
fn parse_rustc_diagnostics(stdout: &str, workspace_root: &std::path::Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip non-diagnostic messages (compiler-artifact, build-script-executed, etc.)
        if !trimmed.contains(r#""reason":"compiler-message""#) {
            continue;
        }
        if let Ok(msg) = serde_json::from_str::<RustcMessage>(trimmed) {
            // Only process top-level warnings and errors.
            if msg.level != "warning" && msg.level != "error" {
                continue;
            }
            if let Some(finding) = rustc_message_to_finding(&msg, workspace_root) {
                findings.push(finding);
            }
        }
    }
    findings
}

fn rustc_message_to_finding(
    msg: &RustcMessage,
    workspace_root: &std::path::Path,
) -> Option<Finding> {
    let severity = match msg.level.as_str() {
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        _ => return None,
    };

    let rule_id = msg.code.as_ref().map_or("rustc.unknown".to_string(), |c| {
        format!("toolchain.{}", c.code)
    });

    let message = msg.message.join("\n");

    // Build location from the first span if available.
    let location = msg.spans.first().map(|span| {
        let path: PathBuf = span.file_name.clone().into();
        let path = path
            .strip_prefix(workspace_root)
            .ok()
            .map(PathBuf::from)
            .unwrap_or(path);
        Location {
            path,
            line: Some(span.line_start as u32),
            column: Some(span.column_start as u32),
            end_line: Some(span.line_end as u32),
            end_column: Some(span.column_end as u32),
        }
    });

    // Collect notes and help text from the rendered message parts.
    let suggestion = if msg.message.len() > 1 {
        let notes: Vec<String> = msg.message[1..].to_vec();
        Some(notes.join("\n"))
    } else {
        None
    };

    let confidence = match severity {
        Severity::Error => Confidence::High,
        Severity::Warning => Confidence::Medium,
        Severity::Info => Confidence::Low,
    };

    Some(Finding {
        rule_id,
        title: message.clone(),
        category: Category::Toolchain,
        severity,
        confidence,
        location,
        message,
        why_it_matters: "Toolchain diagnostics indicate compilation issues that should be addressed for code quality and stability.".to_string(),
        suggestion,
        references: Vec::new(),
        llm_fix_prompt: None,
    })
}

// ---------------------------------------------------------------------------
// JSON types for cargo --message-format=json
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct RustcMessage {
    #[serde(rename = "reason")]
    _reason: String,
    #[serde(rename = "rendered")]
    message: Vec<String>,
    #[serde(rename = "code", default)]
    code: Option<RustcCode>,
    #[serde(rename = "level")]
    level: String,
    #[serde(rename = "spans", default)]
    spans: Vec<RustcSpan>,
}

#[derive(Debug, serde::Deserialize)]
struct RustcCode {
    code: String,
    #[allow(dead_code)]
    explanation: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct RustcSpan {
    #[serde(rename = "file_name")]
    file_name: String,
    #[serde(rename = "line_start")]
    line_start: usize,
    #[serde(rename = "column_start")]
    column_start: usize,
    #[serde(rename = "line_end")]
    line_end: usize,
    #[serde(rename = "column_end")]
    column_end: usize,
}
