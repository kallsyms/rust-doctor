//! Diagnostic data types: Report, Finding, Location, Severity, Category, Confidence.
//!
//! These types form the stable, serialisable core of rust-doctor output.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    /// Return a human-friendly label.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
            Severity::Info => "INFO",
        }
    }

    /// Return true if this severity should count as a failure under
    /// `--fail-on` semantics.
    pub fn is_error(&self) -> bool {
        matches!(self, Severity::Error)
    }
}

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

/// How confident we are that the finding is a real issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

/// High-level classification of a rule/finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Community style / ergonomics guidance (idiom.* rules).
    Idiom,
    /// Positive design patterns worth suggesting (pattern.* rules).
    Pattern,
    /// Likely harmful approaches (anti_pattern.* rules).
    AntiPattern,
    /// Crate / module / API surface and maintainability.
    Organization,
    /// Compiler, Clippy, and toolchain findings.
    Toolchain,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::Idiom => "Idiom",
            Category::Pattern => "Pattern",
            Category::AntiPattern => "Anti-Pattern",
            Category::Organization => "Organization",
            Category::Toolchain => "Toolchain",
        }
    }
}

// ---------------------------------------------------------------------------
// Location
// ---------------------------------------------------------------------------

/// Source-location span for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub path: PathBuf,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// A single diagnostic finding produced by a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: Option<Location>,
    pub message: String,
    pub why_it_matters: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_fix_prompt: Option<String>,
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Aggregate counts for a report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub total: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Top-level output emitted by rust-doctor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool_version: String,
    pub workspace_root: PathBuf,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(tool_version: String, workspace_root: PathBuf) -> Self {
        Self {
            tool_version,
            workspace_root,
            summary: Summary::default(),
            findings: Vec::new(),
        }
    }

    /// Update summary counts from findings.
    pub fn compute_summary(&mut self) {
        self.summary = Summary::from_findings(&self.findings);
    }
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Summary::default();
        for f in findings {
            s.total += 1;
            match f.severity {
                Severity::Error => s.errors += 1,
                Severity::Warning => s.warnings += 1,
                Severity::Info => s.infos += 1,
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_counts_are_correct() {
        let findings = vec![
            Finding {
                rule_id: "test".to_string(),
                title: "t1".to_string(),
                category: Category::Idiom,
                severity: Severity::Error,
                confidence: Confidence::High,
                location: None,
                message: "m".to_string(),
                why_it_matters: "w".to_string(),
                suggestion: None,
                references: Vec::new(),
                llm_fix_prompt: None,
            },
            Finding {
                rule_id: "test2".to_string(),
                title: "t2".to_string(),
                category: Category::Pattern,
                severity: Severity::Warning,
                confidence: Confidence::Medium,
                location: None,
                message: "m2".to_string(),
                why_it_matters: "w2".to_string(),
                suggestion: None,
                references: Vec::new(),
                llm_fix_prompt: None,
            },
            Finding {
                rule_id: "test3".to_string(),
                title: "t3".to_string(),
                category: Category::AntiPattern,
                severity: Severity::Info,
                confidence: Confidence::Low,
                location: None,
                message: "m3".to_string(),
                why_it_matters: "w3".to_string(),
                suggestion: None,
                references: Vec::new(),
                llm_fix_prompt: None,
            },
        ];
        let s = Summary::from_findings(&findings);
        assert_eq!(s.total, 3);
        assert_eq!(s.errors, 1);
        assert_eq!(s.warnings, 1);
        assert_eq!(s.infos, 1);
    }

    #[test]
    fn report_compute_summary() {
        let mut report = Report::new("0.1.0".to_string(), PathBuf::from("/"));
        report.findings.push(Finding {
            rule_id: "r1".into(),
            title: "t".into(),
            category: Category::Idiom,
            severity: Severity::Error,
            confidence: Confidence::High,
            location: None,
            message: "m".into(),
            why_it_matters: "w".into(),
            suggestion: None,
            references: Vec::new(),
            llm_fix_prompt: None,
        });
        report.compute_summary();
        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.errors, 1);
    }

    #[test]
    fn severity_is_error() {
        assert!(Severity::Error.is_error());
        assert!(!Severity::Warning.is_error());
        assert!(!Severity::Info.is_error());
    }

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Error.label(), "ERROR");
        assert_eq!(Severity::Warning.label(), "WARNING");
        assert_eq!(Severity::Info.label(), "INFO");
    }

    #[test]
    fn category_labels() {
        assert_eq!(Category::Idiom.label(), "Idiom");
        assert_eq!(Category::AntiPattern.label(), "Anti-Pattern");
    }
}
