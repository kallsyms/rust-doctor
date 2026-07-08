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

/// Aggregate health score for a report.
///
/// The score starts at 100 and deducts points for findings based on severity
/// and confidence. It is intentionally simple and stable so humans and LLM
/// agents can quickly understand whether a codebase is healthy, needs cleanup,
/// or has serious risks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthScore {
    /// 0-100 codebase health score, where 100 means no findings.
    pub score: u8,
    /// Letter grade derived from `score`.
    pub grade: String,
    /// Human-readable grade label.
    pub label: String,
    /// Raw deduction total before the score is clamped at zero.
    pub deductions: u16,
}

impl Default for HealthScore {
    fn default() -> Self {
        Self {
            score: 100,
            grade: "A".to_string(),
            label: "Excellent".to_string(),
            deductions: 0,
        }
    }
}

impl HealthScore {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let deductions: u16 = findings.iter().map(finding_deduction).sum();
        let score = 100_u16.saturating_sub(deductions.min(100)) as u8;
        let (grade, label) = grade_for(score);

        Self {
            score,
            grade: grade.to_string(),
            label: label.to_string(),
            deductions,
        }
    }
}

fn finding_deduction(finding: &Finding) -> u16 {
    match (finding.severity, finding.confidence) {
        (Severity::Error, Confidence::High) => 30,
        (Severity::Error, Confidence::Medium) => 24,
        (Severity::Error, Confidence::Low) => 18,
        (Severity::Warning, Confidence::High) => 10,
        (Severity::Warning, Confidence::Medium) => 8,
        (Severity::Warning, Confidence::Low) => 6,
        (Severity::Info, Confidence::High) => 3,
        (Severity::Info, Confidence::Medium) => 2,
        (Severity::Info, Confidence::Low) => 1,
    }
}

fn grade_for(score: u8) -> (&'static str, &'static str) {
    match score {
        90..=100 => ("A", "Excellent"),
        75..=89 => ("B", "Good"),
        60..=74 => ("C", "Fair"),
        40..=59 => ("D", "Risky"),
        _ => ("F", "Critical"),
    }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Aggregate counts and score for a report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub total: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub health: HealthScore,
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
        s.health = HealthScore::from_findings(findings);
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
        assert_eq!(s.health.score, 61);
        assert_eq!(s.health.grade, "C");
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
