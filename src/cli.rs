use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::analysis;
use crate::config::{self, Config};
use crate::diagnostic::{Category, Report, Severity};
use crate::output;
use crate::workspace;

/// rust-doctor: Rust-native CLI analyzer for idioms, patterns, and anti-patterns
#[derive(Parser, Debug)]
#[command(name = "rust-doctor", version, about)]
pub struct Cli {
    /// Path to scan (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "human")]
    pub format: OutputFormat,

    /// Filter by category (comma-separated)
    #[arg(long)]
    pub category: Option<String>,

    /// Minimum severity to report
    #[arg(long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Exit with code 1 if findings at or above this level
    #[arg(long, value_enum)]
    pub fail_on: Option<SeverityFilter>,

    /// Skip cargo check / cargo clippy toolchain analysis
    #[arg(long)]
    pub no_toolchain: bool,

    /// Include non-workspace dependency crates
    #[arg(long)]
    pub include_dependencies: bool,

    /// Path to config file
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SeverityFilter {
    Info,
    Warning,
    Error,
}

impl From<SeverityFilter> for config::SeverityFilter {
    fn from(f: SeverityFilter) -> Self {
        match f {
            SeverityFilter::Info => config::SeverityFilter::Info,
            SeverityFilter::Warning => config::SeverityFilter::Warning,
            SeverityFilter::Error => config::SeverityFilter::Error,
        }
    }
}

impl From<config::SeverityFilter> for SeverityFilter {
    fn from(f: config::SeverityFilter) -> Self {
        match f {
            config::SeverityFilter::Info => SeverityFilter::Info,
            config::SeverityFilter::Warning => SeverityFilter::Warning,
            config::SeverityFilter::Error => SeverityFilter::Error,
        }
    }
}

pub struct Runner {
    cli: Cli,
    config: Config,
}

impl Runner {
    pub fn new(cli: Cli) -> Self {
        let config = Config::load(cli.config.as_deref(), cli.no_toolchain);
        Self { cli, config }
    }

    pub fn run(self) -> anyhow::Result<()> {
        let scan_path =
            std::fs::canonicalize(&self.cli.path).unwrap_or_else(|_| self.cli.path.clone());
        let workspace = workspace::Workspace::discover_with_dependencies(
            &scan_path,
            self.cli.include_dependencies,
        )?;
        let source_files = workspace.source_files.clone();
        let report = workspace.scan(&self.config)?;
        let report = self.apply_filters(report, &source_files);

        match self.cli.format {
            OutputFormat::Human => {
                let text = output::human::render(&report);
                println!("{}", text);
            }
            OutputFormat::Json => {
                let json = output::json::render_json(&report);
                println!("{}", json);
            }
            OutputFormat::Sarif => {
                let text = output::json::render_sarif(&report);
                println!("{}", text);
            }
        }

        // Determine fail_on: CLI arg takes precedence over config.
        let fail_on = self
            .cli
            .fail_on
            .or(self.config.scan.fail_on.map(SeverityFilter::from))
            .unwrap_or(SeverityFilter::Error);

        let fail_ord = filter_to_ord(fail_on);
        let has_failing = report
            .findings
            .iter()
            .any(|f| severity_to_ord(f.severity) >= fail_ord);

        if has_failing {
            std::process::exit(1);
        }
        Ok(())
    }

    fn apply_filters(&self, mut report: Report, source_files: &[PathBuf]) -> Report {
        // Apply source-level suppressions (rust-doctor-allow / rust-doctor-disable-next-line).
        let mut suppressed_rules: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for file_path in source_files {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                let suppressions = analysis::parse_suppressions(&content);
                for sup in suppressions {
                    if let Some(ref rule_id) = sup.rule_id {
                        suppressed_rules.insert(rule_id.clone());
                    }
                }
            }
        }

        // Filter out findings for suppressed rules.
        report.findings.retain(|f| {
            if suppressed_rules.contains(&f.rule_id) {
                return false;
            }
            // Also check disable-next-line style suppressions by line number.
            if let Some(ref loc) = f.location {
                let content = match std::fs::read_to_string(&loc.path) {
                    Ok(c) => c,
                    Err(_) => return true,
                };
                let suppressions = analysis::parse_suppressions(&content);
                if analysis::is_line_suppressed(
                    &suppressions,
                    &f.rule_id,
                    f.location.as_ref().unwrap().line.unwrap_or(0),
                ) {
                    return false;
                }
            }
            true
        });

        // Category filter: CLI --category takes precedence.
        if let Some(ref cat) = self.cli.category {
            let cats: Vec<&str> = cat.split(',').collect();
            report.findings.retain(|f| {
                cats.iter().any(|c| {
                    category_label(&f.category)
                        .to_lowercase()
                        .contains(&c.to_lowercase())
                })
            });
        }

        // Severity filter: CLI --severity takes precedence.
        if let Some(min_sev) = self.cli.severity {
            let min = filter_to_ord(min_sev);
            report
                .findings
                .retain(|f| severity_to_ord(f.severity) >= min);
        }

        // Recompute summary after filtering and suppression.
        report.compute_summary();

        report
    }
}

fn filter_to_ord(f: SeverityFilter) -> u8 {
    match f {
        SeverityFilter::Info => 0,
        SeverityFilter::Warning => 1,
        SeverityFilter::Error => 2,
    }
}

fn severity_to_ord(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}

fn category_label(cat: &Category) -> &'static str {
    match cat {
        Category::Idiom => "Idiom",
        Category::Pattern => "Pattern",
        Category::AntiPattern => "AntiPattern",
        Category::Organization => "Organization",
        Category::Toolchain => "Toolchain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependencies_are_excluded_by_default_and_can_be_included() {
        let cli = Cli::try_parse_from(["rust-doctor"]).unwrap();
        assert!(!cli.include_dependencies);

        let cli = Cli::try_parse_from(["rust-doctor", "--include-dependencies"]).unwrap();
        assert!(cli.include_dependencies);
    }
}
