use std::path::PathBuf;

use clap::{Parser, ValueEnum};

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
        let workspace = workspace::Workspace::discover(&scan_path)?;
        let report = workspace.scan(&self.config)?;
        let report = self.apply_filters(report);

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

    fn apply_filters(&self, mut report: Report) -> Report {
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

        // Recompute summary after filtering.
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
