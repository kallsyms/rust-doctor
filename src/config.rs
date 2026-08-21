//! Configuration for rust-doctor.

use std::path::Path;

use serde::Deserialize;

/// Top-level configuration.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub rules: RulesConfig,
}

/// [scan] section.
#[derive(Debug, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_true")]
    pub include_toolchain: bool,
    #[serde(default = "default_true")]
    pub include_clippy: bool,
    #[serde(default)]
    pub fail_on: Option<SeverityFilter>,
}

fn default_true() -> bool {
    true
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_toolchain: true,
            include_clippy: true,
            fail_on: None,
        }
    }
}

/// [rules] section.
#[derive(Debug, Default, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub disabled: Vec<String>,
    #[serde(default)]
    pub warn: Vec<String>,
    #[serde(default)]
    pub info: Vec<String>,
}

/// Severity threshold for filtering / fail-on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum SeverityFilter {
    #[default]
    Info,
    Warning,
    Error,
}

impl Config {
    /// Load config from an optional file path, falling back to defaults.
    pub fn load(config_path: Option<&Path>, no_toolchain: bool) -> Self {
        let mut config = Self::default();
        if let Some(path) = config_path {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(parsed) = toml::from_str::<Config>(&contents) {
                    config = parsed;
                }
            }
        }
        if no_toolchain {
            config.scan.include_toolchain = false;
            config.scan.include_clippy = false;
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toolchain_analysis_is_enabled_by_default() {
        let config = Config::load(None, false);

        assert!(config.scan.include_toolchain);
        assert!(config.scan.include_clippy);
    }

    #[test]
    fn no_toolchain_disables_check_and_clippy() {
        let config = Config::load(None, true);

        assert!(!config.scan.include_toolchain);
        assert!(!config.scan.include_clippy);
    }
}
