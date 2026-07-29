//! Reusable rule-analysis helpers for parsing Rust files.
//!
//! Provides common utilities for:
//! - Locating items in source text (line/column finding)
//! - Identifying public APIs (pub fn, pub struct, pub enum, pub trait)
//! - Detecting unsafe and extern signatures
//! - Consistent finding construction
//! - Parsing suppression comments (`rust-doctor-allow` / `rust-doctor-disable-next-line`)

use std::path::Path;

use crate::diagnostic::{Finding, Location};
use quote::ToTokens;

// ---------------------------------------------------------------------------
// Source location helpers
// ---------------------------------------------------------------------------

/// Find the line number (1-based) of a text pattern in source content.
///
/// Returns `None` if not found.
pub fn find_line(content: &str, pattern: &str) -> Option<u32> {
    content
        .lines()
        .position(|l| l.contains(pattern))
        .map(|n| (n + 1) as u32)
}

/// Find the line number of a token near a given identifier.
///
/// Looks for lines containing both `keyword` and `ident`.
pub fn find_line_with_keyword(content: &str, keyword: &str, ident: &str) -> Option<u32> {
    content
        .lines()
        .position(|l| l.contains(keyword) && l.contains(ident))
        .or_else(|| {
            content
                .lines()
                .position(|l| l.contains(&format!("{keyword} {ident}")))
        })
        .or_else(|| {
            content
                .lines()
                .position(|l| l.contains(&format!("{ident}.{keyword}")))
        })
        .map(|n| (n + 1) as u32)
}

// ---------------------------------------------------------------------------
// Public API detection
// ---------------------------------------------------------------------------

/// Check if a visibility string contains `pub` (including `pub(crate)`, `pub(super)`, etc.).
pub fn is_pub(vis_str: &str) -> bool {
    vis_str.contains("pub")
}

/// Check if a syn::Visibility (as token stream string) is public.
pub fn is_vis_pub(vis: &syn::Visibility) -> bool {
    is_pub(&vis.to_token_stream().to_string())
}

/// Collect all public function names from parsed items.
pub fn collect_pub_fn_names(items: &[syn::Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| {
            if let syn::Item::Fn(fn_item) = item {
                let vis_str = fn_item.vis.to_token_stream().to_string();
                if vis_str.contains("pub") {
                    Some(fn_item.sig.ident.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

/// Collect all public struct/enum/trait names from parsed items.
pub fn collect_pub_type_names(items: &[syn::Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(s) => {
                let vis_str = item.to_token_stream().to_string();
                if vis_str.contains("pub") {
                    Some(s.ident.to_string())
                } else {
                    None
                }
            }
            syn::Item::Enum(e) => {
                let vis_str = item.to_token_stream().to_string();
                if vis_str.contains("pub") {
                    Some(e.ident.to_string())
                } else {
                    None
                }
            }
            syn::Item::Trait(t) => {
                let vis_str = item.to_token_stream().to_string();
                if vis_str.contains("pub") {
                    Some(t.ident.to_string())
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Unsafe / extern detection
// ---------------------------------------------------------------------------

/// Count the number of `unsafe` blocks or fn items in source content.
pub fn count_unsafe(content: &str) -> usize {
    content
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("unsafe ")
                || trimmed.starts_with("unsafe{")
                || trimmed.starts_with("unsafe fn")
        })
        .count()
}

/// Check if a function signature contains `unsafe`.
pub fn is_fn_unsafe(fn_item: &syn::ItemFn) -> bool {
    fn_item.sig.unsafety.is_some()
}

/// Check if a function signature is `extern`.
pub fn is_fn_extern(fn_item: &syn::ItemFn) -> bool {
    fn_item.sig.abi.is_some()
}

/// Collect all unsafe function names from parsed items.
pub fn collect_unsafe_fn_names(items: &[syn::Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| {
            if let syn::Item::Fn(fn_item) = item {
                if is_fn_unsafe(fn_item) {
                    Some(fn_item.sig.ident.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

/// Collect all extern function signatures from parsed items.
pub fn collect_extern_fn_names(items: &[syn::Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| {
            if let syn::Item::Fn(fn_item) = item {
                if is_fn_extern(fn_item) {
                    Some(format!(
                        "{}({})",
                        fn_item.sig.ident,
                        fn_item
                            .sig
                            .inputs
                            .iter()
                            .map(|arg| match arg {
                                syn::FnArg::Typed(pat_type) => {
                                    pat_type.ty.to_token_stream().to_string()
                                }
                                syn::FnArg::Receiver(r) => r.to_token_stream().to_string(),
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Finding construction helpers
// ---------------------------------------------------------------------------

/// Build a `Finding` with consistent defaults for a given rule.
pub fn make_finding(
    rule: &dyn crate::rules::registry::Rule,
    location: Location,
    message: String,
    why_it_matters: String,
    suggestion: Option<String>,
) -> Finding {
    Finding {
        rule_id: rule.id().to_string(),
        title: rule.title().to_string(),
        category: rule.category(),
        severity: rule.default_severity(),
        confidence: rule.default_confidence(),
        location: Some(location),
        message,
        why_it_matters,
        suggestion,
        references: rule.references().into_iter().map(String::from).collect(),
        llm_fix_prompt: rule.llm_fix_prompt().map(String::from),
    }
}

/// Build a `Finding` without a specific location (e.g., crate-level findings).
pub fn make_finding_no_location(
    rule: &dyn crate::rules::registry::Rule,
    message: String,
    why_it_matters: String,
    suggestion: Option<String>,
) -> Finding {
    Finding {
        rule_id: rule.id().to_string(),
        title: rule.title().to_string(),
        category: rule.category(),
        severity: rule.default_severity(),
        confidence: rule.default_confidence(),
        location: None,
        message,
        why_it_matters,
        suggestion,
        references: rule.references().into_iter().map(String::from).collect(),
        llm_fix_prompt: rule.llm_fix_prompt().map(String::from),
    }
}

// ---------------------------------------------------------------------------
// Suppression comment parsing
// ---------------------------------------------------------------------------

/// Suppression directive parsed from a source comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    /// The rule ID to suppress (empty means all rules).
    pub rule_id: Option<String>,
    /// The 1-based line number the suppression applies to (next line for "disable-next-line").
    pub line: u32,
}

/// Parse suppression comments from source content.
///
/// Recognizes two forms:
/// - `// rust-doctor-allow RULE_ID` — suppresses RULE_ID for the entire rest of the file
/// - `// rust-doctor-disable-next-line RULE_ID` — suppresses RULE_ID for the next line only
///
/// If no rule ID is provided, the suppression applies to all rules.
pub fn parse_suppressions(content: &str) -> Vec<Suppression> {
    let mut suppressions = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Check for `// rust-doctor-allow RULE_ID`
        if let Some(rest) = trimmed.strip_prefix("// rust-doctor-allow") {
            let rest = rest.trim();
            let rule_id = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            suppressions.push(Suppression {
                rule_id: rule_id.clone(),
                line: (idx + 1) as u32,
            });
        }

        // Check for `// rust-doctor-disable-next-line RULE_ID`
        if let Some(rest) = trimmed.strip_prefix("// rust-doctor-disable-next-line") {
            let rest = rest.trim();
            let rule_id = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            suppressions.push(Suppression {
                rule_id: rule_id.clone(),
                line: (idx + 2) as u32, // applies to the NEXT line
            });
        }
    }

    suppressions
}

/// Check if a finding at the given line should be suppressed by any directive.
///
/// Returns `true` if the finding should be suppressed (i.e., filtered out).
pub fn is_suppressed(suppressions: &[Suppression], rule_id: &str, line: Option<u32>) -> bool {
    let target_line = match line {
        Some(l) => l,
        None => return false, // No location means we can't suppress by line
    };

    for sup in suppressions {
        match (&sup.rule_id, line) {
            // Global suppression (no rule_id) on or after this line
            (None, _) => {
                if sup.line <= target_line {
                    return true;
                }
            }
            // Rule-specific suppression
            (Some(ref sup_rule), _) => {
                if sup_rule == rule_id || sup_rule == "*" {
                    // "disable-next-line" suppresses only the next line
                    if sup.line == target_line {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Check if a specific line in source should be suppressed for a given rule.
pub fn is_line_suppressed(suppressions: &[Suppression], rule_id: &str, line: u32) -> bool {
    suppressions.iter().any(|sup| match &sup.rule_id {
        Some(ref s) => (s == rule_id || s == "*") && sup.line == line,
        None => sup.line <= line,
    })
}

// ---------------------------------------------------------------------------
// File discovery helpers
// ---------------------------------------------------------------------------

/// Recursively collect `.rs` files from a directory.
///
/// Skips `target/` and `.git/` directories.
pub fn collect_rust_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            if path
                .file_name()
                .map(|n| n == "target" || n == ".git" || n == ".cargo")
                .unwrap_or(false)
            {
                continue;
            }
            collect_rust_files(&path, files);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            files.push(path);
        }
    }
}

/// Parse a Rust source file and return the `syn::File`.
pub fn parse_file(content: &str) -> Option<syn::File> {
    syn::parse_file(content).ok()
}

/// Read and parse a Rust source file at the given path.
pub fn parse_file_at(path: &Path) -> Option<syn::File> {
    let content = std::fs::read_to_string(path).ok()?;
    syn::parse_file(&content).ok()
}
