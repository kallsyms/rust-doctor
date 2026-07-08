//! Pattern rules and Phase-2 stubs.

use crate::diagnostic::{Category, Confidence, Finding, Location, Severity};
use crate::rules::registry::{Rule, RuleContext};
use quote::ToTokens;
use std::path::PathBuf;
use syn::File;

// ---------------------------------------------------------------------------
// PatternBuilder
// ---------------------------------------------------------------------------

/// Suggest builder pattern for functions with many parameters.
#[derive(Default)]
pub struct PatternBuilder;

impl Rule for PatternBuilder {
    fn id(&self) -> &'static str {
        "pattern.builder"
    }

    fn title(&self) -> &'static str {
        "Consider builder pattern"
    }

    fn category(&self) -> Category {
        Category::Pattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Suggests builder pattern for public constructors with many parameters."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/creational/builder.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Consider using a builder pattern with a `Config` struct and `build()` method for functions with many parameters.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const PARAM_THRESHOLD: usize = 5;

        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                let file: File = match syn::parse_file(&content) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                for item in &file.items {
                    if let syn::Item::Fn(fn_item) = item {
                        let vis_str = fn_item.vis.to_token_stream().to_string();
                        if !vis_str.contains("pub") {
                            continue;
                        }

                        let input_count = fn_item.sig.inputs.len();
                        if input_count >= PARAM_THRESHOLD {
                            let line = content
                                .lines()
                                .position(|l| {
                                    l.contains("fn") && l.contains(&fn_item.sig.ident.to_string())
                                })
                                .map(|n| (n + 1) as u32)
                                .unwrap_or(0);

                            let opt_count = fn_item
                                .sig
                                .inputs
                                .iter()
                                .filter(|arg| {
                                    if let syn::FnArg::Typed(pat_type) = arg {
                                        let ty_str = pat_type.ty.to_token_stream().to_string();
                                        ty_str.starts_with("Option<")
                                    } else {
                                        false
                                    }
                                })
                                .count();

                            let mut message = format!(
                                "Public function `{}` has {} parameters (threshold: {})",
                                fn_item.sig.ident, input_count, PARAM_THRESHOLD
                            );
                            if opt_count > 0 {
                                message.push_str(&format!(
                                    "; {} parameters are `Option<T>`",
                                    opt_count
                                ));
                            }

                            out.push(Finding {
                                rule_id: self.id().to_string(),
                                title: self.title().to_string(),
                                category: self.category(),
                                severity: self.default_severity(),
                                confidence: self.default_confidence(),
                                location: Some(Location {
                                    path: src_path.to_path_buf().into(),
                                    line: Some(line),
                                    column: None,
                                    end_line: Some(line),
                                    end_column: None,
                                }),
                                message,
                                why_it_matters: "Functions with many parameters are hard to call correctly and difficult to extend without breaking existing callers. The builder pattern provides a clean, extensible API."
                                    .to_string(),
                                suggestion: Some(
                                    "Consider creating a `Config` struct and using the builder pattern (e.g., `MyBuilder::default().field1(...).build()`) instead."
                                        .to_string(),
                                ),
                                references: self.references().into_iter().map(String::from).collect(),
                                llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PatternContainUnSafety
// ---------------------------------------------------------------------------

/// Flag unsafe code spread across many files.
#[derive(Default)]
pub struct PatternContainUnSafety;

impl Rule for PatternContainUnSafety {
    fn id(&self) -> &'static str {
        "pattern.contain-unsafety"
    }

    fn title(&self) -> &'static str {
        "Consider containing unsafe code"
    }

    fn category(&self) -> Category {
        Category::Organization
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Flag `unsafe` spread across many files; suggest small audited unsafe boundaries."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/structural/contain-unsafety.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Isolate unsafe code into small modules with safe outer APIs. Keep the unsafe surface area minimal.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        let mut unsafe_files: Vec<PathBuf> = Vec::new();

        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                if content.contains("unsafe") {
                    unsafe_files.push(src_path.to_path_buf().into());
                }
            }
        }

        if unsafe_files.len() > 5 {
            out.push(Finding {
                rule_id: self.id().to_string(),
                title: self.title().to_string(),
                category: self.category(),
                severity: self.default_severity(),
                confidence: self.default_confidence(),
                location: None,
                message: format!("Unsafe code found in {} files; consider containing it in a single module", unsafe_files.len()),
                why_it_matters: "Unsafe code spread across many files makes auditing harder and increases the risk of unsafe bugs.".to_string(),
                suggestion: Some("Group unsafe code into a small module with a safe public API boundary.".to_string()),
                references: self.references().into_iter().map(String::from).collect(),
                llm_fix_prompt: self.llm_fix_prompt().map(String::from),
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PatternCustomTraitsForBounds
// ---------------------------------------------------------------------------

/// Flag repeated long where clauses or complex Fn bounds.
#[derive(Default)]
pub struct PatternCustomTraitsForBounds;

impl Rule for PatternCustomTraitsForBounds {
    fn id(&self) -> &'static str {
        "pattern.custom-traits-for-bounds"
    }

    fn title(&self) -> &'static str {
        "Consider custom trait for complex bounds"
    }

    fn category(&self) -> Category {
        Category::Pattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Flag repeated long where clauses or complex Fn bounds."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/structural/custom-traits-for-complex-bounds.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Extract complex trait bounds into a named custom trait with a blanket implementation for readability.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const WHERE_CLAUSE_CHAR_THRESHOLD: usize = 80;

        for pkg in ctx.metadata.packages.iter() {
            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                let content = std::fs::read_to_string(src_path)?;
                let file: File = match syn::parse_file(&content) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                for item in &file.items {
                    match item {
                        syn::Item::Fn(fn_item) => {
                            analyze_fn_where_clause(
                                fn_item,
                                &content,
                                src_path.as_std_path(),
                                self,
                                out,
                                WHERE_CLAUSE_CHAR_THRESHOLD,
                            );
                        }
                        syn::Item::Impl(imp) => {
                            analyze_impl_where_clause(
                                imp,
                                &content,
                                src_path.as_std_path(),
                                self,
                                out,
                                WHERE_CLAUSE_CHAR_THRESHOLD,
                            );
                        }
                        syn::Item::Trait(tr) => {
                            analyze_trait_where_clause(
                                tr,
                                &content,
                                src_path.as_std_path(),
                                self,
                                out,
                                WHERE_CLAUSE_CHAR_THRESHOLD,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

/// Analyze a function for overly long where clauses or complex Fn bounds.
fn analyze_fn_where_clause(
    fn_item: &syn::ItemFn,
    content: &str,
    src_path: &std::path::Path,
    rule: &PatternCustomTraitsForBounds,
    out: &mut Vec<Finding>,
    threshold: usize,
) {
    let item_token_str = quote::quote!(#fn_item).to_string();
    if item_token_str.len() > threshold && item_token_str.contains("where") {
        analyze_where_text(
            item_token_str.as_str(),
            content,
            src_path,
            rule,
            "function",
            threshold,
            out,
        );
    }
}

/// Analyze an impl block for overly long where clauses or complex Fn bounds.
fn analyze_impl_where_clause(
    imp: &syn::ItemImpl,
    content: &str,
    src_path: &std::path::Path,
    rule: &PatternCustomTraitsForBounds,
    out: &mut Vec<Finding>,
    threshold: usize,
) {
    let item_token_str = quote::quote!(#imp).to_string();
    if item_token_str.len() > threshold && item_token_str.contains("where") {
        analyze_where_text(
            item_token_str.as_str(),
            content,
            src_path,
            rule,
            "impl block",
            threshold,
            out,
        );
    }
}

/// Analyze a trait for overly long where clauses or complex Fn bounds.
fn analyze_trait_where_clause(
    tr: &syn::ItemTrait,
    content: &str,
    src_path: &std::path::Path,
    rule: &PatternCustomTraitsForBounds,
    out: &mut Vec<Finding>,
    threshold: usize,
) {
    let item_token_str = quote::quote!(#tr).to_string();
    if item_token_str.len() > threshold && item_token_str.contains("where") {
        analyze_where_text(
            item_token_str.as_str(),
            content,
            src_path,
            rule,
            "trait",
            threshold,
            out,
        );
    }
}

/// Analyze where clause text for complex bounds.
fn analyze_where_text(
    item_str: &str,
    content: &str,
    src_path: &std::path::Path,
    rule: &PatternCustomTraitsForBounds,
    item_kind: &str,
    _threshold: usize,
    out: &mut Vec<Finding>,
) {
    if let Some(where_pos) = item_str.find("where") {
        let where_end = item_str.len().min(where_pos + 5 + 200);
        let where_text = &item_str[where_pos..where_end];

        let fn_bound_count = where_text.matches("Fn").count();

        if fn_bound_count >= 2 || where_text.len() > 60 {
            let line = content
                .lines()
                .position(|l| l.contains("where"))
                .map(|n| (n + 1) as u32)
                .unwrap_or(0);

            out.push(Finding {
                rule_id: rule.id().to_string(),
                title: rule.title().to_string(),
                category: rule.category(),
                severity: rule.default_severity(),
                confidence: rule.default_confidence(),
                location: Some(Location {
                    path: src_path.to_path_buf(),
                    line: Some(line),
                    column: None,
                    end_line: Some(line),
                    end_column: None,
                }),
                message: format!(
                    "{} has a complex where clause ({} Fn bounds) that could be extracted into a custom trait",
                    item_kind, fn_bound_count.max(1)
                ),
                why_it_matters: "Long, complex trait bounds reduce readability and make it harder to understand API requirements at a glance. A custom trait with a blanket implementation can express the same constraint in a single name."
                    .to_string(),
                suggestion: Some("Extract the trait bounds into a named custom trait (e.g., `trait MyBounds: TraitA + TraitB + Fn(...)`) and use it as a single bound.".to_string()),
                references: rule.references().into_iter().map(String::from).collect(),
                llm_fix_prompt: rule.llm_fix_prompt().map(String::from),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// PatternSmallCrates
// ---------------------------------------------------------------------------

/// Flag very large crates/modules.
#[derive(Default)]
pub struct PatternSmallCrates;

impl Rule for PatternSmallCrates {
    fn id(&self) -> &'static str {
        "pattern.small-crates"
    }

    fn title(&self) -> &'static str {
        "Consider splitting large crates"
    }

    fn category(&self) -> Category {
        Category::Organization
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Flag very large crates/modules as organization guidance."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/structural/prefer-small-crates.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Consider splitting large crates into smaller, more focused crates for better modularity and parallel compilation.")
    }

    fn check(&self, ctx: &RuleContext, out: &mut Vec<Finding>) -> anyhow::Result<()> {
        const LARGE_CRATE_LINES: usize = 1000;
        const LARGE_CRATE_FILES: usize = 15;

        for pkg in ctx.metadata.packages.iter() {
            let mut total_lines: usize = 0;
            let mut file_count: usize = 0;
            let mut large_files: Vec<(String, usize)> = Vec::new();

            for target in &pkg.targets {
                let src_path = target.src_path.as_path();
                if !src_path.exists() {
                    continue;
                }
                if src_path.is_file() {
                    if let Ok(content) = std::fs::read_to_string(src_path) {
                        let line_count = content.lines().count();
                        total_lines += line_count;
                        file_count += 1;
                        if line_count > 300 {
                            large_files.push((src_path.to_string(), line_count));
                        }
                    }
                }
            }

            // Also check for subdirectories that might be large modules
            for pkg2 in ctx.metadata.packages.iter() {
                for target in &pkg2.targets {
                    let src_path = target.src_path.as_path();
                    if src_path.is_dir() {
                        // Count files in the directory
                        let mut dir_files: Vec<std::path::PathBuf> = Vec::new();
                        collect_files(src_path.as_std_path(), &mut dir_files);
                        file_count += dir_files.len();
                        for f in &dir_files {
                            if let Ok(content) = std::fs::read_to_string(f) {
                                total_lines += content.lines().count();
                                let line_count = content.lines().count();
                                if line_count > 300 {
                                    large_files.push((f.display().to_string(), line_count));
                                }
                            }
                        }
                    }
                }
            }

            if total_lines > LARGE_CRATE_LINES || file_count > LARGE_CRATE_FILES {
                let mut suggestion = format!(
                    "Consider splitting this crate into smaller modules. \
                     Current size: {} lines across {} files. \
                     Large files:",
                    total_lines, file_count
                );
                for (path, lines) in large_files.iter().take(5) {
                    suggestion.push_str(&format!("\n  - {}: {} lines", path, lines));
                }

                out.push(Finding {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    category: self.category(),
                    severity: self.default_severity(),
                    confidence: self.default_confidence(),
                    location: None,
                    message: format!(
                        "Package \"{}\" is large ({} lines, {} files); consider splitting into smaller crates",
                        pkg.name, total_lines, file_count
                    ),
                    why_it_matters: "Large crates slow down compilation, reduce modularity, and make it harder for developers to navigate the codebase. Smaller, focused crates improve parallel compilation and reuse."
                        .to_string(),
                    suggestion: Some(suggestion),
                    references: self.references().into_iter().map(String::from).collect(),
                    llm_fix_prompt: self.llm_fix_prompt().map(String::from),
                });
            }
        }
        Ok(())
    }
}

fn collect_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
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
            if path.file_name() == Some("target".as_ref())
                || path.file_name() == Some(".git".as_ref())
            {
                continue;
            }
            collect_files(&path, files);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            files.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Phase-2 Stubs (inert - no findings)
// ---------------------------------------------------------------------------

/// Phase-2: Clone to satisfy borrow checker.
#[derive(Default)]
pub struct AntiCloneToSatisfyBorrowChecker;

impl Rule for AntiCloneToSatisfyBorrowChecker {
    fn id(&self) -> &'static str {
        "anti.clone-to-satisfy-borrow-checker"
    }

    fn title(&self) -> &'static str {
        "Clone to satisfy borrow checker"
    }

    fn category(&self) -> Category {
        Category::AntiPattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Phase-2 stub: flags suspicious `.clone()` near borrow-checker workarounds."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/anti-patterns/clone-to-satisfy-borrow-checker.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Consider using `mem::take`, `mem::replace`, or `Option::take` to avoid unnecessary clones.")
    }

    fn check(&self, _ctx: &RuleContext, _out: &mut Vec<Finding>) -> anyhow::Result<()> {
        // Phase-2 stub: needs type/flow context
        Ok(())
    }
}

/// Phase-2 stub: FFI idiomatic errors.
#[derive(Default)]
pub struct FfiIdiomaticErrors;

impl Rule for FfiIdiomaticErrors {
    fn id(&self) -> &'static str {
        "ffi.idiomatic-errors"
    }

    fn title(&self) -> &'static str {
        "FFI idiomatic errors"
    }

    fn category(&self) -> Category {
        Category::Toolchain
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Phase-2 stub: FFI idiomatic error handling."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/idioms/ffi-idiomatic-errors.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Map Rust errors to C-compatible codes for FFI boundaries.")
    }

    fn check(&self, _ctx: &RuleContext, _out: &mut Vec<Finding>) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Phase-2 stub: Newtype pattern.
#[derive(Default)]
pub struct PatternNewtype;

impl Rule for PatternNewtype {
    fn id(&self) -> &'static str {
        "pattern.newtype"
    }

    fn title(&self) -> &'static str {
        "Consider newtype for type safety"
    }

    fn category(&self) -> Category {
        Category::Pattern
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn default_confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Phase-2 stub: detect repeated primitive parameters where a newtype may clarify meaning."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://rust-unofficial.github.io/patterns/patterns/creational/newtype.html"]
    }

    fn llm_fix_prompt(&self) -> Option<&'static str> {
        Some("Consider using a tuple struct newtype instead of raw primitive parameters for type safety.")
    }

    fn check(&self, _ctx: &RuleContext, _out: &mut Vec<Finding>) -> anyhow::Result<()> {
        Ok(())
    }
}
